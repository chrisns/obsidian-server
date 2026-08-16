// /opt/mcp/server.js
import { readFileSync, writeFileSync, renameSync, statSync, unlinkSync,
         openSync, fsyncSync, closeSync, readdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import path from "node:path";
import * as z from "zod/v4";
import YAML from "yaml";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { auth, initAuth, audit, authStats, counters, ctx } from "./auth.js";

const VAULT    = process.env.VAULT    ?? "/data/vault";
const STAGING  = process.env.STAGING  ?? "/data/staging";
const OB_STATE = process.env.OB_STATE ?? "/data/state/obsidian-headless";

const MAX_BYTES = 1024 * 1024;
const BAD_NAME = /[*"\\/<>:|?]/;
const CONFLICT = /conflicted copy|\.sync-conflict|[ (]\d+\)?\.md$/i;

const inVault = (rel) => {
  const abs = path.resolve(VAULT, rel);
  if (abs !== VAULT && !abs.startsWith(VAULT + path.sep)) throw new Error(`path escapes vault: ${rel}`);
  return abs;
};

const walk = (dir, out = []) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name.startsWith(".")) continue;               // skip .obsidian and friends
    const p = path.join(dir, e.name);
    e.isDirectory() ? walk(p, out) : e.name.endsWith(".md") && out.push(p);
  }
  return out;
};

function validate(rel, content) {
  const errors = [], warnings = [];
  const base = path.basename(rel);
  if (BAD_NAME.test(base) || base.startsWith(".") || base.startsWith(" "))
    errors.push(`illegal filename for Obsidian: ${base}`);
  if (CONFLICT.test(base)) errors.push(`conflicted-copy filename pattern: ${base}`);
  if (Buffer.byteLength(content) > MAX_BYTES) errors.push(`over ${MAX_BYTES} bytes`);
  if (content.startsWith("---\n")) {
    const end = content.indexOf("\n---", 3);
    if (end < 0) errors.push("frontmatter fence opened but never closed");
    else { try { YAML.parse(content.slice(4, end)); } catch (e) { errors.push(`frontmatter: ${e.message}`); } }
  }
  const names = new Set(walk(VAULT).map(p => path.basename(p, ".md")));
  for (const m of content.matchAll(/\[\[([^\]|#]+)/g)) {
    const t = m[1].trim();
    if (!names.has(path.basename(t))) warnings.push(`wikilink target not found: [[${t}]]`);
  }
  return { errors, warnings };
}

// tmp-then-rename. Same filesystem, so this is a real atomic rename(2) and
// `ob sync --continuous` sees exactly one complete file, never a partial one.
export function commit(rel, content, expectMtime) {
  const abs = inVault(rel);
  if (!content.endsWith("\n")) content += "\n";          // the one silent fix
  const report = validate(rel, content);
  if (report.errors.length) return { ok: false, ...report };
  const tmp = path.join(STAGING, `${randomUUID()}.tmp`);
  writeFileSync(tmp, content, { mode: 0o644 });
  const fd = openSync(tmp, "r"); fsyncSync(fd); closeSync(fd);
  if (expectMtime !== undefined) {
    const now = existsSync(abs) ? statSync(abs).mtimeMs : 0;
    if (now !== expectMtime) { unlinkSync(tmp); return { ok: false, errors: ["conflict: file changed under us"], warnings: [] }; }
  }
  renameSync(tmp, abs);
  return { ok: true, path: rel, bytes: Buffer.byteLength(content), ...report };
}
// MCP_TOKEN is gone. There is no single token any more.

// ... inVault(), walk() unchanged ...

// A full tree walk is ~1,649 files over 194 directories and blocks the event
// loop; Node is single-threaded and this container is capped at 500m CPU.
// Two callers must not pay it per request: /readyz, which is UNAUTHENTICATED
// and polled by the kubelet every 10s, and validate(), which runs on every
// write. Callers that need fresh mtimes (vault_list, vault_status) still walk
// directly, and they are authenticated and infrequent.
let cached = { at: 0, v: null };
const walkCached = (ms = 5000) => {
  if (Date.now() - cached.at > ms) cached = { at: Date.now(), v: walk(VAULT) };
  return cached.v;
};

// in validate(), the only change:
//   const names = new Set(walkCached(30_000).map(p => path.basename(p, ".md")));
// in commit(), after a successful renameSync:
//   cached.at = 0;                                      // new note, drop the memo

// --- scope ------------------------------------------------------------------
// Two servers, not one server with a runtime check. `rw` is a superset of `ro`.
// Scope is enforced by WHICH SERVER the request is dispatched to, so a
// read-only consumer's tools/list does not even mention vault_write: it cannot
// call a tool it was never told about, and it does not burn context on one.
// There is no check to forget, because there is no check.
const ro = new McpServer({ name: "vault", version: "1.0.0" });
const rw = new McpServer({ name: "vault", version: "1.0.0" });

// The scope argument is mandatory, so a new tool cannot silently land in the
// read-only set. That is the failure this whole exercise is about.
const tool = (scope, name, spec, fn) => {
  const wrapped = async (args, extra) => {
    const st = ctx.getStore();
    try {
      const r = await fn(args, extra);
      if (st) st.ok = !r.isError;
      if (scope === "rw" && st?.client && !r.isError)
        counters.writes[st.client] = (counters.writes[st.client] ?? 0) + 1;
      return r;
    } catch (e) {
      if (st) { st.ok = false; st.err = e.message; }
      throw e;
    }
  };
  if (scope === "ro") ro.registerTool(name, spec, wrapped);
  rw.registerTool(name, spec, wrapped);                   // rw is a superset
};

tool("ro", "vault_search",
  { description: "Full-text search the vault. 18 MB of markdown, greps in ~40 ms, so there is no index.",
    inputSchema: { query: z.string(), regex: z.boolean().default(false),
                   glob: z.string().default("*.md"), max_results: z.number().default(50) } },
  async ({ query, regex, glob, max_results }) => {
    const args = ["--json", "-n", "--max-count", "3", "-g", glob, "-m", String(max_results)];
    if (!regex) args.push("-F");
    let out = "";
    // `-e` and `--` are load-bearing, NOT style. ripgrep parses flags at any
    // argv position, so a bare `query` lets a caller pass `--pre=/bin/sh`,
    // which is consumed as a flag. Whether that reaches execution depends on
    // how the child's stdin happens to be wired (pipe: inert, /dev/null:
    // executes, inherited: hangs forever and blocks the event loop), so today
    // it is safe by accident. `-e` pins the argument as the pattern and `--`
    // ends flag parsing before the path. -F does NOT help; it makes the
    // pattern literal, not the argv safe.
    //
    // cwd is pinned rather than inherited: the image sets WORKDIR /data/vault,
    // and a flag-shaped query that steals the pattern position leaves ripgrep
    // with no path argument, at which point it searches the working directory.
    // Pinning it means the argv fix does not quietly depend on ambient cwd.
    try { out = execFileSync("rg", [...args, "-e", query, "--", VAULT],
                             { encoding: "utf8", maxBuffer: 8e6, cwd: VAULT }); }
    catch (e) { if (e.status !== 1) throw e; }           // 1 = no matches
    const hits = out.split("\n").filter(Boolean).map(JSON.parse)
      .filter(o => o.type === "match")
      .map(o => ({ path: path.relative(VAULT, o.data.path.text),
                   line: o.data.line_number, text: o.data.lines.text.trimEnd() }));
    return { content: [{ type: "text", text: JSON.stringify(hits, null, 2) }] };
  });

tool("ro", "vault_read",
  { description: "Read one note.", inputSchema: { path: z.string() } },
  async ({ path: rel }) => ({ content: [{ type: "text", text: readFileSync(inVault(rel), "utf8") }] }));
tool("ro", "vault_list",
  { description: "List markdown files, newest first.", inputSchema: { limit: z.number().default(200) } },
  async ({ limit }) => {
    const rows = walk(VAULT).map(p => ({ path: path.relative(VAULT, p), mtime: statSync(p).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime).slice(0, limit);
    return { content: [{ type: "text", text: JSON.stringify(rows, null, 2) }] };
  });
tool("ro", "vault_status",
  { description: "Freshness, as data rather than as a failure. Read this before trusting the vault is current.", inputSchema: {} },
  async () => ({ content: [{ type: "text", text: JSON.stringify(status(), null, 2) }] }));
tool("rw", "vault_write",
  { description: "Write a note through the validation gate. Staged outside the synced tree, validated, then atomically renamed in. dry_run returns the report without writing.",
    inputSchema: { path: z.string(), content: z.string(),
                   mode: z.enum(["create", "overwrite", "append"]).default("create"),
                   dry_run: z.boolean().default(false) } },
  async ({ path: rel, content, mode, dry_run }) => {
    const abs = inVault(rel);
    const exists = existsSync(abs);
    if (mode === "create" && exists) throw new Error(`exists: ${rel}`);
    let body = content, mtime;
    if (mode === "append" && exists) {
      mtime = statSync(abs).mtimeMs;
      body = readFileSync(abs, "utf8").replace(/\n*$/, "\n") + content;
    }
    const r = dry_run ? { ok: null, ...validate(rel, body) } : commit(rel, body, mtime);
    return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }], isError: r.ok === false };
  });

// --- transport --------------------------------------------------------------
// host: "0.0.0.0" matches the real bind and disables the SDK's localhost-only
// Host-header validation, which otherwise 403s every request whose Host is not
// localhost: kubelet probes (pod IP), n8n (the Service DNS name), and any
// future consumer. DNS-rebinding protection defends UNAUTHENTICATED localhost
// servers from browsers; every route here that matters is bearer-gated, which
// is the SDK's own documented alternative. Do not "fix" the resulting startup
// warning by adding allowedHosts: pod IPs are unenumerable, so an allowlist
// reintroduces the probe 403 the moment the workaround header is dropped.
const app = createMcpExpressApp({ host: "0.0.0.0" });

// Registered BEFORE the auth middleware, so the kubelet needs no token and the
// middleware needs no exemption logic. Both are cheap by construction: /readyz
// is unauthenticated, so an uncached tree walk here is a free denial of service
// for any pod in the cluster.
app.get("/healthz", (_q, s) => s.json({ status: "ok" }));
app.get("/readyz", (_q, s) => {
  try {
    statSync(path.join(VAULT, ".obsidian"));
    if (!walkCached().length) throw new Error("empty");
    s.json({ status: "ok" });
  } catch (e) { s.status(503).json({ status: "unready", error: e.message }); }
});

initAuth();
app.use(auth);                       // everything below here is authenticated

// One audit line per authenticated request, emitted from the ROUTE on response
// close so it fires whatever happens: a successful call, a tool the caller's
// scope does not expose (which never reaches the wrapper above), a malformed
// body, or a crash. Absence of `ok` is the signature of a scope refusal.
app.post("/mcp", async (q, s) => {
  const t0 = Date.now();
  const body = [].concat(q.body ?? []);
  const calls = body.filter(b => b?.method === "tools/call");
  const st = ctx.getStore();
  st.method = body.map(b => b?.method).filter(Boolean).join(",") || null;
  st.tool   = calls.map(b => b.params?.name).join(",") || null;
  st.path   = calls.map(b => b.params?.arguments?.path).filter(Boolean).join(",") || null;
  s.once("close", () => audit({ ms: Date.now() - t0, status: s.statusCode }));

  const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });  // stateless
  await (q.scope === "rw" ? rw : ro).connect(t);
  await t.handleRequest(q, s, q.body);
  s.on("close", () => t.close());
});

// Bound to 0.0.0.0 only. There is deliberately NO second unauthenticated
// listener on 127.0.0.1: the agent container reads /data/vault through the
// filesystem and never calls this server, so it would have no consumer, and an
// unauthenticated loopback port is reachable by every container in this pod,
// including the one that processes untrusted capture notes.
export const listen = (port = 8080) => app.listen(port, "0.0.0.0",
  () => console.log(JSON.stringify({ evt: "listening", port })));
if (process.env.RUN !== "0") listen(Number(process.env.PORT ?? 8080));

function status() {
  const files = walk(VAULT);
  const newest = files.reduce((m, p) => Math.max(m, statSync(p).mtimeMs), 0);
  let synced_seconds_ago = null;
  try {
    const dir = readdirSync(path.join(OB_STATE, "sync"))[0];
    const log = readFileSync(path.join(OB_STATE, "sync", dir, "sync.log"), "utf8").slice(-200000);
    const line = log.split("\n").filter(l => l.includes("Fully synced")).pop();
    if (line) synced_seconds_ago = Math.round((Date.now() - Date.parse(line.slice(1, 25))) / 1000);
  } catch { /* no log yet */ }
  return { markdown_files: files.length,
           newest_note_age_seconds: Math.round((Date.now() - newest) / 1000),
           synced_seconds_ago,
           healthy: synced_seconds_ago !== null && synced_seconds_ago < 900,
           // Added by the auth design: the n8n dead-man's switch polls this one
           // tool, so denial counts must ride along with freshness or nothing
           // ever notices a consumer failing to authenticate.
           auth: authStats() };
}
