// mcp/test.js  ->  node test.js
// One runnable check for the security-critical logic: the write gate, the
// ripgrep argv, and auth.
import assert from "node:assert";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync,
         mkdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const mk = (p) => mkdtempSync(path.join(tmpdir(), p));
const vault = mk("v-"), staging = mk("s-"), dir = mk("tok-"), seen = mk("seen-");
const audit = path.join(mk("aud-"), "mcp-audit.log");
mkdirSync(path.join(vault, ".obsidian"));
writeFileSync(path.join(vault, "seed.md"),
  "hello world\n-- dashed\nliteral --pre=/bin/sh here\nTODO: --pre is scary\n");

Object.assign(process.env, {
  VAULT: vault, STAGING: staging, MCP_TOKEN_DIR: dir, MCP_SEEN_DIR: seen,
  MCP_AUDIT: audit, MCP_RELOAD_MS: "50",   // 30s in production
  RUN: "0",                                // do not bind 8080 on import
});

const WATCH = "a".repeat(64), IDX_OLD = "b".repeat(64), IDX_NEW = "c".repeat(64);
writeFileSync(path.join(dir, "N8N_WATCH_RO"), WATCH + "\n");
writeFileSync(path.join(dir, "INDEXER_RW"), `${IDX_OLD},${IDX_NEW}\n`);  // mid-rotation
writeFileSync(path.join(dir, "..data"), "ignored");                      // kubelet artefact
writeFileSync(path.join(dir, "BADKEY"), "d".repeat(64));                 // no scope suffix

const { listen, commit } = await import("./server.js");

// --- the write gate ---------------------------------------------------------
assert.equal(commit("a:b.md", "x").ok, false, "illegal filename must reject");
assert.equal(commit("ok.md", "---\n: :\n---\nx").ok, false, "bad yaml must reject");
assert.equal(commit("ok.md", "---\ntags: [index]\n---\nx").ok, true);
assert.ok(readFileSync(path.join(vault, "ok.md"), "utf8").endsWith("\n"), "newline auto-fixed");
assert.equal(commit("Note conflicted copy.md", "x").ok, false);
assert.throws(() => commit("../escape.md", "x"), /escapes vault/, "path escape must throw, not write");
console.log("gate ok");

// --- the server -------------------------------------------------------------
const srv = listen(0);
await new Promise(r => srv.once("listening", r));
const base = `http://127.0.0.1:${srv.address().port}`;
const url = base + "/mcp";

const rpc = (token, body) => fetch(url, {
  method: "POST",
  headers: { "content-type": "application/json",
             accept: "application/json, text/event-stream",
             ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, ...body }),
});
const json = async (r) => {
  const t = await r.text();
  const line = t.split("\n").find(l => l.startsWith("data: "));   // SSE framing
  return JSON.parse(line ? line.slice(6) : t);
};
const list = async (token) => {
  const j = await json(await rpc(token, { method: "tools/list", params: {} }));
  return j.result.tools.map(t => t.name).sort();
};
const callTool = async (token, name, args = {}) =>
  json(await rpc(token, { method: "tools/call", params: { name, arguments: args } }));

const RO_TOOLS = ["vault_list", "vault_read", "vault_search", "vault_status"];
const RW_TOOLS = [...RO_TOOLS, "vault_write"].sort();

// 1. no token, wrong token, and tokens of completely different lengths are all
//    401, and none of them throws (the timingSafeEqual length trap).
for (const t of [undefined, "z".repeat(64), "short", "a".repeat(200), ""]) {
  assert.equal((await rpc(t, { method: "tools/list", params: {} })).status, 401, `must reject: ${t}`);
}
assert.equal((await fetch(base + "/healthz")).status, 200, "healthz stays open for the kubelet");
assert.equal((await fetch(base + "/readyz")).status, 200, "readyz stays open for the kubelet");

// 2. scope is enforced by tool visibility, not by a runtime check.
assert.deepEqual(await list(WATCH), RO_TOOLS, "ro must not even see vault_write");
assert.deepEqual(await list(IDX_OLD), RW_TOOLS);
assert.deepEqual(await list(IDX_NEW), RW_TOOLS, "both tokens of a mid-rotation pair work");

// 3. a read-only consumer calling the write tool is refused by dispatch.
const denied = await callTool(WATCH, "vault_write", { path: "x.md", content: "y" });
assert.ok(denied.result.isError && /not found/.test(denied.result.content[0].text),
  "ro token calling vault_write must be refused by dispatch");
assert.ok(!existsSync(path.join(vault, "x.md")), "and must not have written anything");
const okw = await callTool(IDX_OLD, "vault_write", { path: "x.md", content: "y" });
assert.ok(!okw.result.isError, "rw token calling vault_write must succeed");

// 4. ripgrep parses flags at ANY argv position, so a flag-shaped query must be
//    treated as a pattern. Asserted by matching, not by a side-effect canary:
//    whether an injected --pre actually executes depends on how the child's
//    stdin happens to be wired (pipe = inert, /dev/null = executes, inherited =
//    hangs), so a canary tests the accident rather than the property. This
//    tests the property: with `-e ... --` the query matches literal text; a
//    vulnerable server consumes it as a flag and returns nothing.
const hits = async (q, extra = {}) =>
  JSON.parse((await callTool(WATCH, "vault_search", { query: q, ...extra })).result.content[0].text).length;
assert.equal(await hits("--pre=/bin/sh"), 1, "flag-shaped query must be a PATTERN, not a flag");
assert.equal(await hits("-- dashed"), 1, "leading-dash query must still match");
assert.equal(await hits("hello"), 1, "ordinary query still works");
assert.equal(await hits("zzz-not-present"), 0, "a genuine miss is still a miss");
assert.equal(await hits("TODO.*scary", { regex: true }), 1, "regex mode still works");

// 5. every call is attributed to a consumer by name, and the two rotation
//    tokens are distinguishable by kid, so you can prove the old one is dead.
const lines = readFileSync(audit, "utf8").trim().split("\n").map(JSON.parse);
const w = lines.filter(l => l.tool === "vault_write");
assert.equal(w.length, 2, "both the refused and the permitted write are logged");
const [refused, allowed] = w;
assert.equal(refused.client, "n8n-watch");
assert.equal(refused.scope, "ro");
assert.equal(refused.ok, undefined, "refused at dispatch, so no tool outcome");
assert.equal(allowed.client, "indexer");
assert.equal(allowed.path, "x.md");
assert.equal(allowed.ok, true);
assert.equal(allowed.kid.length, 8, "kid distinguishes the two rotation tokens");
// 401s are logged to stdout but NOT to the PV file: that path is
// unauthenticated, so appending there would be a disk-fill primitive.
assert.ok(!lines.some(l => l.evt === "denied"), "401s must not reach the PV audit file");

// 6. the dead-man's switch reads per-consumer last-seen, so n8n needs no write
//    path of its own.
assert.deepEqual(readdirSync(seen).sort(), ["indexer", "n8n-watch"]);
const st = JSON.parse((await callTool(WATCH, "vault_status")).result.content[0].text);
assert.equal(st.auth.denied_15m, 5, "the five rejected calls are visible to the n8n poll");
assert.equal(st.auth.writes.indexer, 1);
assert.equal(typeof st.auth.last_seen_seconds_ago["n8n-watch"], "number");

// 7. onboarding and revocation take effect with NO restart. This is the whole
//    argument for the mounted Secret over envFrom.
const HA = "e".repeat(64);
writeFileSync(path.join(dir, "HOMEASSISTANT_RO"), HA);
await new Promise(r => setTimeout(r, 80));
assert.deepEqual(await list(HA), RO_TOOLS, "new consumer works without a rollout");
assert.deepEqual(await list(WATCH), RO_TOOLS, "existing consumer undisturbed");

rmSync(path.join(dir, "HOMEASSISTANT_RO"));
await new Promise(r => setTimeout(r, 80));
assert.equal((await rpc(HA, { method: "tools/list", params: {} })).status, 401,
  "revocation takes effect without a rollout");
assert.deepEqual(await list(IDX_OLD), RW_TOOLS, "others still work");

// 8. concurrency: 20 interleaved calls on two tokens must each be attributed
//    correctly. This is the check that catches sharing the ALS store object.
const before = readFileSync(audit, "utf8").split("\n").length;
await Promise.all(Array.from({ length: 20 }, (_, i) =>
  rpc(i % 2 ? WATCH : IDX_OLD, { method: "tools/call",
    params: { name: i % 2 ? "vault_read" : "vault_write",
              arguments: { path: i % 2 ? "seed.md" : `n${i}.md`, content: "c" } } })));
const fresh = readFileSync(audit, "utf8").trim().split("\n").slice(before - 1).map(JSON.parse);
assert.equal(fresh.length, 20);
for (const l of fresh) {
  assert.equal(l.client === "indexer" ? "vault_write" : "vault_read", l.tool, "client and tool must not cross");
  assert.equal(l.client === "indexer" ? "rw" : "ro", l.scope);
}


// Regression: the SDK's default localhost Host validation 403'd kubelet probes
// (Host: <pod-ip>) and would have 403'd n8n (Host: service DNS). /healthz must
// answer 200 whatever the Host header says.
{
  const res = await fetch(`${base}/healthz`, { headers: { Host: "10.99.99.99:8080" } });
  assert.equal(res.status, 200, "healthz must ignore the Host header");
  const res2 = await fetch(`${base}/mcp`, { method: "POST", headers: { Host: "obsidian.obsidian.svc.cluster.local" } });
  assert.equal(res2.status, 401, "mcp with foreign Host must reach auth (401), not host validation (403)");
}
console.log("host ok");
srv.close();
console.log("auth ok");

