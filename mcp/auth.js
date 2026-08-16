// /opt/mcp/auth.js
//
// Auth is the ONLY control on this endpoint. There is no NetworkPolicy, so any
// pod in the cluster (including an ARC runner executing arbitrary workflow
// code) can open a TCP connection to :8080. Everything below assumes that.
//
// Registry: one file per consumer in a mounted Secret, named CLIENT_SCOPE.
//   /etc/mcp-tokens/N8N_WATCH_RO   -> "a1b2..."          one token
//   /etc/mcp-tokens/INDEXER_RW     -> "c3d4...,e5f6..."  two, mid-rotation
// The Secret is generated with disableNameSuffixHash, so `apply -k` updates it
// in place: the kubelet refreshes the mounted volume within ~60s and load()
// picks it up within RELOAD_MS of that. Adding or revoking a consumer therefore
// needs NO rollout, which matters because this Deployment is Recreate/replicas:1
// and any rollout takes the whole vault pod down.
import { createHash } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import { readdirSync, readFileSync, statSync, writeFileSync, mkdirSync,
         appendFileSync } from "node:fs";
import path from "node:path";

const DIR       = process.env.MCP_TOKEN_DIR ?? "/etc/mcp-tokens";
const SEEN      = process.env.MCP_SEEN_DIR  ?? "/data/state/last-seen";
const AUDIT     = process.env.MCP_AUDIT     ?? "/data/state/mcp-audit.log";
const RELOAD_MS = Number(process.env.MCP_RELOAD_MS ?? 30_000);
const KEY       = /^([A-Z0-9]+(?:_[A-Z0-9]+)*)_(RO|RW)$/;

// Hash first. Both operands are then always 32 bytes, so timingSafeEqual can
// never throw its RangeError on unequal length and no length check is needed.
// A length guard would be wrong twice over: it leaks the token length, and it
// makes the constant-time compare pointless by branching on the input first.
const sha = (s) => createHash("sha256").update(s).digest();

// Carries {client, scope, kid} into the tool handlers without threading a
// parameter through the SDK. Stdlib, and exactly what it is for.
export const ctx = new AsyncLocalStorage();

// Rolling 15-minute window of denials, read by vault_status and alerted on by
// n8n. Self-clearing rather than a cumulative counter, deliberately: a latched
// alarm gets muted, and a muted channel is not a channel.
const denials = [];
export const counters = { calls: {}, writes: {} };

let registry = new Map();
let loadedAt = 0;

function load() {
  const next = new Map();
  for (const f of readdirSync(DIR)) {
    if (f.startsWith("..")) continue;   // kubelet's ..data / ..2026_08_16_… symlinks
    const m = KEY.exec(f);
    if (!m) { console.error(`ignoring token key ${f}: expected CLIENT_RO or CLIENT_RW`); continue; }
    const client = m[1].toLowerCase().replaceAll("_", "-");
    const scope  = m[2].toLowerCase();
    for (const tok of readFileSync(path.join(DIR, f), "utf8").trim().split(",")) {
      const t = tok.trim();
      // A truncated paste must not become a weak credential.
      if (t.length < 32) { console.error(`ignoring short token for ${client}`); continue; }
      const hex = sha(t).toString("hex");
      next.set(hex, { client, scope, kid: hex.slice(0, 8) });
    }
  }
  registry = next;
  loadedAt = Date.now();
  console.log(JSON.stringify({ evt: "registry",
    clients: [...new Set([...next.values()].map(v => `${v.client}:${v.scope}`))].sort() }));
}

export function initAuth() {
  mkdirSync(SEEN, { recursive: true });
  try { load(); } catch (e) { console.error(`cannot read token dir ${DIR}: ${e.message}`); process.exit(1); }
  // Fail closed and loud. An empty registry at boot means the Secret is missing
  // or misnamed, and a crashloop is the correct, visible outcome. An endpoint
  // that comes up with no tokens would accept nothing, but it would also hide
  // the misconfiguration behind a wall of 401s.
  if (!registry.size) { console.error(`no usable tokens in ${DIR}`); process.exit(1); }
}

// ponytail: 30s poll, not fs.watch. The kubelet swaps the ..data symlink
// atomically and watch semantics across that swap are fiddly; a readdir of a
// handful of small files every 30s costs nothing and cannot miss an update.
function fresh() {
  if (Date.now() - loadedAt < RELOAD_MS) return;
  // A failed reload keeps the previous registry, so a transient readdir error
  // does not lock out working consumers.
  try { load(); }
  catch (e) { loadedAt = Date.now(); console.error(`registry reload failed: ${e.message}`); }
}

function touch(client) {
  const p = path.join(SEEN, client);
  try { if (Date.now() - statSync(p).mtimeMs < 30_000) return; } catch { /* first time */ }
  try { writeFileSync(p, ""); } catch (e) { console.error(`last-seen ${client}: ${e.message}`); }
}

// pv=false keeps a line off the PersistentVolume. Used for 401s: that path is
// UNAUTHENTICATED, so appending it to a file on the PV would hand any pod in
// the cluster a disk-fill primitive. stdout is rotated by the kubelet, so it is
// bounded by construction.
export function audit(o, pv = true) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...ctx.getStore(), ...o });
  console.log(line);                                   // kubectl logs
  if (pv) try { appendFileSync(AUDIT, line + "\n"); } catch { /* PV full: keep serving */ }
}

export function authStats() {
  const cut = Date.now() - 900_000;
  while (denials.length && denials[0] < cut) denials.shift();
  const seen = {};
  for (const { client } of registry.values()) {
    try { seen[client] = Math.round((Date.now() - statSync(path.join(SEEN, client)).mtimeMs) / 1000); }
    catch { seen[client] = null; }
  }
  return { denied_15m: denials.length, calls: counters.calls, writes: counters.writes,
           last_seen_seconds_ago: seen };
}

export function auth(q, s, next) {
  fresh();
  const m = /^Bearer (\S+)$/.exec(q.get("authorization") ?? "");
  // O(1) lookup keyed by the digest. This does not need to be constant time:
  // the compared value is a SHA-256 digest, not the secret, and a timing oracle
  // on a digest gives no route back to its preimage. It also stays O(1) at ten
  // consumers, where a loop of timingSafeEqual calls would leak the count and
  // roughly where in the list a token sits.
  const hit = m && registry.get(sha(m[1]).toString("hex"));
  if (!hit) {
    if (denials.length < 1000) denials.push(Date.now());
    audit({ client: null, evt: "denied", ip: q.socket.remoteAddress, has_header: !!m }, false);
    s.set("WWW-Authenticate", "Bearer").status(401).end();
    return;
  }
  counters.calls[hit.client] = (counters.calls[hit.client] ?? 0) + 1;
  touch(hit.client);            // replaces n8n's separate heartbeat write
  q.client = hit.client;
  q.scope  = hit.scope;
  // Copy, never the registry entry itself: the request handler writes the tool
  // name and outcome into the store, and two concurrent calls on one token
  // would otherwise share an object and cross-contaminate the audit log.
  ctx.run({ ...hit }, next);
}
