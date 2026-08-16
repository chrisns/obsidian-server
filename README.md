# obsidian-server

Container image that keeps an Obsidian vault synced on a server and serves it to
agents over MCP. Two processes, one volume, no desktop app and no Electron.

- **sync** runs [`obsidian-headless`](https://github.com/obsidianmd/obsidian-headless)
  (`ob sync --continuous`), the official CLI Sync client, so the vault stays
  current without a machine that has to be awake.
- **mcp** serves that directory over streamable HTTP MCP: search, read, list,
  status, and a gated write.

Deployed from [chrisns/infra](https://github.com/chrisns/infra) under `obsidian/`.

## Why no Obsidian app

The vault this was built for uses no Dataview, no Templater and no Tasks across
all of its notes, so nothing in it needs evaluating at read time. A filesystem
reader therefore loses nothing, and skipping the desktop app removes an Electron
runtime, a VNC server and a GUI login from a workload that should be a daemon.

If your vault does lean on those plugins, this is the wrong tool: a filesystem
reader hands an agent unevaluated query source instead of results. Use the
[Local REST API plugin](https://github.com/coddingtonbear/obsidian-local-rest-api)
with the real app instead.

## Auth

Per-consumer bearer tokens. The server stores only a SHA-256 digest of each and
looks tokens up by digest, so there is no string comparison to leak timing.

Tokens are files in a mounted directory, one per consumer, named `CLIENT_SCOPE`:

```
/etc/mcp-tokens/N8N_WATCH_RO      -> a1b2...            client n8n-watch, read only
/etc/mcp-tokens/INDEXER_RW        -> c3d4...,e5f6...    client indexer, mid-rotation
```

Scope is structural rather than a runtime check. A read-only consumer connects
to an MCP server instance that was never told `vault_write` exists, so it is
absent from `tools/list` and unreachable from dispatch.

The directory is re-read every 30 seconds, so adding or revoking a consumer
needs no restart. A comma-separated value means two live tokens during rotation,
and every audit line carries `kid`, the first eight hex of the digest, so you can
watch the old one fall out of use before deleting it.

`/healthz` and `/readyz` are unauthenticated, for the kubelet.

## Health

The probes watch sync *progress*, not the sync *process*. `ob sync --continuous`
does not exit when its websocket wedges, so a liveness check on the process would
report healthy through a total sync outage. `ob sync-status` is no better: it
reads a config file and prints, with no network call and no timestamp, and exits
0 whether sync last completed three seconds or six weeks ago.

`syncprobe` parses the `Fully synced` line out of `sync.log` instead, and
`vault_status` exposes the same figure as data so an agent can say "newest note
is 40 minutes old" rather than falling over.

## Storage

Node-local, not NFS. Three independent reasons, any one sufficient:

1. `state.db` is better-sqlite3 in WAL mode. WAL needs a shared-memory mmap of a
   `-shm` file, which SQLite does not support over NFS.
2. `ob`'s change detection is inotify (`fs.watch`, `recursive: false` on Linux)
   and its periodic tick does not rescan the disk. Writes made by a different NFS
   client are never noticed, so they would never upload.
3. Upstream issues [#19](https://github.com/obsidianmd/obsidian-headless/issues/19)
   and [#28](https://github.com/obsidianmd/obsidian-headless/issues/28) are open
   and correlate remote deletion with networked filesystems. That failure
   propagates to every synced device.

## Status

`obsidian-headless` is an official open beta. Pin by digest, not by tag, and run
`--mode pull-only` until you are confident, since it structurally cannot delete
or upload.

## Licence

MIT
