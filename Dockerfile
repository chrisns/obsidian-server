# ghcr.io/chrisns/obsidian-vault
#
# Debian, not Alpine: better-sqlite3 12.11.1 is a native module and glibc is the
# tested surface. Alpine also correlates with #45 (0777 file modes).
# Node 22 exactly: engines says >=22.0.0 but #43 shows Node 26 breaking on the
# pinned better-sqlite3.
FROM node:22-bookworm-slim@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436

RUN apt-get update \
 && apt-get install -y --no-install-recommends ripgrep ca-certificates curl unison \
 && rm -rf /var/lib/apt/lists/*

ARG OB_VERSION=0.0.14
# NODE_PATH makes the global install resolvable from an eval context. The
# require is advisory: obsidian-headless ships prebuilt natives bundled inside
# its own tree rather than as a separately resolvable top-level module, so it
# legitimately may not resolve. `ob --version` is the real check, because it
# fails if the native module did not load.
RUN npm install -g obsidian-headless@${OB_VERSION} \
 && (NODE_PATH="$(npm root -g)" node -e "require('better-sqlite3')" \
     && echo "better-sqlite3 resolves top-level" \
     || echo "better-sqlite3 bundled inside obsidian-headless") \
 && ob --version

WORKDIR /opt/mcp
COPY mcp/package.json mcp/package-lock.json ./
RUN npm ci --omit=dev
COPY mcp/server.js mcp/auth.js ./

COPY bin/syncprobe bin/vaultsync /usr/local/bin/
RUN chmod +x /usr/local/bin/syncprobe /usr/local/bin/vaultsync

ENV HOME=/data/state \
    XDG_CONFIG_HOME=/data/state \
    OB_STATE=/data/state/obsidian-headless \
    VAULT=/data/vault \
    STAGING=/data/staging
WORKDIR /data/vault
USER 1000:1000
ENTRYPOINT ["ob"]
CMD ["sync", "--path", "/data/vault", "--continuous"]
