# AGENTS.md — FodprWebClient

Operational commands for development, build, deploy, and the production static host.

## Architecture (v0.6 "Mesh")

Fodpr is now a **fully P2P mesh** network. There is **no relay server**, **no central
API**, and **no host concept**. All connection is client-to-client (F2F) over WebRTC.

- **Connection**: F2F only. Star/host topology is removed. Every peer connects to a set
  of mesh neighbors over WebRTC data channels.
- **IP discovery**: Kademlia DHT running **over WebRTC data channels**
  (`src/lib/dht.ts`). A peer's IPv6 is found by its public key via
  `FIND_NODE` / `FIND_VALUE`. Node ID = SHA-256(compressed pubkey).
- **WoT (Web of Trust)**: IPv6 addresses discovered via DHT are scored with WoT
  (`src/lib/wot.ts`). New/unverified peers **start at the minimum trust score** and
  are only dialed once their score reaches the connect threshold. Scores rise through
  WoT introductions and successful interaction; decay over time (`fodpr_peer_trust`).
- **Messaging**: signed events propagate by gossip over the mesh
  (`src/lib/f2fMesh.ts`, hop-limited, deduped by eventId). Direct P2P messages use
  `FodprData`.
- **Bootstrap** (no relay): invitation codes (`f2finv1...`), configured bootstrap
  nodes (list of `fpub1...@[ipv6]:port`), and manual IP entry.

Key modules:

| File | Role |
|---|---|
| `src/lib/dht.ts` | Kademlia routing table (256-bit ID, k-buckets), PING/FIND_NODE/FIND_VALUE/STORE over data channels |
| `src/lib/f2fMesh.ts` | Mesh manager: WebRTC peer connections, neighbor dial, gossip broadcast, event sync |
| `src/lib/wot.ts` | WoT scoring for discovered IPv6 peers (min score start, decay, introductions) |
| `src/lib/fodprF2f.ts` | F2F peer connection + data channel + signaling helpers (invitation, PeerList) |
| `src/lib/network.ts` | Single network path: F2F mesh + DHT (no mode selector) |

Removed in v0.6: relay client (`src/lib/relay.ts`), host-promotion groups
(`src/lib/rtcGroup.ts`), 3-mode switch (`f2f`/`rtcgroup`/`relay`), relay event REST,
media upload API. The relay source tree `FodprRelay/` and the library companion
server (`Fodpr/src/server.nim`, `Fodpr/src/f2f/group.nim`) are deleted.

## Lint / typecheck / build

```sh
pnpm typecheck     # not scripted -> use: node_modules/.bin/tsc --noEmit
node_modules/.bin/tsc --noEmit
pnpm build         # = tsc && vite build
```

## Run locally (dev)

```sh
pnpm dev --port 5199
```

Dev network: no server required. Peers discover each other over the mesh once
connected (bootstrap node list / invitation code). Seed bootstrap nodes from
`localStorage.fodpr_bootstrap_nodes` (comma-separated `fpub@[ipv6]:port`).

## Tests

Run from `/tmp/opencode/pwtest`:

```sh
node mesh_connect.mjs
```

Two browser-like clients bootstrap, connect over WebRTC (direct IPv6 dial), exchange
a signed event via gossip, and verify both peers see it. The previous relay-based
tests (`feed.mjs`, `repost_quote.mjs`, `reply.mjs`, `reply_mobile_delete.mjs`) are
obsolete and removed.

## Production static host (no server logic)

The web app is served as static files only. `api/server.mjs` is reduced to static
file serving + docs (no REST events, no media upload, no relay bridge).

Config (env vars / `.env`):

```
FODPR_STATIC_ROOT=/var/www/fodpr
FODPR_API_PORT=8088
```

Start:

```sh
pnpm start:api           # = node api/server.mjs
nohup node api/server.mjs > /tmp/fodpr-api.log 2>&1 &
```

Stop:

```sh
kill $(pgrep -f 'api/server.mjs')
```

## Deploy (static files)

```sh
pnpm deploy            # build + sync dist/ -> /var/www/fodpr
```

Manual sync if needed:

```sh
cp -r dist/assets /var/www/fodpr/assets
cp dist/index.html /var/www/fodpr/index.html
cp public/docs.html /var/www/fodpr/docs.html
```

## Health / smoke checks

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://prrr.yoinekodo.jp/
curl -s -o /dev/null -w '%{http_code}\n' https://prrr.yoinekodo.jp/docs.html
```

## P2P mesh notes

- **Kademlia over WebRTC**: DHT RPCs ride existing WebRTC data channels; a node's
  routing table survives while at least one mesh neighbor stays connected. Bootstrap
  nodes are seeded into the routing table on first run.
- **WoT gating**: `connectIfTrusted()` only dials peers whose trust score >= the
  configured minimum (default 0.0 — a WoT introduction raises it). See `wot.ts`.
- **Gossip**: `broadcastEvent()` floods to mesh neighbors up to `MAX_HOPS=2`, dedup
  via `Set<eventIdHex>`.
- **Signaling**: direct dial uses host candidates from the DHT value
  (`[ipv6]:port`); a failing direct dial falls back to signaling through an already
  connected mesh peer.
- **localStorage keys**: `fodpr_vault` (keys), `fodpr_f2f_peer_cache`,
  `fodpr_peer_trust`, `fodpr_bootstrap_nodes`, `fodpr_network_mode` (deprecated,
  always `f2f`).

## Notes

- Static files: `dist/` → `/var/www/fodpr` (served by `server.mjs` at `/` and
  `/docs.html`).
- Event reference: `reference.md` (v0.6 mesh/gossip version).
