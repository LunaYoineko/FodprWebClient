# Prrr

A decentralized SNS client. A browser client that supports both [Fodpr](https://github.com/LunaYoineko/Fodpr) relay servers and Nostr relays.
It is built with TypeScript + React + Vite + Tailwind CSS and reuses the wire protocol (`Protocol`) and signing utilities (`CryptoUtils`) from the **[Fodpr TypeScript SDK](../FodprTSSDK)**.

> Japanese version: [README.md](README.md)

## Features

- **Fodpr / Nostr in a single UI** — switch networks with the header tabs. Log in with fsec (Fodpr) or nsec (Nostr)
- **Supports every Fodpr post format**
  - Text (`TransType: String`), Image (`TransType: Binary`, compressed to ≤ 10 MB client-side)
  - Repost / Quote (comment + `quote:` tag), Heart reaction (`react:` tag, click again to undo)
  - Profile (`TransType: JSON`) — post `{"mode":"profile","name":"...","about":"...","picture":"..."}` (detected via the `mode` key)
- **Nostr support**
  - kind 1 timeline / kind 7 reactions / kind 6 reposts / kind 1 replies / kind 5 deletions
  - Fetches kind 0 profiles and shows each post's display name (`display_name` → `name` → short npub) and avatar
  - nsec / npub support, edit & publish your own profile (kind 0), fetch kind 10002 relay lists and add them to the connection targets
- **Subscriptions & Real-time Sync (REQ / PUSH)** — timelines subscribed with `REQ` are updated in real time from other devices **without a reload**
- **Key management** — Fodpr fsec / Nostr nsec are AES-256-GCM encrypted and stored in `localStorage` + IndexedDB, restored automatically on reload (auto-migrates old plaintext `fodpr_priv`)
- **Image upload** — profile images are uploaded to `/media/upload` and saved as a direct-link URL
- **PWA** — offline caching via Service Worker + home-screen install support (iOS safe-area / Safari bottom-nav padding handled)
- **Responsive layout**
  - Desktop: composer fixed at the bottom (toggleable, preference persisted)
  - Mobile: a pen (FAB) button at the bottom-right opens the composer as a centered modal
- **Bundled REST API server** — `api/server.mjs` serves static files + image upload + relay bridge
- **Client Implementation Guide** — a page opened from the Settings screen documents the post formats, tag specs, `dedupeKey` computation, and the relay list format
- **F2F (Friend-to-Friend) / WoT P2P** — peer cache (max 50), invitation code (`f2finv1...`), signed PeerList exchange on P2P connection, auto-dial from cache (relay-free), WoT introduction
- **RtcGroup (Host-Promotion P2P)** — first connection becomes host, others star-connect to host, oldest guest auto-promoted on host disconnect (`HOST_CHANGE` notification)
- **Network mode switch** — Settings UI toggles between **F2F (WoT) / RtcGroup (Host-Promotion) / Relay Only**, persisted in `localStorage.fodpr_network_mode`

## Requirements

- Node.js 18+
- [pnpm](https://pnpm.io/)
- A running Fodpr relay server (during dev `ws://localhost:8000/`)

> The client itself has no runtime dependency on the SDK, but building requires the SDK sources (`../FodprTSSDK`) via the `@fodpr` alias.

## Setup

```bash
pnpm install
pnpm dev            # http://localhost:5199
```

### Production build & preview

```bash
pnpm build          # outputs static files to dist/
pnpm preview        # previews on http://localhost:8000
```

### REST API server (static + media + relay bridge)

```bash
pnpm start:api
```

Configuration (env vars / `.env`):

```
FODPR_STATIC_ROOT=/var/www/fodpr
FODPR_RELAY_URL=ws://localhost:8000/
FODPR_MEDIA_DIR=/root/FodprWebClient/media
FODPR_API_PORT=8088
```

## Usage

1. Run `pnpm dev` and open the browser.
2. On the login screen choose Fodpr (fsec) or Nostr (nsec), or "browse only" without a key.
3. Switch between the Fodpr / Nostr networks with the header tabs.
4. Type a note → post (Ctrl/Cmd + Enter to submit) → it appears in the timeline immediately (optimistic render).
5. Click the image button → compressed (≤ 10 MB) binary post.
6. On a post: click the heart to react (click again to undo), click the repost icon for repost / quote.
7. **Profile** tab → edit and publish name / about / avatar (JSON for Fodpr, kind 0 for Nostr).
8. In Nostr, click a user's name or avatar → fetch kind 0 and open their profile.
9. **Settings** tab → add/remove relay URLs, copy the secret key, and open the **Client Implementation Guide** (formats & specs).
10. **Settings** → **Network Mode** to select F2F / RtcGroup / Relay Only
    - **F2F**: "Generate Invitation" button creates code → send to peer. "Connect with Invitation" for peer's code. "Fetch Seed" gets 50 peer candidates from relay
    - **RtcGroup**: "Create Group" becomes host, or "Join Group" with host fpub
    - **Relay Only**: no P2P connections

## Project Structure

```
FodprWebClient/
├── public/
│   ├── favicon.svg / icons.svg      # icons
│   ├── icon-192.png / icon-512.png / icon-180.png  # PWA icons
│   ├── manifest.webmanifest         # PWA manifest
│   ├── sw.js                        # Service Worker (offline cache)
│   └── docs.html                    # Client Implementation Guide
├── api/
│   ├── server.mjs                   # REST API (static / /media/upload / relay bridge)
│   └── docs.html                    # API docs (/api/docs)
├── src/
│   ├── App.tsx                      # Main UI (header / nav / timeline / composer / settings / login)
│   ├── main.tsx                     # React entry + PWA(Service Worker) registration
│   ├── index.css                    # Tailwind + aurora background + LiquidGlass theme
│   ├── types.d.ts                   # Module type declarations
│   ├── lib/
│   │   ├── relay.ts                 # Fodpr WebSocket client (uses SDK Protocol)
│   │   ├── nostrRelay.ts            # Nostr WebSocket client (JSON text frames)
│   │   ├── nostrProtocol.ts         # Nostr event generation / signature verification / kind 0 parsing
│   │   ├── protocolAdapter.ts       # Fodpr / Nostr → UnifiedEvent normalization
│   │   ├── bech32.ts                # Bech32 encode/decode for "fsec1..." / "nsec1..." / "npub1..."
│   │   └── keystore.ts              # AES-256-GCM encrypted secret-key storage / restore
│   └── hooks/
│       ├── useRelay.ts              # Fodpr relay hook (connection / send / status)
│       └── useNostrRelay.ts         # Nostr relay hook
├── vite.config.ts                   # @fodpr alias + media proxy middleware
├── tsconfig.json
├── tailwind.config.js
├── postcss.config.js
└── package.json
```

## Wire Protocol

- **Fodpr**: communication uses **binary WebSocket frames** only; text frames would corrupt the public-key/signature byte sequences under UTF-8.
- **Nostr**: standard JSON text frames (NIP-01); handles kind 0/1/5/6/7/10002.
- For the Fodpr event format / tag spec, see the **Client Implementation Guide** (`public/docs.html`, opened from Settings) or [`@fodpr/protocol`](../FodprTSSDK/src/protocol.ts).
- **F2F PeerList exchange**: `TransTypePeerList` (0x09) / `MsgTypePeerListPush` (0x87) for signed peer cache (max 50) over P2P data channel. Auto-dial from merged cache (relay-free).
- **RtcGroup**: `TransTypeWebRTC` + `to:<hostFpub>` subscription for WebRTC signaling relay. Host change via `HOST_CHANGE: <new_fpub>` text notification triggers re-subscription.

## Notes

- For production over HTTPS, use `wss://` instead of `ws://` for the relay URL.
- Default relays: Fodpr = `wss://fodpr-relay.yoinekodo.jp/`, Nostr = `wss://relay.yoinekodo.jp/` (changeable in Settings or via `fodpr_relays` / `nostr_relays` in localStorage).

## License

MIT
