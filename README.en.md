# Fodpr Web Client

A browser-based client for [Fodpr](https://github.com/LunaYoineko/Fodpr) relay servers, styled like Nostter. It is built with TypeScript + React + Vite + Tailwind CSS and reuses the wire protocol (`Protocol`) and signing utilities (`CryptoUtils`) from the **[Fodpr TypeScript SDK](../FodprTSSDK)**.

> Japanese version: [README.md](README.md)

## Features

- **Text / Image / Repost / Quote / Reaction** — supports every post format
  - Text (`TransType: String`), Image (`TransType: Binary`, compressed to ≤ 10 MB client-side)
  - Repost / Quote (comment + `quote:` tag), Heart reaction (`react:` tag, click again to undo)
- **Profile (TransType: JSON)** — post `{"mode":"profile","name":"...","about":"...","picture":"..."}`. Profile management is the client's responsibility (detected via the `mode` key)
- **Subscriptions & Real-time Sync (REQ / PUSH)** — timelines subscribed with `REQ` are updated in real time from other devices **without a reload**
- **Key management** — the private key is AES-256-GCM encrypted and stored in `localStorage` + IndexedDB, restored automatically on reload (auto-migrates old plaintext `fodpr_priv`)
- **PWA** — offline caching via Service Worker + home-screen install support (iOS safe-area / Safari bottom-nav padding handled)
- **Responsive layout**
  - Desktop: composer fixed at the bottom (toggleable, preference persisted)
  - Mobile: a pen (FAB) button at the bottom-right opens the composer as a centered modal
- **Client Implementation Guide** — a page opened from the Settings screen documents the post formats, tag specs, `dedupeKey` computation, and the relay list format

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

## Usage

1. Run `pnpm dev` and open the browser.
2. The header dot (green/red) shows the connection status to the relay.
3. Type a note → post (Ctrl/Cmd + Enter to submit) → it appears in the timeline immediately (optimistic render).
4. Click the image button → compressed (≤ 10 MB) binary post.
5. On a post: click the heart to react (click again to undo), click the repost icon for repost / quote.
6. **Profile** tab → enter name / about / avatar URL → posted as JSON.
7. Click a user's avatar or name → open their profile.
8. **Settings** tab → add/remove relay URLs, copy the secret key, and open the **Client Implementation Guide** (formats & specs).

## Project Structure

```
FodprWebClient/
├── public/
│   ├── favicon.svg              # favicon
│   ├── icon-192.png / icon-512.png / icon-180.png  # PWA icons
│   ├── manifest.webmanifest     # PWA manifest
│   └── sw.js                    # Service Worker (offline cache)
├── src/
│   ├── App.tsx                  # Main UI (header / nav / timeline / composer / settings / login)
│   ├── main.tsx                 # React entry + PWA(Service Worker) registration
│   ├── index.css                # Tailwind + aurora background + LiquidGlass theme
│   ├── types.d.ts               # Module type declarations
│   ├── lib/
│   │   ├── relay.ts             # Browser WebSocket client (uses SDK Protocol/CryptoUtils)
│   │   ├── bech32.ts            # Bech32 encode/decode for "fsec1..." secret keys
│   │   └── keystore.ts          # AES-256-GCM encrypted secret-key storage / restore
│   ├── hooks/
│   │   └── useRelay.ts          # useRelay hook (connection / send / status)
│   └── components/ (planned)    # For future code splitting
├── vite.config.ts               # @fodpr alias + media proxy middleware
├── tsconfig.json
├── tailwind.config.js
├── postcss.config.js
└── package.json
```

## Wire Protocol

- Communication uses **binary WebSocket frames** only; text frames would corrupt the public-key/signature byte sequences under UTF-8.
- See the **Client Implementation Guide** (Settings → "開く") or [`@fodpr/protocol`](../FodprTSSDK/src/protocol.ts) for the event format / tag spec.

## Notes

- For production over HTTPS, use `wss://` instead of `ws://` for the relay URL.
- Default relay: `wss://fodpr-relay.yoinekodo.jp/` (override with `VITE_FODPR_RELAY`).

## License

MIT
