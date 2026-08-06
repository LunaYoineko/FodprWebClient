# AGENTS.md — FodprWebClient

Operational commands for development, build, deploy, and the production API server.

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

Relay (dev): `ws://localhost:8000` (docker `fodprrelay`). The app reads relays from
`localStorage.fodpr_relays`; the test scripts seed it for you.

## Tests

Run from `/tmp/opencode/pwtest`:

```sh
node feed.mjs http://localhost:5199
node repost_quote.mjs http://localhost:5199
node reply.mjs http://localhost:5199
node reply_mobile_delete.mjs http://localhost:5199
```

A Chromium browser is auto-launched. The test sets `fodpr_priv` + `fodpr_relays`
(= `ws://localhost:8000`) in localStorage before navigation.

## Production API server (static + REST + relay bridge)

Config (env vars / `.env`):

```
FODPR_STATIC_ROOT=/var/www/fodpr
FODPR_RELAY_URL=ws://localhost:8000/
FODPR_MEDIA_DIR=/root/FodprWebClient/media
FODPR_API_PORT=8088
```

Start:

```sh
pnpm start:api           # = node api/server.mjs
# or full env form:
export FODPR_STATIC_ROOT=/var/www/fodpr
export FODPR_RELAY_URL=ws://localhost:8000/
export FODPR_MEDIA_DIR=/root/FodprWebClient/media
export FODPR_API_PORT=8088
nohup node api/server.mjs > /tmp/fodpr-api.log 2>&1 &
```

Stop:

```sh
pkill -f 'api/server.mjs'        # or: kill $(pgrep -f 'api/server.mjs')
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
# API docs live in api/docs.html (served at /api/docs)
```

## Health / smoke checks

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://fodpr.yoinekodo.jp/
curl -s -o /dev/null -w '%{http_code}\n' https://fodpr.yoinekodo.jp/docs.html
curl -s -o /dev/null -w '%{http_code}\n' https://fodpr.yoinekodo.jp/api/docs
curl -s https://fodpr.yoinekodo.jp/api/health
```

## Notes

- Static files: `dist/` → `/var/www/fodpr` (served by `server.mjs` at `/` and `/docs.html`).
- API docs: `api/docs.html` → served at `/api/docs` (not part of `dist/`).
- Client implementation guide: `public/docs.html` → served at `/docs.html`.
- Event reference: `reference.md`.
