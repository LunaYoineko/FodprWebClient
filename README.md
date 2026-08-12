# Prrr

分散型SNSクライアント。[Fodpr](https://github.com/LunaYoineko/Fodpr) リレーサーバーと Nostr リレーの両方に対応したブラウザクライアント。
TypeScript + React + Vite + Tailwind CSS でビルドし、**[Fodpr TypeScript SDK](../FodprTSSDK)** のワイヤプロトコル(`Protocol`)と署名ユーティリティ(`CryptoUtils`)をそのまま再利用している。

> English version: [README.en.md](README.en.md)

## 特徴

- **Fodpr / Nostr の 2 ネットワークを 1 つの UI で** — ヘッダーのタブで切替。Fodpr は fsec、Nostr は nsec でログイン
- **Fodpr の投稿フォーマットをすべてサポート**
  - テキスト (`TransType: String`)、画像 (`TransType: Binary`, クライアント側で 10MB まで圧縮)
  - リポスト / 引用リポスト (コメント + `quote:` タグ)、ハートリアクション (`react:` タグ, 再クリックで取消)
  - プロフィール (`TransType: JSON`) — `{"mode":"profile","name":"...","about":"...","picture":"..."}` を JSON 投稿 (`mode` キーで判定)
- **Nostr 対応**
  - kind 1 タイムライン / kind 7 リアクション / kind 6 リポスト / kind 1 リプライ / kind 5 削除
  - kind 0 プロフィールを取得し、各投稿の表示名 (`display_name` → `name` → short npub) とアバターを表示
  - nsec / npub 対応、自分のプロフィール (kind 0) の編集・公開、kind 10002 リレーリストの取得と接続先への追加
- **購読 & リアルタイム同期 (REQ / PUSH)** — 購読したタイムラインを他の端末からの投稿もリロードなしで即受信
- **鍵管理** — Fodpr の fsec / Nostr の nsec を AES-256-GCM で暗号化して `localStorage` + IndexedDB に保存。再読込時は自動復元 (旧平文 `fodpr_priv` からの自動移行も行う)
- **画像アップロード** — プロフィール画像は `/media/upload` にアップロードし直リンク URL を保存
- **PWA** — Service Worker によるオフラインキャッシング + ホーム画面インストール対応 (iOS 安全領域/Safari 下部ナビのパディング調整済)
- **レスポンシブレイアウト**
  - デスクトップ: 画面下部に固定コンポーザー (表示/非表示を切替可能、設定を永続化)
  - モバイル: 画面右下のペン (FAB) ボタン → 投稿欄を中央モーダルで表示
- **REST API サーバー同梱** — `api/server.mjs` が静的ファイル配信 + 画像アップロード + リレー中継を提供
- **クライアント実装ガイド** — 設定画面から開けるページで、投稿フォーマット / タグ仕様 / `dedupeKey` 算出 / リレー一覧の仕様を確認可能
- **F2F (Friend-to-Friend) P2P ネットワーク** — Web of Trust 方式でピアキャッシュを最大 50 件保存。招待コード (`f2finv1...`) またはリレーシードでブートストラップ。接続確立時に署名付き PeerList を交換し、キャッシュからリレーなしでマルチモーダルに再接続可能
- **RtcGroup (ホスト昇格型 P2P)** — 最初の接続者がホストとなり、ホスト離脱時に最古参加者が自動昇格。WebRTC シグナリングをリレー経由で中継
- **ネットワークモード切替** — 設定画面で **F2F (WoT) / RtcGroup (ホスト昇格) / リレーのみ** をトグル選択可能

## 必要環境

- Node.js 18 以上
- [pnpm](https://pnpm.io/)
- 動作中の Fodpr リレーサーバー (開発中は `ws://localhost:8000/`)

> クライアント本体は SDK に依存しないが、ビルドには `@fodpr` エイリアスで SDK ソース(`../FodprTSSDK`)が必要。

## セットアップ

```bash
pnpm install
pnpm dev            # http://localhost:5199
```

### 本番ビルド & プレビュー

```bash
pnpm build          # dist/ に静的ファイルを出力
pnpm preview        # http://localhost:8000 でプレビュー
```

### REST API サーバー (静的配信 + メディア + リレー中継)

```bash
pnpm start:api
```

設定 (環境変数 / `.env`):

```
FODPR_STATIC_ROOT=/var/www/fodpr
FODPR_RELAY_URL=ws://localhost:8000/
FODPR_MEDIA_DIR=/root/FodprWebClient/media
FODPR_API_PORT=8088
```

## 使い方

1. `pnpm dev` で開発サーバーを起動しブラウザで開く
2. ログイン画面で Fodpr (fsec) または Nostr (nsec) を選択。鍵なしで「閲覧だけする」も可
3. ヘッダーのタブで Fodpr / Nostr のネットワークを切替
4. テキスト欄に入力 → 投稿 (Ctrl/Cmd + Enter で送信) → タイムラインへ即反映 (Optimistic)
5. 画像ボタン → 10MB まで圧縮してバイナリ投稿
6. 投稿カードのハートでリアクション (再クリックで取消)、リポストアイコンでリポスト/引用
7. **プロフィール** タブ → 名前/自己紹介/アバターを編集して公開 (Fodpr は JSON、Nostr は kind 0)
8. Nostr では他ユーザーの名前/アバターをクリック → kind 0 を取得してプロフィールを表示
9. **設定** タブ → リレー URL の追加/削除、秘密鍵のコピー、**「クライアント実装ガイド」→開く** でフォーマット仕様を確認
10. **設定** → **ネットワークモード** で F2F / RtcGroup / リレーのみ を選択
    - **F2F**: 「招待コード発行」ボタンでコード生成 → 相手に送る。「招待コードで接続」で相手のコード入力。シード取得でリレーからピア候補 50 件取得
    - **RtcGroup**: 「グループ作成」でホストになる、または「グループ参加」でホスト fpub 指定
    - **リレーのみ**: P2P 接続を行わない

## プロジェクト構成

```
FodprWebClient/
├── public/
│   ├── favicon.svg / icons.svg      # アイコン
│   ├── icon-192.png / icon-512.png / icon-180.png  # PWA アイコン
│   ├── manifest.webmanifest         # PWA マニフェスト
│   ├── sw.js                        # Service Worker (オフラインキャッシュ)
│   └── docs.html                    # クライアント実装ガイド
├── api/
│   ├── server.mjs                   # REST API (静的配信 / /media/upload / リレー中継)
│   └── docs.html                    # API ドキュメント (/api/docs)
├── src/
│   ├── App.tsx                      # メイン UI (ヘッダー/ナビ/タイムライン/コンポーザー/設定/ログイン)
│   ├── main.tsx                     # React エントリ + PWA(SW)登録
│   ├── index.css                    # Tailwind + オーロラ背景 + LiquidGlass テーマ
│   ├── types.d.ts                   # モジュール型宣言
│   ├── lib/
│   │   ├── relay.ts                 # Fodpr WebSocket クライアント (SDK Protocol 使用)
│   │   ├── nostrRelay.ts            # Nostr WebSocket クライアント (JSON テキストフレーム)
│   │   ├── nostrProtocol.ts         # Nostr イベント生成/署名検証/kind 0 パース
│   │   ├── protocolAdapter.ts       # Fodpr / Nostr → UnifiedEvent 正規化
│   │   ├── bech32.ts                # "fsec1..." / "nsec1..." / "npub1..." Bech32 エン/デコード
│   │   ├── keystore.ts              # 秘密鍵の AES-256-GCM 暗号化保存/復号
│   │   ├── fodprF2f.ts              # F2F (WoT) P2P マネージャ: ピアキャッシュ/招待/グループ/シグナリング
│   │   ├── rtcGroup.ts              # RtcGroup (ホスト昇格型) P2P マネージャ: WebRTCシグナリング/ホスト昇格
│   │   └── network.ts               # 統合ネットワーク層 (3モード切替)
│   └── hooks/
│       ├── useRelay.ts              # Fodpr リレー用フック (接続/送受信/ステータス)
│       └── useNostrRelay.ts         # Nostr リレー用フック
├── vite.config.ts                   # @fodpr エイリアス + media プロキシ
├── tsconfig.json
├── tailwind.config.js
├── postcss.config.js
└── package.json
```

## 通信仕様

- **Fodpr**: バイナリ WebSocket フレームで通信。テキストフレームは UTF-8 エンコードにより公開鍵/署名のバイト列を壊すため使用しない。
- **Nostr**: 標準の JSON テキストフレーム (NIP-01) で通信。kind 0/1/5/6/7/10002 を処理。
- Fodpr のイベント形式 / タグ仕様は **[クライアント実装ガイド](public/docs.html)** (設定 → 開く) または [`@fodpr/protocol`](../FodprTSSDK/src/protocol.ts) を参照。
- **F2F PeerList 交換**: `TransTypePeerList` (0x09) / `MsgTypePeerListPush` (0x87) で署名付きピアリスト (最大 50 件) を P2P データチャネル経由で交換。キャッシュマージ後、未接続ピアへ自動ダイヤル。
- **RtcGroup**: `TransTypeWebRTC` + `to:<hostFpub>` 購読で WebRTC シグナリング中継。ホスト切断時 `HOST_CHANGE` テキスト通知で全員再接続。

## メモ

- 本番で HTTPS を使う場合はリレー URL を `wss://` に変更する。
- デフォルトリレー: Fodpr = `wss://fodpr-relay.yoinekodo.jp/`, Nostr = `wss://relay.yoinekodo.jp/` (設定画面または `localStorage` の `fodpr_relays` / `nostr_relays` で変更可)。
- ネットワークモードは `localStorage.fodpr_network_mode` に永続化される (`f2f` | `rtcgroup` | `relay`)。

## ライセンス

MIT