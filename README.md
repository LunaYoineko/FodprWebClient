# Fodpr Web Client

[Fodpr](https://github.com/LunaYoineko/Fodpr) リレーサーバー向けのブラウザクライアント。
TypeScript + React + Vite + Tailwind CSS でビルドし、**[Fodpr TypeScript SDK](../FodprTSSDK)** のワイヤプロトコル(`Protocol`)と署名ユーティリティ(`CryptoUtils`)をそのまま再利用している。

> English version: [README.en.md](README.en.md)

## 特徴

- **テキスト・画像・リポスト・引用・リアクション** — すべての投稿フォーマットをサポート
  - テキスト (`TransType: String`)、画像 (`TransType: Binary`, クライアント側で 10MB まで圧縮)
  - リポスト / 引用リポスト (コメント + `quote:` タグ)、ハートリアクション (`react:` タグ, 再クリックで取消)
- **プロフィール (TransType: JSON)** — `{"mode":"profile","name":"...","about":"...","picture":"..."}` として JSON 投稿。プロフィール管理はクライアント側の責務 (`mode` キーで判定)
- **購読 & リアルタイム同期 (REQ / PUSH)** — `REQ` で購読したタイムラインを他の端末からの投稿もリロードなしで即受信
- **鍵管理** — 秘密鍵を AES-256-GCM で暗号化して `localStorage` + IndexedDB に保存。再読込時は自動復元 (旧平文 `fodpr_priv` からの自動移行も行う)
- **PWA** — Service Worker によるオフラインキャッシング + ホーム画面インストール対応 (iOS 安全領域/Safari 下部ナビのパディング調整済)
- **レスポンシブレイアウト**
  - デスクトップ: 画面下部に固定コンポーザー (表示/非表示を切替可能、設定を永続化)
  - モバイル: 画面右下のペン (FAB) ボタン → 投稿欄を中央モーダルで表示
- **クライアント実装ガイド** — 設定画面から開けるページで、投稿フォーマット / タグ仕様 / `dedupeKey` 算出 / リレー一覧の仕様を確認可能

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

## 使い方

1. `pnpm dev` で開発サーバーを起動しブラウザで開く
2. ヘッダーの接続ステータス (緑/赤ドット) がリレーへの接続状態
3. テキスト欄に入力 → 投稿 (Ctrl/Cmd + Enter で送信) → タイムラインへ即反映 (Optimistic)
4. 画像ボタン → 10MB まで圧縮してバイナリ投稿
5. 投稿カードのハートでリアクション (再クリックで取消)、リポストアイコンでリポスト/引用
6. **プロフィール** タブ → 名前/自己紹介/アバター URL を入力 → JSON として投稿
7. 他ユーザーのアバター/名前をクリック → そのユーザーのプロフィールを開く
8. **設定** タブ → リレー URL の追加/削除、秘密鍵のコピー、**「クライアント実装ガイド」→開く** でフォーマット仕様を確認

## プロジェクト構成

```
FodprWebClient/
├── public/
│   ├── favicon.svg              # ファビコン
│   ├── icon-192.png / icon-512.png / icon-180.png  # PWA アイコン
│   ├── manifest.webmanifest     # PWA マニフェスト
│   └── sw.js                    # Service Worker (オフラインキャッシュ)
├── src/
│   ├── App.tsx                  # メイン UI (ヘッダー/ナビ/タイムライン/コンポーザー/設定/ログイン)
│   ├── main.tsx                 # React エントリ + PWA(SW)登録
│   ├── index.css                # Tailwind + オーロラ背景 + LiquidGlass テーマ
│   ├── types.d.ts               # モジュール型宣言
│   ├── lib/
│   │   ├── relay.ts             # ブラウザ WebSocket クライアント (SDK Protocol/CryptoUtils 使用)
│   │   ├── bech32.ts            # "fsec1..." 秘密鍵の Bech32 エン/デコード
│   │   └── keystore.ts          # 秘密鍵の AES-256-GCM 暗号化保存/復号
│   ├── hooks/
│   │   └── useRelay.ts          # useRelay カスタムフック (接続/送受信/ステータス)
│   └── components/ (計画中)      # 将来の分割用
├── vite.config.ts               # @fodpr エイリアス + media プロキシ
├── tsconfig.json
├── tailwind.config.js
├── postcss.config.js
└── package.json
```

## 通信仕様

- **バイナリフレーム**で通信。テキストフレームは UTF-8 エンコードにより公開鍵/署名のバイト列を壊すため使用しない。
- イベントの送受信形式は **[クライアント実装ガイド](README.md)** (設定 → 開く) または [`@fodpr/protocol`](../FodprTSSDK/src/protocol.ts) を参照。

## メモ

- 本番で HTTPS を使う場合はリレー URL を `wss://` に変更する。
- デフォルトリレーは `wss://fodpr-relay.yoinekodo.jp/` (環境変数 `VITE_FODPR_RELAY` で上書き可)。

## ライセンス

MIT
