# Prrr イベント送信リファレンス

この文書は、Prrr (`/root/FodprWebClient`) がどのようなイベントをどの形式でリレーに送信しているかを説明し、
別クライアントやスクリプトから同じ形式で投稿すれば Prrr のタイムラインに表示されるための手順とコードを示す。

対象プロトコルは FodprTSSDK (`/root/FodprTSSDK/src/protocol.ts`) の `Protocol` と `CryptoUtils` をそのまま使う。
サーバー(Nim)の `protocol.nim` とバイト単位で互換。

---

## 1. 前提知識

### 1.1 送信タイプ (TransType)

イベントの `content` が何であるかを表す数値。

| 定数 | 値 | 用途 |
|---|---|---|
| `TransTypeAll` | `0x00` | REQ(購読)でのみ使用 |
| `TransTypeJSON` | `0x01` | content が UTF-8 の JSON(プロフィール) |
| `TransTypeString` | `0x02` | content が UTF-8 の文字列(テキスト投稿・リアクション・リポスト・リプライ) |
| `TransTypeBinary` | `0x03` | content が任意のバイト列(画像/動画/ファイル投稿) |

### 1.2 イベントの分類 (Prrr 側)

クライアントは受信イベントを `splitEvents` (`src/App.tsx`) で以下のように振り分ける。

- `TransTypeJSON` で content が JSON かつ `mode === "profile"` → **プロフィール**
- `TransTypeString` で `react:` タグ → リアクション、`reply:` タグ → リプライ、`repost:` / `quote:` タグ → リポスト/引用、それ以外 → **テキスト投稿**
- `TransTypeBinary` → **メディア投稿**

リプライは単独の投稿カードとしてはタイムラインに並ばず、対象イベントの下にスレッドとして表示される
(`ReplyThread` / `ReplyCard`)。対象イベントがまだ未取得の場合は「返信先が見つからない投稿」欄に
フォールバック表示される。

### 1.3 イベントの一意キー (dedupeKey)

重複排除に使うキー。イベントの署名まで含めることで「同一秒に複数投稿」しても重複して弾かない。

```
dedupeKey = pubkeyHex + ":" + transType + ":" + createdAt + ":" + signatureHex
```

リポスト/引用/リアクション/リプライの対象指定(タグの値)にもこの文字列を使う。

### 1.4 署名

署名はすべて ECDSA(secp256k1, compact 形式 64 バイト)。`CryptoUtils.signMessage(privKeyHex, contentBytes)` は
**content の SHA-256 ダイジェスト**に対して署名する(`secp.signAsync` は設定済みの SHA-256 を内部で適用)。
サーバー側の検証と一致するよう、署名対象のバイト列は必ず `new TextEncoder().encode(content)` を使うこと。

---

## 2. ワイヤプロトコルと送信方法

リレーとは **バイナリ WebSocket フレーム**で通信する(テキストフレームは UTF-8 エンコードのため
公開鍵/署名のような任意バイト列を壊してしまう)。

### 2.1 パケット種別

| 種別バイト | メッセージ | 方向 |
|---|---|---|
| `0x01` | EVENT(イベント投稿) | クライアント → サーバー |
| `0x02` | REQ(購読要求) | クライアント → サーバー |
| `0x03` | DEL(削除要求) | クライアント → サーバー |
| `0x81` | PUSH(イベント配信) | サーバー → クライアント |

### 2.2 イベント本体のバイナリレイアウト (`Protocol.encodeEvent`)

すべてビッグエンディアン。

```
transType(2) | createdAt(8) | pubkey(33) | tagCount(2) | (tagLen(2) | tag) * tagCount | contentLen(4) | content | signature(64)
```

- `transType`: 1.1 の値
- `createdAt`: Unix タイムスタンプ(秒, uint64)
- `pubkey`: 圧縮公開鍵 33 バイト
- `tags`: UTF-8 文字列の配列
- `content`: UTF-8 バイト列(TransTypeBinary でも content はバイナリのまま配信される)
- `signature`: content の SHA-256 に対する ECDSA 署名 64 バイト

### 2.3 送信パケット (EVENT)

`encodeEvent` の出力は「本体」なので、送信時は先頭に種別バイト `0x01` を付ける。

```ts
const payload = Protocol.encodeEvent(event);       // イベント本体
const frame = new Uint8Array(1 + payload.length);  // 種別バイト + 本体
frame[0] = MsgTypeEvent;                           // 0x01
frame.set(payload, 1);
ws.send(frame.buffer);                             // バイナリフレームで送信
```

### 2.4 購読 (REQ)

接続確立後に一度 REQ を送ると、保存済みイベントが PUSH され、以後の新着も PUSH される。

```
MsgTypeReq(1) | subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
```

```ts
const req: FodprReq = {
  subId: 'sub_web_' + Date.now(),
  transType: TransTypeAll, // すべてのタイプを購読
  tagKey: '',
  tagVal: '',
};
ws.send(Protocol.encodeReq(req)); // 先頭に 0x02 を含む
```

タグ絞り込みも可能。例: `caption:` タグを持つメディアだけを購読する場合、`tagKey = "caption"`。

---

## 3. プロフィール投稿 (TransTypeJSON)

### 3.1 content の JSON 構造

`mode: "profile"` を必須とする。クライアントはこれでプロフィールと判定する。

```json
{
  "mode": "profile",
  "name": "表示名 (必須)",
  "about": "自己紹介 (省略可)",
  "picture": "アイコン画像の直リンク URL (省略可)"
}
```

- `name` が無いと保存されない(`postProfile` は `if (!name) return`)。
- `about` は省略時 `undefined` になる(JSON.stringify でキーごと消える)。
- `picture` は直リンク URL。ファイルからアップロードした場合は `/media/file/<name>` の相対パスが入る
  (同一オリジン前提)。別オリジンのクライアントからも表示したい場合は絶対 URL を入れること。

### 3.2 パース側 (Prrr)

```ts
// src/App.tsx
function parseProfile(content: string): { name?: string; about?: string; picture?: string } {
  const obj = JSON.parse(content);
  if (obj && typeof obj === 'object' && obj.mode === 'profile') {
    return {
      name: typeof obj.name === 'string' ? obj.name : undefined,
      about: typeof obj.about === 'string' ? obj.about : undefined,
      picture: typeof obj.picture === 'string' ? obj.picture : undefined,
    };
  }
  return {};
}
```

表示には `latestProfilePerPubkey` が **createdAt が最大のプロフィールを公開鍵ごとに 1 件**だけ採用する。
つまりプロフィールは「上書き」であり、複数投稿した場合は最新のものが使われる。

### 3.3 送信コード

```ts
import { Protocol, TransTypeJSON } from '@fodpr/protocol';
import { CryptoUtils } from '@fodpr/crypto';

const privKey = '...'; // 64 桁 HEX の秘密鍵

const profile = { mode: 'profile', name: 'なまえ', about: 'じこしょうかい', picture: 'https://example.com/icon.png' };
const content = JSON.stringify(profile);

const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));

const event: FodprEvent = {
  transType: TransTypeJSON,      // 0x01
  createdAt: Math.floor(Date.now() / 1000),
  pubkey: CryptoUtils.hexToBytes(CryptoUtils.getPublicKey(privKey)), // 圧縮公開鍵 33 バイト
  tags: [],
  content,
  signature: CryptoUtils.hexToBytes(sig),
};

// 0x01 を前置してバイナリ送信
const payload = Protocol.encodeEvent(event);
const frame = new Uint8Array(1 + payload.length);
frame[0] = 0x01;
frame.set(payload, 1);
ws.send(frame.buffer);
```

---

## 4. テキスト投稿 (TransTypeString)

### 4.1 形式

- `content`: 投稿テキストそのもの (UTF-8)
- `tags`: なし(リアクション/リポスト/引用/リプライでなければ)
- 署名対象: `content` の UTF-8 バイト列

### 4.2 送信コード (Prrr の `postNote` 相当)

```ts
const content = '今日もにゃんこ日和。';

const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));

const event: FodprEvent = {
  transType: TransTypeString,    // 0x02
  createdAt: Math.floor(Date.now() / 1000),
  pubkey: pubkeyBytes,           // 33 バイト圧縮公開鍵
  tags: [],
  content,
  signature: CryptoUtils.hexToBytes(sig),
};
sendEventToRelay(event); // Protocol.encodeEvent(event) に 0x01 前置して送信
```

※ Prrr 内部の `sendSignedEvent` は Optimistic 更新として自フィードにも即時反映するが、
外部クライアントから送る場合はサーバーからの PUSH で表示される。

---

## 5. メディア投稿 (画像/動画/ファイル) (TransTypeBinary)

### 5.1 content の形式

```
<mime>:<base64>
```

例: `image/png:iVBORw0KGgoAAAANSUhEUg...`

- `<mime>`: data URL の MIME 部分(`data:image/png;base64,XXXX` の `image/png` 部分)
- `<base64>`: data URL の base64 本体(区切りは **コロン `:`**。`;base64,` ではない)

クライアントの描画は `MEDIA_CONTENT_RE = /^(?:img:)?([^:;,]+)(?:;base64)?[,:](.+)$/s` でパースし、
`mime.startsWith('video/')` なら動画、それ以外は画像/ダウンロードリンクとして表示する。
(旧形式 `img:<mime>;base64,<data>` にも互換対応している)

### 5.2 tags

メディアには 3 つのタグを付ける。

| タグ | 内容 |
|---|---|
| `caption:<文字列>` | キャプション(無ければ元ファイル名)。カードの `alt` / 説明文に使う |
| `filename:<文字列>` | 元ファイル名(プレビューやダウンロード名に使う) |
| `mediatype:<image|video|file>` | 種別(動画かどうかの判定に使う) |

### 5.3 送信コード (Prrr の media 投稿部分相当)

```ts
// mediaDataUrl の例: "data:image/png;base64,iVBORw0KGgo..."
const dm = /^data:([^;]+);base64,(.+)$/s.exec(mediaDataUrl);
const mime = dm[1];
const base64 = dm[2];

const caption = content || mediaName || '';
const mediaContent = `${mime}:${base64}`;

const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(mediaContent));

const event: FodprEvent = {
  transType: TransTypeBinary,    // 0x03
  createdAt: Math.floor(Date.now() / 1000),
  pubkey: pubkeyBytes,
  tags: [
    `caption:${caption}`,
    `filename:${mediaName}`,
    `mediatype:${mediaType}`,    // "image" | "video" | "file"
  ],
  content: mediaContent,
  signature: CryptoUtils.hexToBytes(sig),
};
sendEventToRelay(event);
```

### 5.4 圧縮 (Prrr の挙動)

- 画像: 上限 12MB。`compressImageFile` で長辺 1600px までリサイズ+再エンコード
- 動画: 上限 50MB。`compressVideoFile` で data URL 化、`extractVideoThumbnail` でサムネイル抽出
- その他ファイル: 上限 12MB。そのまま data URL 化

(メディア本体はイベントの content に base64 で入るため、リレーの保存サイズもその分大きくなる)

---

## 6. その他のイベント (参考)

同じく TransTypeString で送られる補助イベント。いずれも対象イベントを `dedupeKey` で指定する。

| 種別 | content | tags | 定数 |
|---|---|---|---|
| リアクション | 絵文字(例 `❤️`) | `react:<dedupeKey>` | TransTypeString |
| リポスト | 空文字 | `repost:<dedupeKey>` | TransTypeString |
| 引用リポスト | 自分のコメント | `quote:<dedupeKey>` | TransTypeString |
| リプライ | 返信本文 | `reply:<dedupeKey>` | TransTypeString |

```ts
// リアクション
const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode('❤️'));
sendSignedEvent(TransTypeString, '❤️', sig, [`react:${dedupeKeyOfTarget}`]);

// リポスト (content は空文字でも署名対象は空文字の UTF-8 バイト列)
const sig2 = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(''));
sendSignedEvent(TransTypeString, '', sig2, [`repost:${dedupeKeyOfTarget}`]);

// リプライ (content は返信本文。署名対象は本文の UTF-8 バイト列)
const sig3 = await CryptoUtils.signMessage(privKey, new TextEncoder().encode('返信本文'));
sendSignedEvent(TransTypeString, '返信本文', sig3, [`reply:${dedupeKeyOfTarget}`]);
```

### 6.1 リプライの表示 (Prrr 側)

- 分類: `splitEvents` で `reply:` タグを持つ TransTypeString を `replies` に振り分ける。
- スレッド化: `replyMap` (`Map<dedupeKey, FodprEvent[]>`) で対象ごとに束ね、
  `TimelineCard`(トップレベルのみ)の直下に `ReplyThread` として表示する。返信の返信は再帰的に表示される(深さ上限 4)。
- 返信カードは「◯◯ への返信」の宛先表示と、リアクション/返信/削除のアクションを持つ。
- 自分のプロフィール画面では、自分の投稿一覧にリプライも含めて表示される。

### 6.2 カスタム絵文字 (NIP-30 相当)

本文内の `:shortcode:` をインライン画像に置き換える、Nostr の NIP-30 と同等の仕組み。

- **記法**: `content` に `:shortcode:` を埋め込む。shortcode は英数字・ハイフン・アンダースコアのみ。
- **タグ**: 使用している shortcode ごとに `emoji:<shortcode>:<url>` タグを付ける(絶対 URL)。
  メディア投稿のキャプションにも同様に付与する。
- **表示**: イベントの `emoji:` タグから shortcode → URL を解決し、`:shortcode:` を `<img>` に
  置き換えて表示する。解決できない shortcode は原文のまま残す(NIP-30 のフォールバック規則)。
- ビルトインパックの画像は `/emoji/*.svg`(Prrr がホスト)。投稿時は
  `window.location.origin` を付けて絶対 URL にする。

```ts
// content: "よろしく :prrr: :fire:"
const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));
sendSignedEvent(TransTypeString, content, sig, [
  `emoji:prrr:${origin}/emoji/prrr.svg`,
  `emoji:fire:${origin}/emoji/fire.svg`,
]);
```

Nostr 側では NIP-30 に従い、kind 1 イベントに `["emoji", shortcode, url]` タグを付けて
同じ `:shortcode:` 記法でやり取りする。

---

## 7. プロフィール画像のアップロード (ストレージ)

プロフィールの `picture` に使う直リンク URL は、同一オリジンのメディアサーバーで発行できる。

```
POST /media/upload        (Content-Type: image/png で画像本体を POST)
→ 200 {"url":"/media/file/<32hex>.png","mime":"image/png","isVideo":false,"isImage":true}

GET  /media/file/<name>   保存済み画像の配信
```

実装は `vite.config.ts` の `mediaPlugin`。上限は画像/その他 12MB・動画 50MB。

```ts
// ブラウザから画像をアップロードして URL を得る例
const res = await fetch('/media/upload', {
  method: 'POST',
  headers: { 'Content-Type': blob.type },
  body: blob,
});
const { url } = await res.json(); // 例: "/media/file/abcd1234....png"
// この url をプロフィール JSON の picture に入れて TransTypeJSON で投稿する
```

---

## 8. 検証手順

1. リレー起動: `docker start fodprrelay`(ポート 8000)
2. dev サーバー起動: `pnpm dev --port 5199`
3. テストスイート実行: `cd /tmp/opencode/pwtest && node <name>.mjs [url]`(playwright)
   - テキスト: `e2e.mjs` / `feed.mjs`
   - メディア: `compress.mjs` / `media.mjs`
   - プロフィール: `profile_img.mjs` / `debug_profile2.mjs`
   - リポスト/引用: `repost_quote.mjs`
   - リプライ: `reply.mjs` / `reply_reload.mjs` / `reply_delete_reply.mjs`
   - リプライ(モバイル+削除): `reply_mobile_delete.mjs`
   - 削除サーバー永続化: `delete_persist.mjs`
4. 本番配信: `pnpm build` → `dist/` を `/var/www/fodpr` へ同期

## 8.1 本番サーバーの起動・停止・デプロイ

- サーバー実行ファイル: `api/server.mjs` (静的配信 + REST API + リレーブリッジ)
- 起動(env はプロジェクト直下 `.env` か環境に設定。過去の起動例)

```sh
export FODPR_STATIC_ROOT=/var/www/fodpr
export FODPR_RELAY_URL=ws://localhost:8000/
export FODPR_MEDIA_DIR=/root/FodprWebClient/media
export FODPR_API_PORT=8088
nohup node /root/FodprWebClient/api/server.mjs > /tmp/fodpr-api.log 2>&1 &

# 停止
pkill -f 'api/server.mjs'   # または: kill $(pgrep -f 'api/server.mjs')
```

- デプロイ(静的ファイル同期)

```sh
pnpm build
# dist/ の内容を静的ルートへ上書き同期
cp -r dist/assets /var/www/fodpr/assets
cp dist/index.html /var/www/fodpr/index.html
cp public/docs.html /var/www/fodpr/docs.html
# APIドキュメントは api/docs.html を直接編集 (サーバーが /api/docs として配信)
```

- 起動確認

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://fodpr.yoinekodo.jp/
curl -s -o /dev/null -w '%{http_code}\n' https://fodpr.yoinekodo.jp/docs.html
curl -s -o /dev/null -w '%{http_code}\n' https://fodpr.yoinekodo.jp/api/docs
curl -s -o /dev/null -w '%{http_code}\n' https://fodpr.yoinekodo.jp/api/health
```

---

## 9. 主要ファイル

| ファイル | 役割 |
|---|---|
| `src/App.tsx` | 投稿/プロフィール/メディアの送信・受信分類・描画 |
| `src/lib/relay.ts` | `RelayClient`(WebSocket 送受信、`sendEvent`/`sendReq`/`sendDel`) |
| `src/hooks/useRelay.ts` | 複数リレー接続管理 |
| `FodprTSSDK/src/protocol.ts` | `Protocol`(ワイヤエンコード/デコード)と型定義 |
| `FodprTSSDK/src/crypto.ts` | `CryptoUtils`(鍵生成・署名・HEX 変換) |
| `vite.config.ts` | `/media/upload` ストレージミドルウェア |
