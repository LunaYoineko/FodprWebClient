/**
 * server.mjs
 * ----------
 * Fodpr の REST API サーバー。静的配信(fodpr.yoinekodo.jp 本体)と /api/* を
 * 同一プロセスで提供する(fodpr-server.js の置き換え)。
 *
 *  - 静的配信:   FODPR_STATIC_ROOT(既定 /var/www/fodpr)
 *  - API ドキュメント: GET /api/docs(HTML)
 *  - 画像ストレージ:  POST /media/upload, GET /media/file/<name>(プロフィール画像用)
 *  - REST API (/api/*): 鍵生成 / テキスト投稿 / メディア投稿 / 削除 / イベント取得(購読)
 *
 * リレーとの通信は FodprTSSDK(Protocol / CryptoUtils)を使う。
 *  - 購読(イベント取得)用: 常時接続の REQ(All) を張り、メモリにバッファする
 *  - 投稿・削除用: リクエストごとに一時接続して「OK: ...」/「ERR: ...」応答を待つ
 */

import http from 'node:http';
import path from 'node:path';
import fsp from 'node:fs/promises';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import WebSocket from 'ws';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  Protocol,
  CryptoUtils,
  TransTypeAll,
  TransTypeJSON,
  TransTypeString,
  TransTypeBinary,
  DelTargetEvent,
} from 'fodpr-ts-sdk';

// ────────────────────────────────────────────────────────────────────────────
// 設定
// ────────────────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.FODPR_API_PORT || '8088', 10);
const STATIC_ROOT = process.env.FODPR_STATIC_ROOT || '/var/www/fodpr';
const RELAY_URL = process.env.FODPR_RELAY_URL || 'ws://localhost:8000/';
const MEDIA_DIR = process.env.FODPR_MEDIA_DIR || path.resolve(import.meta.dirname, '..', 'media');
const DOCS_FILE = path.resolve(import.meta.dirname, 'docs.html');

const MAX_MEDIA_BYTES = 12 * 1024 * 1024; // 画像/ファイル(リレー上限16MBに収める)
const MAX_VIDEO_BYTES = 50 * 1024 * 1024; // 動画
const MAX_NOTE_BYTES = 1024 * 1024; // テキスト投稿 1MB
const MAX_BUFFER_EVENTS = 10000; // イベント取得用バッファの上限

const MIME_BY_EXT = {
  jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif',
  mp4: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime', avi: 'video/x-msvideo', mkv: 'video/x-matroska',
};
const EXT_BY_MIME = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif',
  'video/mp4': 'mp4', 'video/webm': 'webm', 'video/quicktime': 'mov', 'video/x-msvideo': 'avi', 'video/x-matroska': 'mkv',
};
const STATIC_TYPE = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.webmanifest': 'application/manifest+json',
  '.txt': 'text/plain; charset=utf-8',
};

// ────────────────────────────────────────────────────────────────────────────
// ヘルパー
// ────────────────────────────────────────────────────────────────────────────
function dedupeKey(e) {
  return `${CryptoUtils.bytesToHex(e.pubkey)}:${e.transType}:${e.createdAt}:${CryptoUtils.bytesToHex(e.signature)}`;
}

function serializeEvent(e) {
  return {
    dedupeKey: dedupeKey(e),
    transType: e.transType,
    createdAt: e.createdAt,
    pubkey: CryptoUtils.bytesToHex(e.pubkey),
    tags: e.tags,
    content: e.content,
    signature: CryptoUtils.bytesToHex(e.signature),
  };
}

function contentHashHex(e) {
  return Buffer.from(sha256(new TextEncoder().encode(e.content))).toString('hex');
}

function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(data);
}

function ok(res, body) { json(res, 200, { ok: true, ...body }); }
function bad(res, status, error) { json(res, status, { ok: false, error }); }

// ────────────────────────────────────────────────────────────────────────────
// リレーとの通信
// ────────────────────────────────────────────────────────────────────────────
let relayConnected = false;

// リクエストごとの一時接続でフレームを送り、最初のテキスト応答(OK/ERR)を返す
function relayRoundTrip(frame) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(RELAY_URL);
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      ws.close();
      reject(new Error('リレーへの応答がタイムアウトしました'));
    }, 15000);
    ws.on('open', () => ws.send(Buffer.from(frame)));
    ws.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.close();
      reject(err);
    });
    ws.on('message', (data, isBinary) => {
      if (settled) return;
      const text = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
      if (isBinary) return;
      settled = true;
      clearTimeout(timer);
      ws.close();
      resolve({ text, ok: text.startsWith('OK:') });
    });
    ws.on('close', () => {
      clearTimeout(timer);
      if (!settled) reject(new Error('リレーへの接続が閉じられました'));
    });
  });
}

// 購読(REQ All)用の常時接続。受信イベントをバッファする
function connectSubscription() {
  const ws = new WebSocket(RELAY_URL);
  ws.on('open', () => {
    relayConnected = true;
    console.log(`[購読] リレーに接続しました: ${RELAY_URL}`);
    const req = Protocol.encodeReq({ subId: 'api_events', transType: TransTypeAll, tagKey: '', tagVal: '' });
    ws.send(Buffer.from(req));
  });
  ws.on('message', (data) => {
    const buf = Array.isArray(data) ? Buffer.concat(data) : Buffer.isBuffer(data) ? data : Buffer.from(data);
    const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    if (bytes.length === 0 || bytes[0] !== 0x81) return;
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    const subIdLen = view.getUint16(1, false);
    const event = Protocol.decodeEvent(bytes.subarray(3 + subIdLen));
    bufferEvent(event);
  });
  ws.on('close', () => {
    relayConnected = false;
    console.log('[購読] リレーから切断。3秒後に再接続します');
    setTimeout(connectSubscription, 3000);
  });
  ws.on('error', () => { /* close で処理される */ });
}

// イベントの重複排除つきバッファ(古いものから破棄)
const eventByKey = new Map();
const eventOrder = [];
let bufferStats = { total: 0 };

function bufferEvent(event) {
  const k = dedupeKey(event);
  if (eventByKey.has(k)) return;
  eventByKey.set(k, event);
  eventOrder.push(k);
  bufferStats.total += 1;
  if (eventOrder.length > MAX_BUFFER_EVENTS) {
    const drop = eventOrder.shift();
    eventByKey.delete(drop);
  }
}

// EVENT パケット(種別バイト 0x01 + 本体)を組み立ててリレーへ送る
async function relayPostEvent(event) {
  const payload = Protocol.encodeEvent(event);
  const frame = new Uint8Array(1 + payload.length);
  frame[0] = 0x01;
  frame.set(payload, 1);
  const r = await relayRoundTrip(frame);
  if (!r.ok) throw new ApiError(400, r.text);
  bufferEvent(event);
  return r.text;
}

// 公開鍵 + createdAt + contentHash を一致させる
function dropFromBuffer(event) {
  const k = dedupeKey(event);
  const idx = eventOrder.indexOf(k);
  if (idx >= 0) {
    eventOrder.splice(idx, 1);
    eventByKey.delete(k);
  }
}

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// ────────────────────────────────────────────────────────────────────────────
// API ハンドラ
// ────────────────────────────────────────────────────────────────────────────
// 秘密鍵の作成
async function apiKeygen(res) {
  const privKey = CryptoUtils.generatePrivateKey();
  ok(res, { privKey, pubkey: CryptoUtils.getPublicKey(privKey) });
}

// テキスト投稿 (TransTypeString)
async function apiNote(body, res) {
  const privKey = body?.privKey;
  const content = body?.content;
  if (!privKey || typeof content !== 'string' || content.length === 0) {
    throw new ApiError(400, 'privKey と content(空でない文字列) が必要です');
  }
  if (Buffer.byteLength(content, 'utf8') > MAX_NOTE_BYTES) {
    throw new ApiError(400, `content は ${MAX_NOTE_BYTES} バイト以内にしてください`);
  }
  const tags = Array.isArray(body.tags) ? body.tags.map(String) : [];
  if (typeof body.quote === 'string' && body.quote) tags.push(`quote:${body.quote}`);

  const event = {
    transType: TransTypeString,
    createdAt: Math.floor(Date.now() / 1000),
    pubkey: CryptoUtils.hexToBytes(CryptoUtils.getPublicKey(privKey)),
    tags,
    content,
    signature: new Uint8Array(),
  };
  event.signature = CryptoUtils.hexToBytes(await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content)));

  const message = await relayPostEvent(event);
  ok(res, { message, event: serializeEvent(event) });
}

// メディア投稿 (TransTypeBinary)。入力は { privKey, mime, data(base64), caption?, filename? }
async function apiMedia(body, res) {
  const privKey = body?.privKey;
  const mime = body?.mime;
  if (!privKey || !mime) throw new ApiError(400, 'privKey と mime が必要です');
  let fileBuffer;
  try {
    fileBuffer = Buffer.from(String(body.data ?? ''), 'base64');
  } catch {
    throw new ApiError(400, 'data(base64) をデコードできません');
  }
  const filename = String(body.filename ?? 'file');
  const isVideo = mime.startsWith('video/');
  const maxBytes = isVideo ? MAX_VIDEO_BYTES : MAX_MEDIA_BYTES;
  if (fileBuffer.length === 0) throw new ApiError(400, 'ファイルが空です');
  if (fileBuffer.length > maxBytes) {
    throw new ApiError(400, `ファイルが大きすぎます (上限 ${Math.round(maxBytes / 1024 / 1024)}MB)`);
  }

  const caption = String(body.caption ?? '');
  const mediaContent = `${mime}:${fileBuffer.toString('base64')}`;
  const mediaType = mime.startsWith('video/') ? 'video' : mime.startsWith('image/') ? 'image' : 'file';

  const event = {
    transType: TransTypeBinary,
    createdAt: Math.floor(Date.now() / 1000),
    pubkey: CryptoUtils.hexToBytes(CryptoUtils.getPublicKey(privKey)),
    tags: [
      `caption:${caption}`,
      `filename:${filename}`,
      `mediatype:${mediaType}`,
    ],
    content: mediaContent,
    signature: new Uint8Array(),
  };
  event.signature = CryptoUtils.hexToBytes(await CryptoUtils.signMessage(privKey, new TextEncoder().encode(mediaContent)));

  const message = await relayPostEvent(event);
  ok(res, { message, event: serializeEvent(event) });
}

// 投稿削除 (DEL, DelTargetEvent)
async function apiDelete(body, res) {
  const privKey = body?.privKey;
  const createdAt = body?.createdAt;
  if (!privKey || typeof createdAt !== 'number') {
    throw new ApiError(400, 'privKey と createdAt(Unix秒) が必要です');
  }
  const contentHashStr = body?.contentHash;
  const contentStr = body?.content;
  if (!contentHashStr && !contentStr) {
    throw new ApiError(400, 'contentHash(64桁HEX) または content が必要です');
  }
  const transType =
    [TransTypeJSON, TransTypeString, TransTypeBinary].includes(body?.transType) ? body.transType : TransTypeAll;

  let contentHashBytes;
  if (contentHashStr) {
    try {
      contentHashBytes = CryptoUtils.hexToBytes(String(contentHashStr));
    } catch {
      throw new ApiError(400, 'contentHash は HEX で指定してください');
    }
    if (contentHashBytes.length !== 32) {
      throw new ApiError(400, 'contentHash は SHA-256 の 32 バイト(64 桁 HEX)にしてください');
    }
  } else {
    contentHashBytes = sha256(new TextEncoder().encode(String(contentStr)));
  }

  const delReq = {
    transType,
    targetType: DelTargetEvent,
    pubkey: CryptoUtils.hexToBytes(CryptoUtils.getPublicKey(privKey)),
    createdAt,
    contentHash: contentHashBytes,
    signature: new Uint8Array(),
  };
  delReq.signature = CryptoUtils.hexToBytes(await CryptoUtils.signMessage(privKey, Protocol.encodeDelSignedData(delReq)));

  const frame = Protocol.encodeDel(delReq);
  const r = await relayRoundTrip(frame);
  if (!r.ok) throw new ApiError(400, r.text);

  const m = /(\d+) event\(s\) deleted/.exec(r.text);
  const deleted = m ? Number(m[1]) : 0;

  // 自バッファからも一致するイベントを除去する
  if (deleted > 0) {
    const pubkeyHex = CryptoUtils.bytesToHex(delReq.pubkey);
    const targetHashHex = Buffer.from(contentHashBytes).toString('hex');
    for (let i = eventOrder.length - 1; i >= 0; i--) {
      const e = eventByKey.get(eventOrder[i]);
      if (
        e &&
        e.createdAt === createdAt &&
        CryptoUtils.bytesToHex(e.pubkey) === pubkeyHex &&
        contentHashHex(e) === targetHashHex
      ) {
        dropFromBuffer(e);
      }
    }
  }
  ok(res, { message: r.text, deleted });
}

// イベント取得(購読バッファからのポーリング)
function apiEvents(query, res) {
  const limit = Math.min(Math.max(parseInt(query.limit || '100', 10) || 100, 1), 1000);
  const since = query.since ? Number(query.since) : undefined;
  const after = typeof query.after === 'string' ? query.after : undefined;
  const transType = query.transType !== undefined ? Number(query.transType) : undefined;
  const tagKey = typeof query.tagKey === 'string' ? query.tagKey : undefined;
  const tagVal = typeof query.tagVal === 'string' ? query.tagVal : undefined;

  const out = [];
  for (let i = eventOrder.length - 1; i >= 0 && out.length < limit; i--) {
    const k = eventOrder[i];
    const e = eventByKey.get(k);
    if (!e) continue;
    if (since !== undefined && e.createdAt <= since) continue;
    if (after !== undefined) {
      if (k === after) break;
    }
    if (transType !== undefined && e.transType !== transType) continue;
    if (tagKey !== undefined) {
      const hit = e.tags.some((t) => t === tagKey || t.startsWith(tagKey + ':'));
      if (!hit) continue;
      if (tagVal !== undefined && !e.tags.some((t) => t === `${tagKey}:${tagVal}`)) continue;
    }
    out.push(serializeEvent(e));
  }
  ok(res, { events: out, count: out.length, relayConnected });
}

function apiHealth(res) {
  ok(res, {
    relayConnected,
    relay: RELAY_URL,
    buffered: eventOrder.length,
    totalEvents: bufferStats.total,
  });
}

// ────────────────────────────────────────────────────────────────────────────
// multipart/form-data パーサ(依存なし)
// ────────────────────────────────────────────────────────────────────────────
function parseMultipart(buf, boundary) {
  const delimiter = Buffer.from(`--${boundary}`);
  const fields = {};
  const files = {};
  let pos = 0;
  const parts = [];
  while (true) {
    const idx = buf.indexOf(delimiter, pos);
    if (idx === -1) break;
    const start = idx + delimiter.length;
    if (buf[start] === 0x2d && buf[start + 1] === 0x2d) break; // 終端 --
    if (buf[start] === 0x0d && buf[start + 1] === 0x0a) {
      const contentStart = start + 2;
      const nextIdx = buf.indexOf(Buffer.from('\r\n--'), contentStart);
      if (nextIdx === -1) break;
      parts.push(buf.subarray(contentStart, nextIdx));
      pos = nextIdx;
    } else break;
  }
  for (const part of parts) {
    const sep = part.indexOf(Buffer.from('\r\n\r\n'));
    if (sep === -1) continue;
    const headerStr = part.subarray(0, sep).toString('utf8');
    const bodyBuf = part.subarray(sep + 4);
    const nameM = /name="([^"]*)"/.exec(headerStr);
    const fnM = /filename="([^"]*)"/.exec(headerStr);
    const ctM = /Content-Type:\s*([^\r\n]+)/i.exec(headerStr);
    const name = nameM ? nameM[1] : '';
    if (fnM) {
      files[name] = {
        filename: fnM[1],
        mime: ctM ? ctM[1].trim() : 'application/octet-stream',
        data: bodyBuf,
      };
    } else if (name) {
      fields[name] = bodyBuf.toString('utf8');
    }
  }
  return { fields, files };
}

// ────────────────────────────────────────────────────────────────────────────
// メディアストレージ(プロフィール画像用, /media/*)
// ────────────────────────────────────────────────────────────────────────────
async function handleMediaUpload(req, res) {
  const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  const ext = EXT_BY_MIME[mime];
  if (!ext) throw new ApiError(415, '対応していないファイル形式です');
  const maxBytes = mime.startsWith('video/') ? MAX_VIDEO_BYTES : MAX_MEDIA_BYTES;
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) throw new ApiError(413, 'ファイルが大きすぎます');
    chunks.push(chunk);
  }
  const name = crypto.randomBytes(16).toString('hex') + '.' + ext;
  await fsp.mkdir(MEDIA_DIR, { recursive: true });
  await fsp.writeFile(path.join(MEDIA_DIR, name), Buffer.concat(chunks));
  ok(res, { url: '/media/file/' + name, mime });
}

async function handleMediaFile(name, res) {
  const m = /^([a-f0-9]{32}\.[a-z0-9]+)$/.exec(name);
  if (!m) throw new ApiError(400, 'invalid name');
  const data = await fsp.readFile(path.join(MEDIA_DIR, m[1]));
  const ext = m[1].split('.').pop() ?? '';
  res.writeHead(200, {
    'Content-Type': MIME_BY_EXT[ext] || 'application/octet-stream',
    'Cache-Control': 'public, max-age=31536000, immutable',
  });
  res.end(data);
}

async function handleDocs(res) {
  const html = await fsp.readFile(DOCS_FILE);
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

// ────────────────────────────────────────────────────────────────────────────
// ボディ読み込み
// ────────────────────────────────────────────────────────────────────────────
function readRawBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.destroy();
        reject(new ApiError(413, 'ボディが大きすぎます'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', () => reject(new ApiError(400, 'リクエスト読み込みに失敗しました')));
  });
}

async function readJsonBody(req, maxBytes) {
  const buf = await readRawBody(req, maxBytes);
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    throw new ApiError(400, 'JSON として解釈できません');
  }
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP サーバー本体
// ────────────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://x');
  const pathname = decodeURIComponent(url.pathname);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  try {
    // ── /media/* : プロフィール画像ストレージ ──
    if (pathname === '/media/upload' && req.method === 'POST') {
      await handleMediaUpload(req, res);
      return;
    }
    if (pathname.startsWith('/media/file/') && req.method === 'GET') {
      await handleMediaFile(pathname.slice('/media/file/'.length), res);
      return;
    }

    // ── /api/* : REST API ──
    if (pathname === '/api/docs' && req.method === 'GET') {
      await handleDocs(res);
      return;
    }
    if (pathname.startsWith('/api/')) {
      const route = pathname.slice('/api/'.length).replace(/\/+$/, '');
      switch (route) {
        case 'health':
          if (req.method !== 'GET') throw new ApiError(405, 'GET のみ対応');
          apiHealth(res);
          return;
        case 'keygen':
          if (req.method !== 'POST') throw new ApiError(405, 'POST のみ対応');
          await apiKeygen(res);
          return;
        case 'note':
          if (req.method !== 'POST') throw new ApiError(405, 'POST のみ対応');
          await apiNote(await readJsonBody(req, MAX_NOTE_BYTES + 1024 * 1024), res);
          return;
        case 'media': {
          if (req.method !== 'POST') throw new ApiError(405, 'POST のみ対応');
          const contentType = String(req.headers['content-type'] || '');
          if (contentType.startsWith('multipart/form-data')) {
            const boundaryM = /boundary="?([^";]+)"?/i.exec(contentType);
            if (!boundaryM) throw new ApiError(400, 'Content-Type に boundary がありません');
            const raw = await readRawBody(req, MAX_VIDEO_BYTES + 1024 * 1024);
            const { fields, files } = parseMultipart(raw, boundaryM[1]);
            const file = files.file || files.media || Object.values(files)[0];
            if (!file) throw new ApiError(400, 'file パートが必要です');
            await apiMedia(
              {
                privKey: fields.privKey,
                caption: fields.caption ?? '',
                filename: fields.filename || file.filename,
                mime: file.mime,
                data: file.data.toString('base64'),
              },
              res,
            );
          } else {
            await apiMedia(await readJsonBody(req, MAX_VIDEO_BYTES + 1024 * 1024), res);
          }
          return;
        }
        case 'delete':
          if (req.method !== 'POST') throw new ApiError(405, 'POST のみ対応');
          await apiDelete(await readJsonBody(req, 1024 * 1024), res);
          return;
        case 'events':
          if (req.method !== 'GET') throw new ApiError(405, 'GET のみ対応');
          apiEvents(Object.fromEntries(url.searchParams), res);
          return;
        default:
          throw new ApiError(404, 'Not Found');
      }
    }

    // ── 静的配信 ──
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Method Not Allowed');
      return;
    }
    const rel = pathname === '/' ? '/index.html' : pathname;
    const filePath = path.resolve(STATIC_ROOT, '.' + rel);
    if (!filePath.startsWith(path.resolve(STATIC_ROOT) + path.sep)) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Forbidden');
      return;
    }
    const data = await fsp.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': STATIC_TYPE[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=31536000',
    });
    res.end(data);
  } catch (e) {
    if (e instanceof ApiError) {
      bad(res, e.status, e.message);
    } else if (e && e.code === 'ENOENT') {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
    } else {
      bad(res, 500, String(e && e.message ? e.message : e));
    }
  }
});

// ────────────────────────────────────────────────────────────────────────────
// 起動
// ────────────────────────────────────────────────────────────────────────────
await fsp.mkdir(MEDIA_DIR, { recursive: true });
connectSubscription();

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Fodpr REST API server listening on http://0.0.0.0:${PORT}`);
  console.log(`  static root: ${STATIC_ROOT}`);
  console.log(`  relay: ${RELAY_URL}`);
  console.log(`  media dir: ${MEDIA_DIR}`);
});
