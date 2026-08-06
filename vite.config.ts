import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import crypto from 'node:crypto';
import { mkdir, writeFile, readFile } from 'node:fs/promises';

// FodprTSSDK の source を再利用できるようにする(別プロジェクトにあるため fs.allow が必要)
const fodprSdkRoot = import.meta.dirname ? path.resolve(import.meta.dirname, '../FodprTSSDK') : path.resolve('../FodprTSSDK');

// ────────────────────────────────────────────────────────────────────────────
// 画像ストレージ
// プロフィール画像の直リンク URL を発行するための小さなアップロードサーバー。
// 開発/プレビューサーバー内のミドルウェアとして動くため、同一オリジンで
// CORS なしに使える(fodpr.yoinekodo.jp は Cloudflare Tunnel でこのサーバーへ
// 直接接続している)。
//   POST /media/upload          … 画像本体を保存して { url: "/media/file/<name>" } を返す
//   GET  /media/file/<name>     … 保存済み画像を配信する
// 保存先: <project>/media/
// ────────────────────────────────────────────────────────────────────────────
const MEDIA_DIR = path.resolve(import.meta.dirname ?? '.', 'media');
const MAX_UPLOAD_BYTES = 12 * 1024 * 1024;
const EXT_BY_MIME: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
  'video/mp4': 'mp4',
  'video/webm': 'webm',
  'video/quicktime': 'mov',
  'video/x-msvideo': 'avi',
  'video/x-matroska': 'mkv',
};

const MIME_BY_EXT: Record<string, string> = {
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  png: 'image/png',
  webp: 'image/webp',
  gif: 'image/gif',
  mp4: 'video/mp4',
  webm: 'video/webm',
  mov: 'video/quicktime',
  avi: 'video/x-msvideo',
  mkv: 'video/x-matroska',
};

const VIDEO_MIMES = new Set([
  'video/mp4',
  'video/webm',
  'video/quicktime',
  'video/x-msvideo',
  'video/x-matroska',
]);

const isVideoMime = (mime: string) => VIDEO_MIMES.has(mime);
const isImageMime = (mime: string) => ['image/jpeg', 'image/png', 'image/webp', 'image/gif'].includes(mime);

async function handleMedia(req: any, res: any, next: () => void): Promise<void> {
  try {
    // アップロード (use('/media') のため req.url は先頭の '/media' が取り除かれた状態)
    if (req.method === 'POST' && req.url === '/upload') {
      const mime = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
      const ext = EXT_BY_MIME[mime];
      if (!ext) {
        res.statusCode = 415;
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.end(JSON.stringify({ error: '対応していないファイル形式です' }));
        return;
      }
      const isVideo = isVideoMime(mime);
      const isImage = isImageMime(mime);
      const maxBytes = isVideo ? 50 * 1024 * 1024 : 12 * 1024 * 1024; // 動画 50MB, 画像/その他 12MB
      const chunks: Buffer[] = [];
      let total = 0;
      for await (const chunk of req) {
        total += chunk.length;
        if (total > maxBytes) {
          res.statusCode = 413;
          res.setHeader('Content-Type', 'application/json; charset=utf-8');
          res.end(JSON.stringify({ error: isVideo ? '動画が大きすぎます (50MBまで)' : 'ファイルが大きすぎます (12MBまで)' }));
          return;
        }
        chunks.push(chunk);
      }
      const name = crypto.randomBytes(16).toString('hex') + '.' + ext;
      await mkdir(MEDIA_DIR, { recursive: true });
      await writeFile(path.join(MEDIA_DIR, name), Buffer.concat(chunks));
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ url: '/media/file/' + name, mime, isVideo, isImage }));
      return;
    }

    // 配信
    const m = /^\/file\/([a-f0-9]{32}\.[a-z0-9]+)$/.exec(req.url ?? '');
    if (req.method === 'GET' && m) {
      const ext = m[1].split('.').pop() ?? '';
      const buf = await readFile(path.join(MEDIA_DIR, m[1]));
      res.statusCode = 200;
      res.setHeader('Content-Type', MIME_BY_EXT[ext] ?? 'application/octet-stream');
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      res.end(buf);
      return;
    }

    next();
  } catch {
    res.statusCode = 404;
    res.end('not found');
  }
}

function mediaPlugin(): Plugin {
  return {
    name: 'fodpr-media',
    configureServer(server) {
      server.middlewares.use('/media', (req, res, next) => {
        void handleMedia(req, res, next);
      });
    },
    configurePreviewServer(server) {
      server.middlewares.use('/media', (req, res, next) => {
        void handleMedia(req, res, next);
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), mediaPlugin()],
  resolve: {
    alias: {
      // SDK の source を @fodpr というエイリアスで参照できるようにする
      '@fodpr': fodprSdkRoot + '/src',
    },
  },
  server: {
    fs: {
      // SDK のディレクトリ以下のファイルをインポートできるように許可
      allow: [fodprSdkRoot],
    },
    allowedHosts: ['fodpr.yoinekodo.jp'],
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
  },
});
