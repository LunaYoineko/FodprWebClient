import { useEffect, useMemo, useRef, useState } from 'react';
import {
  TransTypeAll,
  TransTypeBinary,
  TransTypeJSON,
  TransTypeString,
  type FodprEvent,
  type FodprReq,
} from '@fodpr/protocol';
import { CryptoUtils } from '@fodpr/crypto';
import '@dpawlikowski/liquid-glass/css';
import { LiquidGlass } from '@dpawlikowski/liquid-glass/react';
import type { RelayMessage } from './lib/relay';
import { fsecToHex, hexToFsec } from './lib/bech32';
import { clearSecret, loadSecret, migrateLegacySecret, saveSecret } from './lib/keystore';
import { useRelay, type RelayStatus } from './hooks/useRelay';

// 既定の接続先リレー(設定画面から追加・削除可能)
const DEFAULT_RELAYS = [
  'wss://fodpr-relay.yoinekodo.jp/'
];
const RELAYS_STORAGE_KEY = 'fodpr_relays';

// 入力された秘密鍵文字列を HEX に正規化する(fsec1... 形式または 64桁HEX)
function normalizeSecretKey(input: string): string {
  const s = input.trim();
  if (!s) throw new Error('秘密鍵を入力してください');
  if (s.toLowerCase().startsWith('fsec')) return fsecToHex(s);
  if (!/^[0-9a-fA-F]{64}$/.test(s)) throw new Error('fsec 形式または 64桁の HEX で入力してください');
  return s.toLowerCase();
}

// リレー一覧を localStorage から読み込む(不正な値は既定値へフォールバック)
function loadRelays(): string[] {
  const raw = localStorage.getItem(RELAYS_STORAGE_KEY);
  if (raw) {
    try {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) {
        const urls = arr.filter((x): x is string => typeof x === 'string' && /^wss?:\/\//.test(x));
        if (urls.length > 0) return urls;
      }
    } catch {
      /* 壊れていれば既定値へ */
    }
  }
  return [...DEFAULT_RELAYS];
}

// pubkey hex をキーにしてイベントを一意化する(サーバー再送信・自投稿の重複を避ける)
// 署名まで含めることで「同一秒に複数投稿」しても重複して弾かない。
function dedupeKey(e: FodprEvent): string {
  const pk = CryptoUtils.bytesToHex(e.pubkey);
  const sig = CryptoUtils.bytesToHex(e.signature);
  return `${pk}:${e.transType}:${e.createdAt}:${sig}`;
}

function splitEvents(events: FodprEvent[]) {
  const out = {
    profiles: [] as FodprEvent[],
    notes: [] as FodprEvent[],
    binaries: [] as FodprEvent[],
    reactions: [] as FodprEvent[],
    links: [] as FodprEvent[],
    others: [] as FodprEvent[],
  };
  for (const e of events) {
    if (e.transType === TransTypeJSON) {
      try {
        const obj = JSON.parse(e.content);
        if (obj?.mode === 'profile') {
          out.profiles.push(e);
          continue;
        }
      } catch {
        /* JSON 解析失敗は others へ */
      }
      out.others.push(e);
    } else if (e.transType === TransTypeString) {
      // リアクション: content=絵文字、tags に react:<対象イベントの dedupeKey>
      if (e.tags.some((t) => t.startsWith('react:'))) {
        out.reactions.push(e);
      } else if (e.tags.some((t) => t.startsWith('repost:')) || e.tags.some((t) => t.startsWith('quote:'))) {
        // リポスト/引用リポスト: tags に repost:<key> / quote:<key>
        out.links.push(e);
      } else {
        out.notes.push(e);
      }
    } else if (e.transType === TransTypeBinary) {
      out.binaries.push(e);
    } else {
      out.others.push(e);
    }
  }
  return out;
}

// 公開鍵 -> 最新のプロフィール(event.createdAt が最大のもの)を返す
function latestProfilePerPubkey(profiles: FodprEvent[]): Record<string, FodprEvent> {
  const map: Record<string, FodprEvent> = {};
  for (const e of profiles) {
    const key = CryptoUtils.bytesToHex(e.pubkey);
    const prev = map[key];
    if (!prev || e.createdAt > prev.createdAt) {
      map[key] = e;
    }
  }
  return map;
}

// プロフィールイベントの content をパースする(失敗時は空オブジェクト)
function parseProfile(content: string): { name?: string; about?: string; picture?: string } {
  try {
    const obj = JSON.parse(content);
    if (obj && typeof obj === 'object' && obj.mode === 'profile') {
      return {
        name: typeof obj.name === 'string' ? obj.name : undefined,
        about: typeof obj.about === 'string' ? obj.about : undefined,
        picture: typeof obj.picture === 'string' ? obj.picture : undefined,
      };
    }
  } catch {
    /* no-op */
  }
  return {};
}

// プロフィールイベントから名前を取り出す(失敗時は null)
function profileName(e: FodprEvent | undefined): string | null {
  if (!e) return null;
  return parseProfile(e.content).name ?? null;
}

// プロフィールイベントからアイコン画像 URL(直リンク)を取り出す(失敗時は null)
function profilePicture(e: FodprEvent | undefined): string | null {
  if (!e) return null;
  return parseProfile(e.content).picture ?? null;
}

// 画像投稿(Binary)の content 形式: img:<mime>;base64,<data>
const IMAGE_CONTENT_RE = /^img:([^;]+);base64,(.+)$/s;

function parseImageContent(content: string): { mime: string; base64: string } | null {
  const m = IMAGE_CONTENT_RE.exec(content);
  return m ? { mime: m[1], base64: m[2] } : null;
}

// 画像イベントのタグ(caption:...)から説明文を取り出す
function captionFromTags(tags: string[]): string | null {
  for (const t of tags) {
    if (t.startsWith('caption:')) return t.slice('caption:'.length);
  }
  return null;
}

// リアクションイベントのタグ(react:<対象の dedupeKey>)から対象イベントのキーを取り出す
function reactionTarget(e: FodprEvent): string | null {
  for (const t of e.tags) {
    if (t.startsWith('react:')) return t.slice('react:'.length);
  }
  return null;
}

// リポスト/引用イベントのタグ(repost:<key> / quote:<key>)から対象イベントのキーを取り出す
function repostTarget(e: FodprEvent): string | null {
  for (const t of e.tags) {
    if (t.startsWith('repost:')) return t.slice('repost:'.length);
  }
  return null;
}

function quoteTarget(e: FodprEvent): string | null {
  for (const t of e.tags) {
    if (t.startsWith('quote:')) return t.slice('quote:'.length);
  }
  return null;
}

// イベント本文の短い抜粋(引用プレビュー用)
function eventSnippet(e: FodprEvent | undefined): string {
  if (!e) return '';
  if (e.transType === TransTypeBinary) {
    return parseImageContent(e.content) ? '画像' : '[バイナリ]';
  }
  const s = e.content.trim();
  return s.length > 80 ? s.slice(0, 80) + '…' : s;
}

// ある投稿に付いたリアクション一覧を「絵文字ごとの集計」にまとめる
function aggregateReactions(list: ReactionItem[] | undefined, selfPubkeyHex: string) {
  const m = new Map<string, { count: number; self: boolean }>();
  for (const r of list ?? []) {
    const cur = m.get(r.emoji) ?? { count: 0, self: false };
    cur.count += 1;
    if (r.pubkey === selfPubkeyHex) cur.self = true;
    m.set(r.emoji, cur);
  }
  return [...m.entries()].map(([emoji, v]) => ({ emoji, ...v }));
}

type ReactionItem = { emoji: string; pubkey: string };
type ReactionMap = Map<string, ReactionItem[]>;

// 投稿(テキスト/画像)を最新順(createdAt 降順)に並べる。同時刻は署名で安定ソート。
function sortPostsDesc(posts: FodprEvent[]): FodprEvent[] {
  return [...posts].sort((a, b) => {
    if (b.createdAt !== a.createdAt) return b.createdAt - a.createdAt;
    return CryptoUtils.bytesToHex(b.signature) > CryptoUtils.bytesToHex(a.signature) ? 1 : -1;
  });
}

// pubkey(HEX)から表示名を引く: プロフィールの名前を優先、なければ先頭7桁
function resolveDisplayName(pubkeyHex: string, profileMap: Record<string, FodprEvent>): string {
  return profileName(profileMap[pubkeyHex]) ?? pubkeyHex.slice(0, 7);
}

// ビューポート幅が sm(640px)以上かどうかを監視するフック(モバイル/デスクトップの出し分け用)
function useIsSm() {
  const [isSm, setIsSm] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 640px)').matches,
  );
  useEffect(() => {
    const mq = window.matchMedia('(min-width: 640px)');
    const onChange = () => setIsSm(mq.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  return isSm;
}

// ペン(鉛筆)アイコン。モバイルの投稿 FAB に使う
function PenIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z" />
    </svg>
  );
}

const NAV_ITEMS = [
  { id: 'timeline', label: 'タイムライン' },
  { id: 'profile', label: 'プロフィール' },
  { id: 'settings', label: '設定' },
] as const;

type ViewId = (typeof NAV_ITEMS)[number]['id'];

// プロフィール画像(直リンク URL)を表示するアバター。URL が無い/読み込めない場合は
// 名前の頭文字でフォールバックする。
function Avatar({
  picture,
  pubkeyHex,
  name,
  className,
}: {
  picture: string | null;
  pubkeyHex: string;
  name: string;
  className?: string;
}) {
  const [failed, setFailed] = useState(false);
  const base = 'shrink-0 overflow-hidden rounded-full bg-surface-2 ' + (className ?? 'h-10 w-10');
  if (picture && !failed) {
    return (
      <img
        src={picture}
        alt=""
        loading="lazy"
        referrerPolicy="no-referrer"
        onError={() => setFailed(true)}
        className={base + ' object-cover'}
      />
    );
  }
  const ch = (name && name.trim() ? name.trim()[0] : pubkeyHex[0] ?? '?').toUpperCase();
  return <div className={base + ' flex items-center justify-center font-semibold text-primary'}>{ch}</div>;
}

// 画像のリサイズ上限(この辺までに縮小してから投稿する)
const MAX_IMAGE_DIMENSION = 1600;
const JPEG_QUALITY = 0.85;

// 動画からサムネイル(先頭フレーム)を抽出し、圧縮して data URL を返す
async function extractVideoThumbnail(file: File, _maxDim = 480): Promise<{ dataUrl: string; size: number }> {
  return new Promise((resolve, reject) => {
    const video = document.createElement('video');
    video.preload = 'metadata';
    video.muted = true;
    video.onloadedmetadata = () => {
      const scale = Math.min(1, 480 / Math.max(video.videoWidth, video.videoHeight));
      const w = Math.max(1, Math.round(video.videoWidth * scale));
      const h = Math.max(1, Math.round(video.videoHeight * scale));
      const canvas = document.createElement('canvas');
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        reject(new Error('canvas が利用できません'));
        return;
      }
      video.currentTime = 0;
      video.onseeked = () => {
        ctx.drawImage(video, 0, 0, w, h);
        const dataUrl = canvas.toDataURL('image/jpeg', 0.8);
        const size = Math.round(dataUrl.length * 0.75);
        resolve({ dataUrl, size });
      };
      video.currentTime = 0.1; // 少し進めて確実にフレームを取得
    };
    video.onerror = () => reject(new Error('動画の読み込みに失敗しました'));
    video.src = URL.createObjectURL(file);
  });
}

// 動画ファイルをクライアント側で圧縮(解像度制限 + 再エンコード)
// WebCodecs が使える環境では VideoEncoder を使うが、フォールバックとしてそのまま送信も可能
async function compressVideoFile(file: File, _maxDim = 720, _maxBitrate = 2_000_000): Promise<{ dataUrl: string; size: number }> {
  // 現状はサムネイルのみ生成し、動画本体はそのまま送信(サイズ制限内なら)
  // 将来的に WebCodecs VideoEncoder で再エンコード可能
  // 動画本体を data URL 化 (大きいため base64 化は注意)
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = reader.result as string;
      resolve({ dataUrl, size: file.size });
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// ファイル種別判定
function isVideoFile(file: File): boolean {
  return file.type.startsWith('video/');
}

function isImageFile(file: File): boolean {
  return file.type.startsWith('image/');
}

// バイト数を表示用に整形する
function formatBytes(n: number): string {
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  if (n >= 1024) return Math.round(n / 1024) + ' KB';
  return n + ' B';
}

// 画像をクライアント側で圧縮(リサイズ + 再エンコード)して data URL を返す。
// 写真(JPEG等)は JPEG に再エンコードしてサイズを落とす。
// 透過を想定する PNG/GIF/WebP は alpha を保つため PNG のまま再エンコードする。
async function compressImageFile(file: File): Promise<{ dataUrl: string; size: number }> {
  const bitmap = await createImageBitmap(file);
  try {
    const scale = Math.min(1, MAX_IMAGE_DIMENSION / Math.max(bitmap.width, bitmap.height));
    const w = Math.max(1, Math.round(bitmap.width * scale));
    const h = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('canvas が利用できません');
    ctx.drawImage(bitmap, 0, 0, w, h);
    const keepAlpha = file.type === 'image/png' || file.type === 'image/gif' || file.type === 'image/webp';
    const dataUrl = keepAlpha ? canvas.toDataURL('image/png') : canvas.toDataURL('image/jpeg', JPEG_QUALITY);
    // base64 の文字数 × 3/4 ≒ デコード後のバイト数
    const size = Math.round(dataUrl.length * 0.75);
    return { dataUrl, size };
  } finally {
    bitmap.close();
  }
}

function App() {
  // 秘密鍵はメモリ上のみに保持(localStorage には暗号化して保存)
  const [privKey, setPrivKey] = useState<string | null>(null);
  const [ready, setReady] = useState(false); // 復号ロード完了フラグ

  const pubkeyHex = useMemo(() => (privKey ? CryptoUtils.getPublicKey(privKey) : ''), [privKey]);
  const pubkeyBytes = useMemo(() => (pubkeyHex ? CryptoUtils.hexToBytes(pubkeyHex) : new Uint8Array()), [pubkeyHex]);

  // 表示ビュー: タイムライン / プロフィール / 設定
  const [view, setView] = useState<ViewId>('timeline');

  // TL 上のユーザー名/アイコンをクリックしたときに開く「他ユーザーのプロフィール」
  const [openPubkey, setOpenPubkey] = useState<string | null>(null);

  // 投稿欄(下部コンポーザ)の表示/非表示。設定は localStorage に保存する
  const [composerHidden, setComposerHidden] = useState<boolean>(
    () => localStorage.getItem('fodpr_composer_hidden') === '1',
  );

  // モバイル用の中大モーダル投稿欄(既定は非表示)
  const [mobileComposerOpen, setMobileComposerOpen] = useState(false);
  const isSm = useIsSm();

  // クライアント実装ドキュメントページの表示/非表示(設定 -> 開く)
  const [showDocs, setShowDocs] = useState(false);

  function toggleComposer() {
    if (isSm) {
      setComposerHidden((prev) => {
        const next = !prev;
        localStorage.setItem('fodpr_composer_hidden', next ? '1' : '0');
        return next;
      });
    } else {
      setMobileComposerOpen((o) => !o);
    }
  }

  // 接続先リレー(複数・設定画面から変更可能)
  const [relayUrls, setRelayUrls] = useState<string[]>(loadRelays);
  const relayUrlsKey = relayUrls.join('\n');
  const relay = useRelay(relayUrls);

  // コンポーザ入力
  const [noteText, setNoteText] = useState('');
  const [name, setName] = useState('');
  const [about, setAbout] = useState('');
  const [picture, setPicture] = useState('');

  // 引用リポスト中の対象イベントの dedupeKey(非 null ならコンポーザが引用モード)
  const [quoteTarget, setQuoteTarget] = useState<string | null>(null);

  // 画像/動画/ファイル投稿(Binary)用の添付状態
  const [mediaDataUrl, setMediaDataUrl] = useState<string | null>(null);
  const [mediaName, setMediaName] = useState<string | null>(null);
  const [mediaSize, setMediaSize] = useState(0);
  const [mediaError, setMediaError] = useState<string | null>(null);
  const [mediaType, setMediaType] = useState<'image' | 'video' | 'file' | null>(null);
  const [mediaThumbnail, setMediaThumbnail] = useState<string | null>(null);

  // 自クライアントの投稿を即座にフィードに反映するためのローカル蓄積(Optimistic)
  const [localEvents, setLocalEvents] = useState<FodprEvent[]>([]);

  // 起動時: 暗号化された秘密鍵を復号して自動ログインする(旧平文保存からの移行も行う)
  useEffect(() => {
    let cancelled = false;
    (async () => {
      let hex: string | null = null;
      try {
        hex = await migrateLegacySecret();
        if (!hex) hex = await loadSecret();
      } catch {
        hex = null;
      }
      if (cancelled) return;
      if (hex && /^[0-9a-f]{64}$/i.test(hex)) {
        try {
          CryptoUtils.getPublicKey(hex); // 不正な鍵はログインしない
          setPrivKey(hex);
        } catch {
          setPrivKey(null);
        }
      }
      setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // 受信 PUSH イベント(各リレーから)を型付きで取り出す
  const receivedEvents = useMemo(
    () =>
      relay.messages.filter(
        (m): m is Extract<RelayMessage, { kind: 'event' }> => m.kind === 'event',
      ).map((m) => m.event),
    [relay.messages],
  );

  // サーバー受信 + 自投稿をマージ(重複排除)してフィードのソースにする
  const allEvents = useMemo(() => {
    const seen = new Set<string>();
    const merged: FodprEvent[] = [];
    for (const e of receivedEvents) {
      const k = dedupeKey(e);
      if (!seen.has(k)) {
        seen.add(k);
        merged.push(e);
      }
    }
    for (const e of localEvents) {
      const k = dedupeKey(e);
      if (!seen.has(k)) {
        seen.add(k);
        merged.push(e);
      }
    }
    return merged;
  }, [receivedEvents, localEvents]);

  const { profiles, notes, binaries, reactions, links, others } = useMemo(() => splitEvents(allEvents), [allEvents]);
  const profileMap = useMemo(() => latestProfilePerPubkey(profiles), [profiles]);

  // dedupeKey -> イベント の解決マップ(リポスト/引用の対象を引くために使う)
  const eventByKey = useMemo(() => {
    const m = new Map<string, FodprEvent>();
    for (const e of allEvents) m.set(dedupeKey(e), e);
    return m;
  }, [allEvents]);

  // リアクションを対象イベントの dedupeKey ごとにまとめる
  const reactionMap: ReactionMap = useMemo(() => {
    const m: ReactionMap = new Map();
    for (const e of reactions) {
      const key = reactionTarget(e);
      if (!key || !e.content.trim()) continue;
      const list = m.get(key) ?? [];
      list.push({ emoji: e.content, pubkey: CryptoUtils.bytesToHex(e.pubkey) });
      m.set(key, list);
    }
    return m;
  }, [reactions]);

  // 接続確立後に一度 REQ(All) して保存済みイベントを取得する(再接続・リレー変更時にも再送)
  useEffect(() => {
    let done = false;
    if (!relay.connected) return;
    const req: FodprReq = { subId: 'sub_web_' + Date.now(), transType: TransTypeAll, tagKey: '', tagVal: '' };
    const t = setTimeout(() => {
      if (done) return;
      try {
        relay.sendReq(req);
      } catch {
        /* 未接続中は無視 */
      }
    }, 300);
    return () => {
      done = true;
      clearTimeout(t);
    };
  }, [relayUrlsKey, relay.connected, relay.sendReq]);

  // 署名済みイベントを全リレーへ送信する
  function sendSignedEvent(transType: number, content: string, signatureHex: string, tags: string[] = []) {
    const event: FodprEvent = {
      transType,
      createdAt: Math.floor(Date.now() / 1000),
      pubkey: pubkeyBytes,
      tags,
      content,
      signature: CryptoUtils.hexToBytes(signatureHex),
    };
    // Optimistic: 自フィードに即反映
    setLocalEvents((prev) => [event, ...prev]);
    relay.sendEvent(event);
  }

  // ファイル(画像/動画/ファイル)を選択して圧縮/処理し、data URL として保持する
  async function onPickFile(file: File | undefined) {
    setMediaError(null);
    if (!file) return;

    if (isVideoFile(file)) {
      // 動画: サムネイル抽出 + 動画本体の data URL 化
      if (file.size > 50 * 1024 * 1024) {
        setMediaError('動画は 50MB 以下にしてください');
        return;
      }
      try {
        const thumb = await extractVideoThumbnail(file);
        const media = await compressVideoFile(file);
        setMediaDataUrl(media.dataUrl);
        setMediaThumbnail(thumb.dataUrl);
        setMediaSize(file.size);
        setMediaName(file.name);
        setMediaType('video');
      } catch {
        setMediaError('動画を処理できませんでした');
      }
      return;
    }

    if (isImageFile(file)) {
      // 画像: 圧縮
      if (file.size > 12 * 1024 * 1024) {
        setMediaError('画像は 12MB 以下にしてください');
        return;
      }
      try {
        const { dataUrl, size } = await compressImageFile(file);
        setMediaDataUrl(dataUrl);
        setMediaSize(size);
        setMediaName(file.name);
        setMediaType('image');
        setMediaThumbnail(null);
      } catch {
        setMediaError('画像を読み込めませんでした');
      }
      return;
    }

    // その他のファイル: そのまま送信 (圧縮なし)
    if (file.size > 12 * 1024 * 1024) {
      setMediaError('ファイルは 12MB 以下にしてください');
      return;
    }
    try {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result as string);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
      setMediaDataUrl(dataUrl);
      setMediaSize(file.size);
      setMediaName(file.name);
      setMediaType('file');
      setMediaThumbnail(null);
    } catch {
      setMediaError('ファイルを読み込めませんでした');
    }
  }

  // 添付ファイル(画像/動画/ファイル)プレビューと関連状態をクリアする(Composer の「解除」ボタン用)
  function clearMedia() {
    setMediaDataUrl(null);
    setMediaName(null);
    setMediaSize(0);
    setMediaError(null);
    setMediaType(null);
    setMediaThumbnail(null);
  }

  // 投稿するハンドラ: テキストのみ=String、画像あり=Binary、引用モード時は quote タグ付きで送る
  const postNote = async () => {
    if (!privKey) return;
    const content = noteText.trim();

    // 引用リポスト: 自分のコメント + quote:<対象> タグの TransTypeString
    if (quoteTarget) {
      if (!content) return;
      const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));
      sendSignedEvent(TransTypeString, content, sig, [`quote:${quoteTarget}`]);
      setNoteText('');
      setQuoteTarget(null);
      // 投稿後は入力欄を閉じる
      setMobileComposerOpen(false);
      if (isSm) {
        setMobileComposerOpen(false);
      } else {
        setComposerHidden(true);
        localStorage.setItem('fodpr_composer_hidden', '1');
      }
      return;
    }

    if (mediaDataUrl) {
      // 画像/動画/ファイル投稿: TransTypeBinary で base64 を送る
      // content = メタデータ(メディアタイプ、ファイル名、キャプション等)
      const dm = /^data:([^;]+);base64,(.+)$/s.exec(mediaDataUrl);
      if (!dm) return;
      const mime = dm[1];
      const base64 = dm[2];
      const caption = content || mediaName || '';
      const mediaContent = `${mime}:${base64}`;
      const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(mediaContent));
      const tags = [
        `caption:${caption}`,
        `filename:${mediaName}`,
        `mediatype:${mediaType}`,
      ];
      sendSignedEvent(TransTypeBinary, mediaContent, sig, tags);
      setNoteText('');
      setMediaDataUrl(null);
      setMediaName(null);
      setMediaSize(0);
      setMediaType(null);
      setMediaThumbnail(null);
      // 投稿後は入力欄を閉じる
      if (isSm) {
        setMobileComposerOpen(false);
      } else {
        setComposerHidden(true);
        localStorage.setItem('fodpr_composer_hidden', '1');
      }
      return;
    }

    if (!content) return;
    const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));
    sendSignedEvent(TransTypeString, content, sig);
    setNoteText('');
    // 投稿後は入力欄を閉じる
    if (isSm) {
      setMobileComposerOpen(false);
    } else {
      setComposerHidden(true);
      localStorage.setItem('fodpr_composer_hidden', '1');
    }
  };

  // 対象イベントへリアクション(絵文字)を投稿する。
  // content=リアクション、tags=[react:<対象の dedupeKey>] の TransTypeString として送る。
  async function handleReact(targetKey: string, emoji: string) {
    if (!privKey || !relay.connected) return;
    const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(emoji));
    sendSignedEvent(TransTypeString, emoji, sig, [`react:${targetKey}`]);
  }

  // リポスト: content=空、tags=[repost:<対象の dedupeKey>] の TransTypeString として送る
  async function handleRepost(targetKey: string) {
    if (!privKey || !relay.connected) return;
    const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(''));
    sendSignedEvent(TransTypeString, '', sig, [`repost:${targetKey}`]);
  }

  // 引用リポスト開始: タイムラインへ戻ってコンポーザを引用モードにする
  function startQuote(targetKey: string) {
    setView('timeline');
    setOpenPubkey(null);
    if (isSm) {
      if (composerHidden) {
        setComposerHidden(false);
        localStorage.setItem('fodpr_composer_hidden', '0');
      }
    } else {
      setMobileComposerOpen(true);
    }
    setQuoteTarget(targetKey);
  }

  // プロフィール(JSON mode: profile)を投稿するハンドラ
  const postProfile = async () => {
    if (!name) return;
    if (!privKey) return;
    const profile = { mode: 'profile', name, about: about || undefined, picture: picture.trim() || undefined };
    const content = JSON.stringify(profile);
    const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));
    sendSignedEvent(TransTypeJSON, content, sig);
    setAbout('');
  };

  // fsec(または HEX)でログインし、暗号化して保存する
  async function handleLogin(input: string) {
    const hex = normalizeSecretKey(input);
    CryptoUtils.getPublicKey(hex); // 不正な鍵はここでエラーになる
    await saveSecret(hex);
    setPrivKey(hex);
  }

  // 新しい鍵を生成してログイン
  async function handleGenerate() {
    const hex = CryptoUtils.generatePrivateKey();
    await saveSecret(hex);
    setPrivKey(hex);
  }

  // ログアウト(localStorage / IndexedDB の鍵を破棄してログイン画面へ戻る)
  function handleLogout() {
    void clearSecret();
    setPrivKey(null);
    setView('timeline');
    setOpenPubkey(null);
    setQuoteTarget(null);
    setLocalEvents([]);
  }

  // リレー一覧を更新して保存する
  function updateRelays(urls: string[]) {
    setRelayUrls(urls);
    localStorage.setItem(RELAYS_STORAGE_KEY, JSON.stringify(urls));
  }

  // 復号ロード中はローディング画面
  if (!ready) {
    return (
      <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-bg text-gray-400">
        <div className="aurora" aria-hidden="true" />
        <p className="relative z-10 text-sm">読み込み中...</p>
      </div>
    );
  }

  // 未ログインならログイン画面を表示
  if (!privKey) {
    return <LoginScreen onLogin={handleLogin} onGenerate={handleGenerate} />;
  }

  const selfName = resolveDisplayName(pubkeyHex, profileMap);

  // 引用モード中は引用対象イベントとその投稿者名を解決してプレビューに使う
  const quoteEvent = quoteTarget ? eventByKey.get(quoteTarget) : undefined;
  const quoteName = quoteEvent
    ? resolveDisplayName(CryptoUtils.bytesToHex(quoteEvent.pubkey), profileMap)
    : undefined;
  // 投稿欄の表示状態(デスクトップ=下部固定、モバイル=中央モーダル)
  const composerVisible = isSm ? !composerHidden : mobileComposerOpen;

  return (
    <div className="relative h-svh h-[100dvh] overflow-hidden bg-bg text-gray-100">
      <div className="aurora" aria-hidden="true" />

      <div className="relative z-10 flex h-full flex-col pt-[env(safe-area-inset-top)] pb-[env(safe-area-inset-bottom)]">
        {/* ヘッダー */}
        <header className="flex flex-wrap items-center justify-center gap-2 px-3 py-2.5 sm:gap-3 sm:px-4 sm:py-3">
          <h1 className="mr-auto shrink-0 text-2xl font-bold tracking-tight text-white/90">Fodpr</h1>

          {/* ナビメニュー: タイムライン / プロフィール / 設定 */}
          <LiquidGlass intensity="subtle" refractive className="liquid-glass--nav">
            <nav className="flex items-center gap-1 px-1.5 py-1.5">
              {NAV_ITEMS.map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    setView(item.id);
                    setOpenPubkey(null);
                    setQuoteTarget(null);
                  }}
                  className={
                    'rounded-full px-3.5 py-1.5 text-sm transition-colors ' +
                    (view === item.id ? 'bg-white/15 text-white' : 'text-gray-300 hover:bg-white/10')
                  }
                >
                  {item.label}
                </button>
              ))}
            </nav>
          </LiquidGlass>

{/* アカウント: 接続状態 + 投稿欄の開閉(ログアウトは設定画面) */}
           <div className="flex shrink-0 items-center gap-2 text-sm">
             {isSm && (
               <button
                 onClick={toggleComposer}
                 aria-label={composerVisible ? '書き込み欄を隠す' : '書き込み欄を表示'}
                 title={composerVisible ? '書き込み欄を隠す' : '書き込み欄を表示'}
                 className={
                   'shrink-0 rounded-full border px-2.5 py-2 transition-colors ' +
                   (composerVisible
                     ? 'border-white/15 text-gray-300 hover:bg-white/10'
                     : 'border-primary/50 bg-primary/10 text-white')
                 }
               >
                 <svg
                   viewBox="0 0 24 24"
                   className="h-4 w-4"
                   fill="none"
                   stroke="currentColor"
                   strokeWidth="2"
                   strokeLinecap="round"
                   strokeLinejoin="round"
                   aria-hidden="true"
                 >
                   <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z" />
                   {!composerVisible && <path d="M3 3l18 18" />}
                 </svg>
               </button>
             )}
            <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--nav">
              <div className="flex items-center gap-2 px-3.5 py-1.5">
                <Avatar
                  picture={profilePicture(profileMap[pubkeyHex])}
                  pubkeyHex={pubkeyHex}
                  name={selfName}
                  className="h-6 w-6 text-xs"
                />
                <span className={'h-2 w-2 rounded-full ' + (relay.connected ? 'bg-green-400' : 'bg-red-400')} />
                <span className="hidden font-medium text-white sm:inline">{selfName}</span>
              </div>
            </LiquidGlass>
          </div>
        </header>

        {/* ビュー */}
        <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto px-4 pb-4">
          {openPubkey && (
            <UserProfileView
              pubkeyHex={openPubkey}
              profileMap={profileMap}
              notes={notes}
              binaries={binaries}
              links={links}
              eventByKey={eventByKey}
              reactions={reactionMap}
              selfPubkeyHex={pubkeyHex}
              onBack={() => setOpenPubkey(null)}
              onOpenUser={setOpenPubkey}
              onReact={handleReact}
              onRepost={handleRepost}
              onQuote={startQuote}
            />
          )}
          {!openPubkey && view === 'timeline' && (
            <Timeline
              notes={notes}
              binaries={binaries}
              links={links}
              others={others}
              eventByKey={eventByKey}
              profileMap={profileMap}
              reactions={reactionMap}
              selfPubkeyHex={pubkeyHex}
              onOpenUser={setOpenPubkey}
              onReact={handleReact}
              onRepost={handleRepost}
              onQuote={startQuote}
            />
          )}
          {view === 'profile' && (
            <ProfileView
              pubkeyHex={pubkeyHex}
              selfName={selfName}
              picture={picture}
              name={name}
              about={about}
              onPictureChange={setPicture}
              onNameChange={setName}
              onAboutChange={setAbout}
              onSave={postProfile}
              relayConnected={relay.connected}
            />
          )}
          {view === 'settings' && (
            <SettingsView
              relayUrls={relayUrls}
              onRelayChange={updateRelays}
              relayStatus={relay.relayStatus}
              relayConnected={relay.connected}
              onLogout={handleLogout}
              onShowDocs={() => setShowDocs(true)}
              secretHex={privKey}
            />
          )}
        </main>

        {/* デスクトップ: 画面下部のテキスト投稿欄(タイムラインのみ・他ユーザーのプロフィール表示中/非表示設定時は非表示) */}
        {isSm && view === 'timeline' && !openPubkey && !composerHidden && (
          <footer className="px-3 sm:px-4">
            <LiquidGlass intensity="subtle" refractive className="liquid-glass--card w-full">
              <Composer
                noteText={noteText}
                setNoteText={setNoteText}
                mediaDataUrl={mediaDataUrl}
                mediaName={mediaName}
                mediaSize={mediaSize}
                mediaError={mediaError}
                clearMedia={clearMedia}
                quoteTarget={quoteTarget}
                quoteEvent={quoteEvent}
                quoteName={quoteName}
                onCancelQuote={() => setQuoteTarget(null)}
                onPickFile={onPickFile}
                onSubmit={postNote}
                relayConnected={relay.connected}
                mediaType={mediaType}
                mediaThumbnail={mediaThumbnail}
              />
            </LiquidGlass>
          </footer>
        )}

        {/* モバイル: 投稿欄は既定で非表示。右下のペン(FAB)で中央モーダルを開く */}
        {!isSm && view === 'timeline' && !openPubkey && (
          <>
            {!mobileComposerOpen && (
              <button
                onClick={() => setMobileComposerOpen(true)}
                aria-label="投稿欄を開く"
                title="投稿欄を開く"
                style={{ right: '0.5rem', bottom: 'max(env(safe-area-inset-bottom),0.5rem)' }}
                className="fixed z-30 flex h-12 w-12 items-center justify-center rounded-full border border-white/15 bg-primary text-bg shadow-lg transition-colors hover:bg-primary-hover"
              >
                <PenIcon className="h-6 w-6" />
              </button>
            )}
            {mobileComposerOpen && (
              <div
                className="fixed inset-0 z-40 flex items-center justify-center bg-bg/95 backdrop-blur-sm p-4"
                onClick={() => setMobileComposerOpen(false)}
              >
                <div className="w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
                  <LiquidGlass intensity="subtle" refractive className="liquid-glass--card w-full">
                    <div className="flex justify-end p-2 pb-0">
                      <button
                        onClick={() => setMobileComposerOpen(false)}
                        aria-label="閉じる"
                        title="閉じる"
                        className="rounded-full border border-white/15 px-3 py-1.5 text-sm text-gray-300 transition-colors hover:bg-white/10"
                      >
                        閉じる
                      </button>
                    </div>
                    <Composer
                      noteText={noteText}
                      setNoteText={setNoteText}
                      mediaDataUrl={mediaDataUrl}
                      mediaName={mediaName}
                      mediaSize={mediaSize}
                      mediaError={mediaError}
                      clearMedia={clearMedia}
                      quoteTarget={quoteTarget}
                      quoteEvent={quoteEvent}
                      quoteName={quoteName}
                      onCancelQuote={() => setQuoteTarget(null)}
                      onPickFile={onPickFile}
                      onSubmit={postNote}
                      relayConnected={relay.connected}
                      mediaType={mediaType}
                      mediaThumbnail={mediaThumbnail}
                    />
                  </LiquidGlass>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* クライアント実装ドキュメントページ(最上層オーバーレイ) */}
      {showDocs && <DocsPage onClose={() => setShowDocs(false)} />}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   投稿カード(テキスト/画像共通)。名前・アイコンクリックでそのユーザーの
   プロフィールを開き、リアクションの表示/投稿も行う。
   ──────────────────────────────────────────────────────────────────── */
function PostCard({
  e,
  profileMap,
  reactions,
  selfPubkeyHex,
  onOpenUser,
  onReact,
  onRepost,
  onQuote,
  embedded = false,
}: {
  e: FodprEvent;
  profileMap: Record<string, FodprEvent>;
  reactions: ReactionItem[] | undefined;
  selfPubkeyHex: string;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  embedded?: boolean;
}) {
  const pkHex = CryptoUtils.bytesToHex(e.pubkey);
  const name = resolveDisplayName(pkHex, profileMap);
  const pic = profilePicture(profileMap[pkHex]);
  const key = dedupeKey(e);

  // Binary だが画像としてパースできないイベントは簡易表示する
  if (e.transType === TransTypeBinary) {
    const img = parseImageContent(e.content);
    if (!img) {
      return (
        <div className="rounded-lg border border-white/10 bg-black/30 p-3 text-sm text-gray-400">
          [Binary event · signature {e.signature.length} bytes]
          <span className="block text-xs">{name}</span>
        </div>
      );
    }
    const caption = captionFromTags(e.tags);
    return (
      <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
        <div className="flex gap-3 p-4">
          <button
            onClick={() => onOpenUser(pkHex)}
            className="shrink-0 rounded-full transition-transform hover:scale-105"
            title="プロフィールを開く"
          >
            <Avatar picture={pic} pubkeyHex={pkHex} name={name} />
          </button>
          <div className="min-w-0 flex-1">
            <div className="flex items-baseline gap-2">
              <button
                onClick={() => onOpenUser(pkHex)}
                className="font-semibold text-primary transition-colors hover:text-primary-hover hover:underline"
              >
                {name}
              </button>
              <span className="text-xs text-gray-400">{new Date(e.createdAt * 1000).toLocaleString()}</span>
            </div>
            {caption && <p className="mt-2 text-lg leading-relaxed whitespace-pre-wrap break-words sm:text-xl">{caption}</p>}
            <img
              src={`data:${img.mime};base64,${img.base64}`}
              alt={caption ?? '画像'}
              loading="lazy"
              className="mt-2 max-h-96 w-auto max-w-full rounded-xl"
            />
            <PostActions
              targetKey={key}
              reactions={reactions}
              selfPubkeyHex={selfPubkeyHex}
              embedded={embedded}
              onReact={onReact}
              onRepost={onRepost}
              onQuote={onQuote}
            />
          </div>
        </div>
      </LiquidGlass>
  );
}

  return (
    <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
      <div className="flex gap-3 p-4">
        <button
          onClick={() => onOpenUser(pkHex)}
          className="shrink-0 rounded-full transition-transform hover:scale-105"
          title="プロフィールを開く"
        >
          <Avatar picture={pic} pubkeyHex={pkHex} name={name} />
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <button
              onClick={() => onOpenUser(pkHex)}
              className="font-semibold text-primary transition-colors hover:text-primary-hover hover:underline"
            >
              {name}
            </button>
            <span className="text-xs text-gray-400">{new Date(e.createdAt * 1000).toLocaleString()}</span>
          </div>
          <p className="mt-2 text-lg leading-relaxed whitespace-pre-wrap break-words sm:text-xl">{e.content}</p>
          <PostActions
            targetKey={key}
            reactions={reactions}
            selfPubkeyHex={selfPubkeyHex}
            embedded={embedded}
            onReact={onReact}
            onRepost={onRepost}
            onQuote={onQuote}
          />
        </div>
      </div>
    </LiquidGlass>
  );
}

/* ────────────────────────────────────────────────────────────────────
   投稿欄コンポーザ(デスクトップの下部固定欄とモバイルの中央モーダルの共通部品)
   引用モードに入ると入力欄へ自動フォーカスする。Ctrl/Cmd+Enter で投稿。
   ──────────────────────────────────────────────────────────────────── */
function Composer({
  noteText,
  setNoteText,
  mediaDataUrl,
  mediaName,
  mediaSize,
  mediaError,
  clearMedia,
  quoteTarget,
  quoteEvent,
  quoteName,
  onCancelQuote,
  onPickFile,
  onSubmit,
  relayConnected,
  mediaType,
  mediaThumbnail,
}: {
  noteText: string;
  setNoteText: (v: string) => void;
  mediaDataUrl: string | null;
  mediaName: string | null;
  mediaSize: number;
  mediaError: string | null;
  clearMedia: () => void;
  quoteTarget: string | null;
  quoteEvent: FodprEvent | undefined;
  quoteName: string | undefined;
  onCancelQuote: () => void;
  onPickFile: (file: File | undefined) => void;
  onSubmit: () => void;
  relayConnected: boolean;
  mediaType: 'image' | 'video' | 'file' | null;
  mediaThumbnail: string | null;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const noteRef = useRef<HTMLTextAreaElement>(null);

  // 引用モードに入ったら入力欄へ自動でフォーカスする
  useEffect(() => {
    if (quoteTarget) noteRef.current?.focus();
  }, [quoteTarget]);

  return (
    <div className="p-3">
      {mediaDataUrl && (
        <div className="mb-2 flex items-center gap-3 rounded-xl bg-black/30 p-2">
          {mediaType === 'video' && mediaThumbnail ? (
            <video src={mediaThumbnail} className="h-14 w-14 rounded-lg object-cover" muted />
          ) : (
            <img src={mediaDataUrl} alt="プレビュー" className="h-14 w-14 rounded-lg object-cover" />
          )}
          <span className="min-w-0 flex-1 truncate text-xs text-gray-400">
            {mediaName} ({formatBytes(mediaSize)})
            {mediaType === 'video' && ' (動画)'}
            {mediaType === 'file' && ' (ファイル)'}
          </span>
          <button
            onClick={clearMedia}
            className="shrink-0 rounded-lg border border-white/15 px-2.5 py-1 text-xs text-gray-400 transition-colors hover:bg-white/10"
          >
            解除
          </button>
        </div>
      )}
      {quoteTarget && (
        <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-black/20 px-3 py-2">
          <span className="shrink-0 text-xs text-gray-400">引用:</span>
          <span className="min-w-0 flex-1 truncate text-xs text-gray-300">
            {quoteName ? `${quoteName}: ${eventSnippet(quoteEvent)}` : '元の投稿が見つかりません'}
          </span>
          <button
            onClick={onCancelQuote}
            className="shrink-0 rounded-lg border border-white/15 px-2.5 py-1 text-xs text-gray-400 transition-colors hover:bg-white/10"
          >
            解除
          </button>
        </div>
      )}
      <div className="flex items-end gap-3">
        <textarea
          ref={noteRef}
          className="max-h-40 flex-1 resize-none rounded-xl bg-black/30 p-3 text-base text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
          placeholder={quoteTarget ? '引用して投稿する...' : '何か投稿する...'}
          value={noteText}
          onChange={(e) => setNoteText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
              e.preventDefault();
              void onSubmit();
            }
          }}
          rows={2}
        />
        <div className="flex shrink-0 gap-2">
          <button
            onClick={() => fileRef.current?.click()}
            disabled={!relayConnected || !!quoteTarget}
            className="rounded-xl border border-white/15 px-3 py-2.5 text-sm font-semibold text-gray-300 transition-colors hover:bg-white/10 disabled:opacity-40 sm:px-4 sm:py-3"
          >
            添付
          </button>
          <button
            onClick={() => void onSubmit()}
            disabled={!relayConnected || (quoteTarget ? !noteText.trim() : !noteText.trim() && !mediaDataUrl)}
            className="rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:opacity-40 sm:px-6 sm:py-3"
          >
            投稿
          </button>
        </div>
      </div>
      {mediaError && <p className="mt-2 text-xs text-red-400">{mediaError}</p>}
      <input
        ref={fileRef}
        type="file"
        accept="image/*,video/*,*/*"
        className="hidden"
        onChange={(e) => {
          onPickFile(e.target.files?.[0]);
          e.target.value = '';
        }}
      />
    </div>
  );
}
// リポスト/引用のボタン行(埋め込み表示時は出さない)
function RepostIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <polyline points="17 1 21 5 17 9" />
      <path d="M3 11V9a4 4 0 0 1 4-4h14" />
      <polyline points="7 23 3 19 7 15" />
      <path d="M21 13v2a4 4 0 0 1-4 4H3" />
    </svg>
  );
}

// リアクションのハート。未反応ならアウトライン、反応済みなら塗りつぶし表示
function HeartIcon({ filled, className }: { filled: boolean; className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill={filled ? 'currentColor' : 'none'}
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z" />
    </svg>
  );
}

// 投稿アクション行: ハート(未反応=アウトライン / 反応済み=塗り) + リポスト/引用アイコン。
// ハートとリポストアイコンは横並び。リポストアイコンを押すとメニューで「リポスト」「引用」を選べる。
function PostActions({
  targetKey,
  reactions,
  selfPubkeyHex,
  embedded,
  onReact,
  onRepost,
  onQuote,
}: {
  targetKey: string;
  reactions: ReactionItem[] | undefined;
  selfPubkeyHex: string;
  embedded: boolean;
  onReact: (targetKey: string, emoji: string) => void;
  onRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const agg = aggregateReactions(reactions, selfPubkeyHex);
  const selfReacted = agg.some((r) => r.self);
  const total = agg.reduce((sum, r) => sum + r.count, 0);
  return (
    <div className="mt-3 flex flex-wrap items-center gap-1.5">
      <button
        onClick={() => {
          if (!selfReacted) onReact(targetKey, '❤️');
        }}
        title={selfReacted ? 'リアクション済み' : 'リアクション ❤️'}
        aria-pressed={selfReacted}
        className={
          'flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-colors ' +
          (selfReacted
            ? 'border-primary/60 bg-primary/15 text-primary'
            : 'border-white/15 text-gray-300 hover:bg-white/10')
        }
      >
        <HeartIcon filled={selfReacted} className="h-4 w-4" />
        {total > 0 && <span>{total}</span>}
      </button>
      {!embedded && (
        <div className="relative">
          <button
            onClick={() => setOpen((o) => !o)}
            title="共有(リポスト/引用)"
            aria-expanded={open}
            className="rounded-full border border-white/15 p-1.5 text-gray-300 transition-colors hover:bg-white/10"
          >
            <RepostIcon className="h-4 w-4" />
          </button>
          {open && (
            <>
              <button className="fixed inset-0 z-10 cursor-default" aria-hidden="true" onClick={() => setOpen(false)} />
              <div className="absolute bottom-full left-0 z-20 mb-1.5 min-w-36 overflow-hidden rounded-xl border border-white/15 bg-[#14161a] shadow-xl">
                <button
                  onClick={() => {
                    setOpen(false);
                    onRepost(targetKey);
                  }}
                  className="block w-full px-3.5 py-2 text-left text-sm text-gray-200 transition-colors hover:bg-white/10"
                >
                  リポスト
                </button>
                <button
                  onClick={() => {
                    setOpen(false);
                    onQuote(targetKey);
                  }}
                  className="block w-full px-3.5 py-2 text-left text-sm text-gray-200 transition-colors hover:bg-white/10"
                >
                  引用
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   リポスト/引用の共有カード。ヘッダーにアクション種別と投稿者を表示し、
   中身に対象イベントを埋め込む。
   ──────────────────────────────────────────────────────────────────── */
function SharedCard({
  e,
  profileMap,
  reactions,
  eventByKey,
  selfPubkeyHex,
  onOpenUser,
  onReact,
  onRepost,
  onQuote,
  depth,
}: {
  e: FodprEvent;
  profileMap: Record<string, FodprEvent>;
  reactions: ReactionMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  depth: number;
}) {
  const pkHex = CryptoUtils.bytesToHex(e.pubkey);
  const name = resolveDisplayName(pkHex, profileMap);
  const isQuote = quoteTarget(e) !== null;
  const targetKey = (isQuote ? quoteTarget(e) : repostTarget(e)) as string;
  const target = eventByKey.get(targetKey);

  return (
    <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
      <div className="p-3">
        <div className="flex items-baseline gap-2 px-1 pb-2 text-xs text-gray-400">
          <span className="font-semibold">{isQuote ? '引用' : 'リポスト'}</span>
          <span>・ {name}</span>
          <span className="text-gray-500">{new Date(e.createdAt * 1000).toLocaleString()}</span>
        </div>
        {isQuote && e.content.trim() && (
          <p className="mb-2 whitespace-pre-wrap break-words px-1 text-lg leading-relaxed text-gray-100 sm:text-xl">
            {e.content}
          </p>
        )}
        {target ? (
          <div className="overflow-hidden rounded-xl border border-white/10 bg-black/20">
            <TimelineCard
              e={target}
              profileMap={profileMap}
              reactions={reactions}
              eventByKey={eventByKey}
              selfPubkeyHex={selfPubkeyHex}
              onOpenUser={onOpenUser}
              onReact={onReact}
              onRepost={onRepost}
              onQuote={onQuote}
              depth={depth + 1}
            />
          </div>
        ) : (
          <p className="rounded-lg border border-white/10 bg-black/20 p-3 text-xs text-gray-500">
            元の投稿が見つかりません(タグ: {targetKey.slice(0, 40)}…)
          </p>
        )}
      </div>
    </LiquidGlass>
  );
}

// 通常投稿 / リポスト・引用を自動で振り分けるカードディスパッチャー
function TimelineCard({
  e,
  profileMap,
  reactions,
  eventByKey,
  selfPubkeyHex,
  onOpenUser,
  onReact,
  onRepost,
  onQuote,
  depth = 0,
}: {
  e: FodprEvent;
  profileMap: Record<string, FodprEvent>;
  reactions: ReactionMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  depth?: number;
}) {
  if (repostTarget(e) || quoteTarget(e)) {
    if (depth >= 3) {
      return (
        <div className="rounded-lg border border-white/10 bg-black/20 p-3 text-xs text-gray-500">
          共有チェーンの上限です
        </div>
      );
    }
    return (
      <SharedCard
        e={e}
        profileMap={profileMap}
        reactions={reactions}
        eventByKey={eventByKey}
        selfPubkeyHex={selfPubkeyHex}
        onOpenUser={onOpenUser}
        onReact={onReact}
        onRepost={onRepost}
        onQuote={onQuote}
        depth={depth}
      />
    );
  }
  return (
    <PostCard
      e={e}
      profileMap={profileMap}
      reactions={reactions.get(dedupeKey(e))}
      selfPubkeyHex={selfPubkeyHex}
      onOpenUser={onOpenUser}
      onReact={onReact}
      onRepost={onRepost}
      onQuote={onQuote}
      embedded={depth > 0}
    />
  );
}

/* ────────────────────────────────────────────────────────────────────
   タイムライン(最新順)
   ──────────────────────────────────────────────────────────────────── */
function Timeline({
  notes,
  binaries,
  links,
  others,
  profileMap,
  reactions,
  eventByKey,
  selfPubkeyHex,
  onOpenUser,
  onReact,
  onRepost,
  onQuote,
}: {
  notes: FodprEvent[];
  binaries: FodprEvent[];
  links: FodprEvent[];
  others: FodprEvent[];
  profileMap: Record<string, FodprEvent>;
  reactions: ReactionMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
}) {
  // テキスト/画像/共有を統合して最新順(上=最新)に並べる
  const posts = sortPostsDesc([...notes, ...binaries, ...links]);

  return (
    <div className="space-y-3">
      {posts.length === 0 && <p className="pt-8 text-center text-sm text-gray-500">まだ投稿はありません</p>}

      {posts.map((e) => (
        <TimelineCard
          key={dedupeKey(e)}
          e={e}
          profileMap={profileMap}
          reactions={reactions}
          eventByKey={eventByKey}
          selfPubkeyHex={selfPubkeyHex}
          onOpenUser={onOpenUser}
          onReact={onReact}
          onRepost={onRepost}
          onQuote={onQuote}
        />
      ))}

      {others.length > 0 && (
        <div className="space-y-2 pt-2">
          {others.map((e) => (
            <div key={dedupeKey(e)} className="rounded-lg border border-white/10 bg-black/30 p-3 text-sm">
              <span className="text-gray-400">[Other] </span>
              <span className="break-all text-gray-300">{e.content.slice(0, 200)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   他ユーザーのプロフィール(名前・アイコン・自己紹介・投稿一覧)
   ──────────────────────────────────────────────────────────────────── */
function UserProfileView({
  pubkeyHex,
  profileMap,
  notes,
  binaries,
  links,
  reactions,
  eventByKey,
  selfPubkeyHex,
  onBack,
  onOpenUser,
  onReact,
  onRepost,
  onQuote,
}: {
  pubkeyHex: string;
  profileMap: Record<string, FodprEvent>;
  notes: FodprEvent[];
  binaries: FodprEvent[];
  links: FodprEvent[];
  reactions: ReactionMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  onBack: () => void;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
}) {
  const prof = profileMap[pubkeyHex];
  const p = prof ? parseProfile(prof.content) : {};
  const name = p.name ?? pubkeyHex.slice(0, 12);
  const posts = sortPostsDesc(
    [...notes, ...binaries, ...links].filter((e) => CryptoUtils.bytesToHex(e.pubkey) === pubkeyHex),
  );

  return (
    <div className="space-y-3">
      <LiquidGlass intensity="subtle" refractive className="liquid-glass--card w-full">
        <div className="space-y-4 p-5">
          <button
            onClick={onBack}
            className="rounded-full border border-white/15 px-3 py-1.5 text-xs text-gray-300 transition-colors hover:bg-white/10"
          >
            ← タイムラインに戻る
          </button>

          <div className="flex items-center gap-4">
            <Avatar picture={p.picture ?? null} pubkeyHex={pubkeyHex} name={name} className="h-20 w-20 text-2xl" />
            <div className="min-w-0">
              <h2 className="truncate text-lg font-semibold text-white">{name}</h2>
              {p.about && <p className="mt-1 whitespace-pre-wrap break-words text-sm text-gray-400">{p.about}</p>}
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs text-gray-400">公開鍵</label>
              <span className="text-xs text-gray-500">投稿 {posts.length} 件</span>
            </div>
            <code className="block break-all rounded-xl bg-black/30 px-3 py-2.5 text-xs text-gray-300">{pubkeyHex}</code>
          </div>
        </div>
      </LiquidGlass>

      {posts.length === 0 ? (
        <p className="pt-8 text-center text-sm text-gray-500">まだ投稿はありません</p>
      ) : (
        posts.map((e) => (
          <TimelineCard
            key={dedupeKey(e)}
            e={e}
            profileMap={profileMap}
            reactions={reactions}
            eventByKey={eventByKey}
            selfPubkeyHex={selfPubkeyHex}
            onOpenUser={onOpenUser}
            onReact={onReact}
            onRepost={onRepost}
            onQuote={onQuote}
          />
        ))
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   プロフィール
   ──────────────────────────────────────────────────────────────────── */
function ProfileView({
  pubkeyHex,
  selfName,
  picture,
  name,
  about,
  onPictureChange,
  onNameChange,
  onAboutChange,
  onSave,
  relayConnected,
}: {
  pubkeyHex: string;
  selfName: string;
  picture: string;
  name: string;
  about: string;
  onPictureChange: (v: string) => void;
  onNameChange: (v: string) => void;
  onAboutChange: (v: string) => void;
  onSave: () => void;
  relayConnected: boolean;
}) {
  const [picBusy, setPicBusy] = useState(false);
  const [picStatus, setPicStatus] = useState<string | null>(null);
  const [picErr, setPicErr] = useState<string | null>(null);
  const picFileRef = useRef<HTMLInputElement>(null);

  // 画像ファイルを選択 → 圧縮 → ストレージへアップロード → 直リンク URL を picture へ設定
  async function onPickPicture(file: File | undefined) {
    setPicErr(null);
    setPicStatus(null);
    if (!file) return;
    if (!file.type.startsWith('image/')) {
      setPicErr('画像ファイルのみ選択できます');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setPicErr('画像は 10MB 以下にしてください');
      return;
    }
    try {
      const { dataUrl, size } = await compressImageFile(file);
      setPicBusy(true);
      setPicStatus('アップロード中...');
      const blob = await (await fetch(dataUrl)).blob();
      const res = await fetch('/media/upload', {
        method: 'POST',
        headers: { 'Content-Type': blob.type },
        body: blob,
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(body?.error ?? `アップロード失敗 (${res.status})`);
      }
      const { url } = (await res.json()) as { url: string };
      onPictureChange(url);
      setPicStatus(`アップロードしました (${formatBytes(size)} に圧縮)`);
    } catch (e) {
      setPicErr(e instanceof Error ? e.message : 'アップロードに失敗しました');
    } finally {
      setPicBusy(false);
    }
  }

  return (
    <LiquidGlass intensity="subtle" refractive className="liquid-glass--card w-full">
      <div className="space-y-4 p-5">
        <div className="flex items-center gap-4">
          <Avatar picture={picture || null} pubkeyHex={pubkeyHex} name={selfName} className="h-20 w-20 text-2xl" />
          <div>
            <h2 className="text-lg font-semibold text-white">プロフィール</h2>
            <p className="mt-1 text-sm text-gray-400">現在の表示名: <span className="font-medium text-primary">{selfName}</span></p>
          </div>
        </div>

        <div className="space-y-2">
          <label className="block text-xs text-gray-400">名前</label>
          <input
            type="text"
            placeholder="名前"
            value={name}
            onChange={(e) => onNameChange(e.target.value)}
            className="w-full rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
          />
        </div>

        <div className="space-y-2">
          <label className="block text-xs text-gray-400">プロフィール画像 (直リンク URL または画像ファイル)</label>
          <input
            type="url"
            placeholder="https://example.com/icon.png"
            value={picture}
            onChange={(e) => onPictureChange(e.target.value)}
            className="w-full rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
          />
          <div className="flex items-center gap-2">
            <button
              onClick={() => picFileRef.current?.click()}
              disabled={picBusy}
              className="rounded-xl border border-white/15 px-4 py-2 text-sm text-gray-300 transition-colors hover:bg-white/10 disabled:opacity-40"
            >
              画像を選択してアップロード
            </button>
            {picStatus && <span className="text-xs text-green-400">{picStatus}</span>}
            {picErr && <span className="text-xs text-red-400">{picErr}</span>}
            <input
              ref={picFileRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={(e) => {
                void onPickPicture(e.target.files?.[0]);
                e.target.value = '';
              }}
            />
          </div>
          <p className="text-xs text-gray-500">Nostr と同様、画像の直リンクを指定します。ファイルから選択すると圧縮後、同じサーバーにアップロードして URL を自動で設定します。</p>
        </div>

        <div className="space-y-2">
          <label className="block text-xs text-gray-400">自己紹介 (任意)</label>
          <input
            type="text"
            placeholder="自己紹介"
            value={about}
            onChange={(e) => onAboutChange(e.target.value)}
            className="w-full rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
          />
        </div>

        <div className="flex justify-end">
          <button
            onClick={onSave}
            disabled={!relayConnected || !name.trim()}
            className="rounded-xl bg-primary px-5 py-2 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:opacity-40"
          >
            プロフィールを保存
          </button>
        </div>

        <div className="space-y-2 border-t border-white/10 pt-4">
          <label className="block text-xs text-gray-400">公開鍵</label>
          <code className="block break-all rounded-xl bg-black/30 px-3 py-2.5 text-xs text-gray-300">{pubkeyHex}</code>
        </div>
      </div>
    </LiquidGlass>
  );
}

/* ────────────────────────────────────────────────────────────────────
   設定
   ──────────────────────────────────────────────────────────────────── */
function SettingsView({
  relayUrls,
  onRelayChange,
  relayStatus,
  relayConnected,
  onLogout,
  onShowDocs,
  secretHex,
}: {
  relayUrls: string[];
  onRelayChange: (urls: string[]) => void;
  relayStatus: RelayStatus[];
  relayConnected: boolean;
  onLogout: () => void;
  onShowDocs: () => void;
  secretHex: string;
}) {
  const [relayInput, setRelayInput] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const fsec = useMemo(() => hexToFsec(secretHex), [secretHex]);
  const masked = fsec.length > 16 ? `${fsec.slice(0, 9)}…${fsec.slice(-6)}` : fsec;

  function addRelay() {
    const url = relayInput.trim();
    if (!/^wss?:\/\//.test(url)) {
      setErr('wss:// または ws:// で始まるURLを入力してください');
      return;
    }
    if (relayUrls.includes(url)) {
      setErr('そのリレーは既に登録されています');
      return;
    }
    onRelayChange([...relayUrls, url]);
    setRelayInput('');
    setMsg('リレーを追加しました');
    setErr(null);
  }

  function removeRelay(url: string) {
    if (relayUrls.length <= 1) {
      setErr('最後のリレーは削除できません');
      return;
    }
    onRelayChange(relayUrls.filter((u) => u !== url));
    setMsg('リレーを削除しました');
    setErr(null);
  }

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(fsec);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = fsec;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-3">
      <LiquidGlass intensity="subtle" refractive className="liquid-glass--card w-full">
        <div className="space-y-4 p-5">
          <h2 className="text-lg font-semibold text-white">設定</h2>

          <div className="space-y-2">
            <label className="block text-xs text-gray-400">接続リレー (複数登録可)</label>
            <div className="space-y-2">
              {relayStatus.map((s) => (
                <div key={s.url} className="flex items-center gap-2 rounded-xl bg-black/30 px-3 py-2">
                  <span className={'h-2 w-2 shrink-0 rounded-full ' + (s.connected ? 'bg-green-400' : 'bg-red-400')} />
                  <span className="min-w-0 flex-1 truncate text-xs text-gray-300">{s.url}</span>
                  <button
                    onClick={() => removeRelay(s.url)}
                    disabled={relayUrls.length <= 1}
                    className="shrink-0 rounded-lg border border-white/15 px-2 py-1 text-xs text-gray-400 transition-colors hover:bg-white/10 disabled:opacity-30"
                  >
                    削除
                  </button>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="wss://example-relay/"
                value={relayInput}
                onChange={(e) => setRelayInput(e.target.value)}
                className="min-w-0 flex-1 rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
              />
              <button
                onClick={addRelay}
                className="shrink-0 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover"
              >
                追加
              </button>
            </div>
            <div className="flex items-center justify-between">
              <span className={'flex items-center gap-1.5 text-xs ' + (relayConnected ? 'text-green-400' : 'text-red-400')}>
                <span className={'h-2 w-2 rounded-full ' + (relayConnected ? 'bg-green-400' : 'bg-red-400')} />
                いずれかのリレーに接続中
              </span>
            </div>
          </div>

          <div className="space-y-1 border-t border-white/10 pt-4 text-xs text-gray-400">
            <p>投稿は登録済みの全リレーへ送信され、タイムラインは全リレーから取得したイベントを重複排除して表示します。</p>
          </div>

          {msg && <p className="text-sm text-green-400">{msg}</p>}
          {err && <p className="text-sm text-red-400">{err}</p>}
        </div>
      </LiquidGlass>

      {/* ログアウト + 秘密鍵(マスク表示・コピー) */}
      <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
        <div className="space-y-3 p-4">
          <div className="space-y-1.5">
            <p className="text-sm font-medium text-white">秘密鍵 (fsec)</p>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded-xl bg-black/30 px-3 py-2.5 text-xs text-gray-300">
                {masked}
              </code>
              <button
                onClick={copySecret}
                className="shrink-0 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover"
              >
                {copied ? 'コピーしました' : 'コピー'}
              </button>
            </div>
            <p className="text-xs text-gray-500">クリックではなくコピーボタンで全長の秘密鍵を取得できます。</p>
          </div>

          <div className="flex items-center justify-between border-t border-white/10 pt-3">
            <div>
              <p className="text-sm font-medium text-white">ログアウト</p>
              <p className="mt-0.5 text-xs text-gray-400">ローカルの秘密鍵を削除します</p>
            </div>
              <button
                onClick={onLogout}
                className="rounded-xl border border-red-400/40 px-4 py-2 text-sm text-red-300 transition-colors hover:bg-red-400/10"
              >
                ログアウト
              </button>
            </div>

            <div className="flex items-center justify-between border-t border-white/10 pt-3">
              <div>
                <p className="text-sm font-medium text-white">クライアント実装ガイド</p>
                <p className="mt-0.5 text-xs text-gray-400">JSON/バイナリの投稿フォーマットやタグ仕様を確認できます</p>
              </div>
              <button
                onClick={onShowDocs}
                className="rounded-xl border border-white/15 px-4 py-2 text-sm font-semibold text-gray-300 transition-colors hover:bg-white/10"
              >
                開く
              </button>
            </div>
        </div>
      </LiquidGlass>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   ログイン画面
   ──────────────────────────────────────────────────────────────────── */
function LoginScreen({
  onLogin,
  onGenerate,
}: {
  onLogin: (input: string) => Promise<void>;
  onGenerate: () => Promise<void>;
}) {
  const [keyInput, setKeyInput] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit() {
    setError('');
    setBusy(true);
    try {
      await onLogin(keyInput);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  async function generate() {
    setError('');
    setBusy(true);
    try {
      await onGenerate();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-bg text-gray-100">
      <div className="aurora" aria-hidden="true" />

      <div className="relative z-10 flex min-h-screen items-center justify-center px-4">
        <LiquidGlass intensity="vision" refractive className="w-full max-w-md">
          <div className="space-y-4 p-7">
            <div>
              <h1 className="text-2xl font-semibold text-white">Fodpr</h1>
              <p className="mt-1 text-sm text-gray-300">fsec1... 形式の秘密鍵でログインしてください。</p>
            </div>

            <div className="space-y-2">
              <label className="block text-xs text-gray-400">秘密鍵 (fsec または HEX)</label>
              <input
                type="text"
                placeholder="fsec1..."
                value={keyInput}
                onChange={(e) => {
                  setKeyInput(e.target.value);
                  setError('');
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void submit();
                }}
                autoComplete="off"
                autoFocus
                className="w-full rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
              />
            </div>

            {error && <p className="text-sm text-red-400">{error}</p>}

            <div className="space-y-2">
              <button
                onClick={() => void submit()}
                disabled={busy || !keyInput.trim()}
                className="w-full rounded-xl bg-primary py-2.5 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:opacity-50"
              >
                {busy ? '処理中...' : 'ログイン'}
              </button>
              <button
                onClick={() => void generate()}
                disabled={busy}
                className="w-full rounded-xl border border-white/15 py-2.5 text-sm text-gray-300 transition-colors hover:bg-white/10"
              >
                新しい鍵を生成
              </button>
            </div>

            <p className="text-xs leading-relaxed text-gray-400">
              秘密鍵は AES-256-GCM で暗号化して保存されます(復号鍵はブラウザの IndexedDB に非エクスポート可能な形で保持)。
              次回から自動でログインできます。
            </p>
          </div>
      </LiquidGlass>
    </div>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   クライアント実装ドキュメントページ
   Fodpr のイベントフォーマットやタグ仕様を読み取り可能なページ。
   ──────────────────────────────────────────────────────────────────── */
function DocsPage({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-bg/90 p-4" onClick={onClose}>
      <div
        className="relative max-h-[90dvh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-white/10 bg-bg/70 p-6 text-sm text-gray-200"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          aria-label="閉じる"
          title="閉じる"
          className="absolute top-3 right-3 rounded-full border border-white/15 px-2.5 py-1 text-xs text-gray-400 transition-colors hover:bg-white/10"
        >
          閉じる
        </button>
        <div className="space-y-3 pr-6">
          {parseMdBlocks().map((b, k) => renderMdBlock(b, k))}
        </div>
      </div>
    </div>
  );
}

const DOC_HEAD = `
## イベントの基本形
| フィールド | 型 | 説明 |
| pubkey | bytes | 投稿者の公開鍵(Ed25519) |
| signature | bytes | content に対する署名 |
| transType | string | フォーマット種別(string/binary/json) |
| content | string | 本文 / ペイロード |
| tags | string[] | 補足情報 |
| createdAt | number | Unix 秒タイムスタンプ |
署名検証: signature = sign(privkey, content)
## 投稿フォーマット
TransTypeString はテキスト投稿。transType = "string"; content = 本文; tags = []
TransTypeBinary は画像投稿。transType = "binary"; content = "img:<MIME>;base64,<data>"; tags = ["caption:<キャプション>"]
### リポスト
transType = "string"; content = ""; tags = ["repost:<dedupeKey>"]
### 引用
transType = "string"; content = コメント; tags = ["quote:<dedupeKey>"]
### リアクション(ハート)
transType = "string"; content = "❤️"; tags = ["react:<dedupeKey>"]
## dedupeKey
base64(sha256(pubkey || createdAt || content || tags))
## リレー一覧
localStorage.fodpr_relays = JSON.stringify(["wss://example.com/", ...])  // 複数可
`.trim();

type MdBlock = { type: string; text?: string; code?: string; head?: string[]; rows?: string[][] };

function parseMdBlocks(): MdBlock[] {
  const out: MdBlock[] = [];
  const lines = DOC_HEAD.split('\n');
  let i = 0;
  let para = '';
  const flush = () => { if (para.trim()) out.push({ type: 'p', text: para.trim() }); para = ''; };
  while (i < lines.length) {
    const l = lines[i];
    if (/^### /.test(l)) { flush(); out.push({ type: 'h3', text: l.slice(4) }); i++; continue; }
    if (/^## /.test(l)) { flush(); out.push({ type: 'h2', text: l.slice(3) }); i++; continue; }
    if (/^\|/.test(l)) {
      flush();
      const head = l.split('|').slice(1, -1).map((s) => s.trim());
      const rows: string[][] = [];
      i++;
      while (i < lines.length && /^\|/.test(lines[i])) {
        rows.push(lines[i].split('|').slice(1, -1).map((s) => s.trim()));
        i++;
      }
      out.push({ type: 'table', head, rows });
      continue;
    }
    if (/^```/.test(l)) {
      flush();
      const code: string[] = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) code.push(lines[i++]);
      i++;
      out.push({ type: 'code', code: code.join('\n') });
      continue;
    }
    para += (para ? ' ' : '') + l;
    i++;
  }
  flush();
  return out;
}

function renderMdBlock(b: MdBlock, k: number) {
  const key = `${k}-${b.type}`;
  switch (b.type) {
    case 'h2':
      return <h3 key={key} className="mt-4 text-lg font-semibold text-primary">{b.text}</h3>;
    case 'h3':
      return <h4 key={key} className="mt-3 text-sm font-medium text-gray-300">{b.text}</h4>;
    case 'p':
      return <p key={key} className="leading-relaxed text-gray-300">{b.text}</p>;
    case 'code':
      return (
        <pre key={key} className="my-2 overflow-x-auto rounded-lg bg-black/30 p-3 text-xs text-gray-300">
          <code>{b.code}</code>
        </pre>
      );
    case 'table':
      return (
        <table key={key} className="my-2 w-full border-collapse text-left text-xs">
          <thead>
            <tr>{b.head?.map((h) => <th key={h} className="border-b border-white/10 px-2 py-1 text-gray-400">{h}</th>)}</tr>
          </thead>
          <tbody>
            {b.rows?.map((row, ri) => (
              <tr key={ri}>{row.map((c, ci) => <td key={ci} className="border-b border-white/5 px-2 py-1">{c}</td>)}</tr>
            ))}
          </tbody>
        </table>
      );
    default:
      return null;
  }
}

export default App;
