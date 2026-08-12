import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import {
  Protocol,
  TransTypeAll,
  TransTypeBinary,
  TransTypeJSON,
  TransTypeString,
  DelTargetEvent,
  type FodprDelReq,
  type FodprEvent,
  type FodprReq,
} from '@fodpr/protocol';
import { CryptoUtils } from '@fodpr/crypto';
import '@dpawlikowski/liquid-glass/css';
import { LiquidGlass } from '@dpawlikowski/liquid-glass/react';
import type { RelayMessage } from './lib/relay';
import { sha256 } from '@noble/hashes/sha2.js';
import { fsecToHex, hexToFsec } from './lib/bech32';
import {
  clearSecret,
  clearNostrSecret,
  loadSecret,
  loadNostrSecret,
  migrateLegacySecret,
  saveSecret,
  saveNostrSecret,
} from './lib/keystore';
import { useRelay, type RelayStatus } from './hooks/useRelay';
import {
  getPublicKeyFromSecret,
  hexToNpub,
  hexToNsec,
  kind0DisplayName,
  makeNostrEvent,
  nsecToHex,
  parseKind0Metadata,
  signEventAsync,
  buildReactionTags,
  buildReplyTags,
  buildQuoteTags,
  type NostrEvent,
  type NostrTags,
  type UnsignedNostrEvent,
} from './lib/nostrProtocol';
import {
  type NosskeyCred,
  loginNosskeyPasskey,
  nosskeySupported,
  registerNosskeyPasskey,
  saveNsecToNosskey,
  hasNosskeyCredential,
  getStoredNosskeyCred,
} from './lib/nosskey';
import { fetchNostrKind0, fetchNostrRelayList, type RelayList } from './lib/nostrRelay';
import { useNostrRelay, type NostrRelayStatus } from './hooks/useNostrRelay';
import {
  allEmojis,
  buildFodprEmojiTags,
  buildNostrEmojiTags,
  clearExternalEmojis,
  parseEmoemoEvents,
  parseFodprEmojiTags,
  parseNostrEmojiTags,
  registerExternalEmoji,
  renderCustomEmojis,
  renderNostrContent,
  type CustomEmojiDef,
} from './lib/customEmoji';
import { SteganographyText } from './lib/steganography';
import { type F2FGroupInfo, type F2FPeerInfo } from './lib/fodprF2f';
import { createNetworkManager, type NetworkManager, type NetworkMode, type RtcGroupInfo } from './lib/network';

// 既定の接続先リレー(設定画面から追加・削除可能)
const DEFAULT_RELAYS = [
  'wss://fodpr-relay.yoinekodo.jp/',
  'wss://fodpr-subrelay.yoinekodo.jp/'
];
const RELAYS_STORAGE_KEY = 'fodpr_relays';
const NETWORK_MODE_STORAGE_KEY = 'fodpr_network_mode';

// 既定の Nostr リレー(設定画面から追加・削除可能)
const DEFAULT_NOSTR_RELAYS = ['wss://relay.yoinekodo.jp/'];
const NOSTR_RELAYS_STORAGE_KEY = 'nostr_relays';

// fsec 未ログイン時に nsec でゲストモードへ入ったことを記録するキー。
// nsec は vault(localStorage + IndexedDB)へ永続化されるがゲストモード自体は
// メモリ上のみなので、リロード後も nsec ログインを復元するために使う。
const NOSTR_GUEST_STORAGE_KEY = 'fodpr_nostr_guest';

// NIP-07 でログインした公開鍵(HEX)を保存するキー。
// 秘密鍵はブラウザ拡張内に保持されるため、ここには公開鍵だけを残す。
const NIP07_PUBKEY_STORAGE_KEY = 'fodpr_nip07_pubkey';

// NIP-79 (Nosskey / PRF direct usage)でログインした際の credential ID + 公開鍵。
// 秘密鍵はパスキーの PRF で毎回再生するため、ここには秘密鍵を永続化しない
// (秘密鍵はメモリ上の nostrPrivKey にのみ保持され、リロード後は再照認で再生される)。
// 再ログイン用の手がかり(credential ID + pubkey)だけを永続化する。
const NOSSKEY_CRED_STORAGE_KEY = 'fodpr_nosskey_cred';

// NIP-07: ブラウザ拡張が window.nostr に公開する API(秘密鍵は拡張内に保持)
type Nip07Nostr = {
  getPublicKey: () => Promise<string>;
  signEvent: (ev: {
    kind: number;
    tags: string[][];
    content: string;
    created_at: number;
  }) => Promise<{
    id: string;
    pubkey: string;
    sig: string;
    created_at: number;
    kind: number;
    tags: string[][];
    content: string;
  }>;
};

declare global {
  interface Window {
    nostr?: Nip07Nostr;
  }
}

// ネットワーク(Fodpr / Nostr)のタブ識別子
type ProtocolTab = 'fodpr' | 'nostr';

// ブラウザ通知のオン/オフ(localStorage 保存)
const BROWSER_NOTIF_STORAGE_KEY = 'fodpr_browser_notifications';
// すでにブラウザ通知を飛ばした通知 id の集合(localStorage 保存・再通知防止)
const NOTIF_NOTIFIED_STORAGE_KEY = 'fodpr_notified_notifs';

// すでに通知した id 集合を localStorage から復元する
function loadNotifiedIds(): Set<string> {
  try {
    const raw = localStorage.getItem(NOTIF_NOTIFIED_STORAGE_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) return new Set(arr.map((x) => String(x)));
    }
  } catch {
    /* ignore */
  }
  return new Set<string>();
}

// ミュート中 pubkey(Fodpr / Nostr 共通の HEX)を localStorage から復元する
const MUTE_STORAGE_KEY = 'fodpr_muted_pubkeys';
function loadMutedPubkeys(): Set<string> {
  try {
    const raw = localStorage.getItem(MUTE_STORAGE_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) return new Set(arr.map((x) => String(x)));
    }
  } catch {
    /* ignore */
  }
  return new Set<string>();
}
function saveMutedPubkeys(ids: Set<string>) {
  try {
    localStorage.setItem(MUTE_STORAGE_KEY, JSON.stringify(Array.from(ids)));
  } catch {
    /* ignore */
  }
}

// 入力された秘密鍵文字列を HEX に正規化する(fsec1... 形式または 64桁HEX)
function normalizeSecretKey(input: string): string {
  const s = input.trim();
  if (!s) throw new Error('秘密鍵を入力してください');
  if (s.toLowerCase().startsWith('fsec')) return fsecToHex(s);
  if (!/^[0-9a-fA-F]{64}$/.test(s)) throw new Error('fsec 形式または 64桁の HEX で入力してください');
  return s.toLowerCase();
}

// 入力された Nostr 秘密鍵(nsec1... または 64桁HEX)を HEX に正規化する
function normalizeNostrSecretKey(input: string): string {
  const s = input.trim();
  if (!s) throw new Error('nsec を入力してください');
  if (s.toLowerCase().startsWith('nsec')) return nsecToHex(s);
  if (!/^[0-9a-fA-F]{64}$/.test(s)) throw new Error('nsec 形式または 64桁の HEX で入力してください');
  return s.toLowerCase();
}

// リレー一覧を localStorage から読み込む(不正な値は既定値へフォールバック)
function loadNostrRelays(): string[] {
  const raw = localStorage.getItem(NOSTR_RELAYS_STORAGE_KEY);
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
  return [...DEFAULT_NOSTR_RELAYS];
}

// pubkey hex → 短い npub 表記(npup の先頭で人間に読みやすくする)
function shortNpub(pubkeyHex: string): string {
  try {
    const npub = hexToNpub(pubkeyHex);
    return npub.length > 14 ? npub.slice(0, 12) + '…' : npub;
  } catch {
    return pubkeyHex.slice(0, 10);
  }
}

// Nostr イベントの最初の 'e' タグ(返信/リアクション/リポストの対象)を返す
function firstETag(e: NostrEvent): string | null {
  for (const t of e.tags) {
    if (t[0] === 'e' && typeof t[1] === 'string' && t[1]) return t[1];
  }
  return null;
}

// Nostr 'e' タグのマーカー(marker)を返す: 'reply'|'root'|'q'|undefined。
// NIP-10 に基づき、引用ポストは marker='q' の e タグを持つ。
function firstETagMarker(e: NostrEvent): string | undefined {
  for (const t of e.tags) {
    if (t[0] === 'e' && typeof t[1] === 'string' && t[1]) return t[2];
  }
  return undefined;
}

// Nostr 投稿(テキスト)を最新順に並べる。同時刻は id で安定ソート。
function sortNostrDesc(posts: NostrEvent[]): NostrEvent[] {
  return [...posts].sort((a, b) => {
    if (b.created_at !== a.created_at) return b.created_at - a.created_at;
    return b.id > a.id ? 1 : -1;
  });
}

// pubkey hex → Nostr 表示名(kind 0 の display_name / name、なければ短い npub)
function nostrDisplayName(pubkeyHex: string, profileMap: Record<string, NostrEvent>): string {
  const prof = profileMap[pubkeyHex];
  if (prof) {
    const meta = parseKind0Metadata(prof.content);
    const n = kind0DisplayName(meta);
    if (n) return n;
  }
  return shortNpub(pubkeyHex);
}

// Nostr kind 7 リアクションを絵文字ごとに集計する
function aggregateNostrReactions(list: NostrEvent[] | undefined, selfPubkeyHex: string) {
  const m = new Map<string, { count: number; self: boolean }>();
  for (const e of list ?? []) {
    const emoji = e.content.trim() || '+';
    const cur = m.get(emoji) ?? { count: 0, self: false };
    cur.count += 1;
    if (e.pubkey === selfPubkeyHex) cur.self = true;
    m.set(emoji, cur);
  }
  return [...m.entries()].map(([emoji, v]) => ({ emoji, ...v }));
}

// Nostr 投稿に含まれる画像 URL を取り出す。
// 優先: NIP-92 の imeta タグ。無ければ本文中の http(s) 画像 URL から抽出する。
function nostrImageUrls(e: NostrEvent): { url: string; mime?: string }[] {
  const urls: { url: string; mime?: string }[] = [];
  for (const tag of e.tags) {
    if (tag[0] === 'imeta') {
      const entry = { url: '', mime: undefined as string | undefined };
      for (let i = 1; i < tag.length; i++) {
        if (tag[i] === 'url' && tag[i + 1]) entry.url = tag[i + 1];
        else if (tag[i] === 'm' && tag[i + 1]) entry.mime = tag[i + 1];
      }
      if (entry.url) urls.push(entry);
    }
  }
  if (urls.length > 0) return urls;
  // 本文中の画像 URL(拡張子判定)を抽出
  const IMG_URL_RE = /https?:\/\/[^\s<>"]+\.(?:png|jpe?g|gif|webp|avif|bmp)(?:\?[^\s<>"]*)?/gi;
  for (const m of e.content.matchAll(IMG_URL_RE)) {
    urls.push({ url: m[0] });
  }
  return urls;
}

// 本文中に含まれる画像 URL を全て取り出す(インライン画像化して URL テキストは非表示にする)
function inlineImageUrls(content: string): string[] {
  const IMG_URL_RE = /https?:\/\/[^\s<>"]+\.(?:png|jpe?g|gif|webp|avif|bmp)(?:\?[^\s<>"]*)?/gi;
  return [...content.matchAll(IMG_URL_RE)].map((m) => m[0]);
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
    replies: [] as FodprEvent[],
    links: [] as FodprEvent[],
    others: [] as FodprEvent[],
  };
  for (const e of events) {
    if (e.transType === TransTypeJSON) {
      try {
            const obj = JSON.parse(eventContentStr(e));
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
      } else if (e.tags.some((t) => t.startsWith('reply:'))) {
        // リプライ: content=返信本文、tags に reply:<対象イベントの dedupeKey>
        out.replies.push(e);
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
// SDK で FodprEvent.content が Uint8Array になったため、文字列として読むときは
// eventContentStr でデコードする(旧データ/ローカル楽観イベントは既に string の場合もある)。
const eventContentDecoder = new TextDecoder();
function eventContentStr(e: FodprEvent): string {
  const c = e.content as unknown;
  return typeof c === 'string' ? (c as string) : eventContentDecoder.decode(e.content);
}

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
  return parseProfile(eventContentStr(e)).name ?? null;
}

// プロフィールイベントからアイコン画像 URL(直リンク)を取り出す(失敗時は null)
function profilePicture(e: FodprEvent | undefined): string | null {
  if (!e) return null;
  return parseProfile(eventContentStr(e)).picture ?? null;
}

// メディア投稿(Binary)の content 形式: <mime>:<base64>
// (旧形式の img:<mime>;base64,<data> にも互換対応する)
const MEDIA_CONTENT_RE = /^(?:img:)?([^:;,]+)(?:;base64)?[,:](.+)$/s;

function parseImageContent(content: string): { mime: string; base64: string } | null {
  const m = MEDIA_CONTENT_RE.exec(content);
  return m ? { mime: m[1], base64: m[2] } : null;
}

// メディアイベントのタグ(filename:...)から元ファイル名を取り出す
function filenameFromTags(tags: string[]): string | null {
  for (const t of tags) {
    if (t.startsWith('filename:')) return t.slice('filename:'.length);
  }
  return null;
}

// 画像イベントのタグ(caption:...)から説明文を取り出す
function captionFromTags(tags: string[]): string | null {
  for (const t of tags) {
    if (t.startsWith('caption:')) return t.slice('caption:'.length);
  }
  return null;
}

// ── メンション ────────────────────────────────────────────────

// メンション解決用のユーザー一覧(プロフィール名 + pubkey hex)
type MentionUser = { pk: string; name: string };
function mentionUsers(profileMap: Record<string, FodprEvent>): MentionUser[] {
  return Object.keys(profileMap).map((pk) => ({
    pk,
    name: profileName(profileMap[pk]) ?? pk.slice(0, 12),
  }));
}

// 名前・hex のどちらからも引ける lookup 辞書を構築する
function buildMentionLookup(users: MentionUser[]): Map<string, MentionUser> {
  const m = new Map<string, MentionUser>();
  for (const u of users) {
    m.set(u.pk, u);
    m.set(u.name, u);
  }
  return m;
}

// content 内の `@名前` / `@hex` を名前解決して mention:<hex> タグへ変換する(重複排除)
function buildFodprMentionTags(content: string, lookup: Map<string, MentionUser>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const re = /@([^\s@,。、!！?？;；]+)/g;
  let mm: RegExpExecArray | null;
  while ((mm = re.exec(content)) !== null) {
    const u = lookup.get(mm[1]);
    if (u && !seen.has(u.pk)) {
      seen.add(u.pk);
      out.push(`mention:${u.pk}`);
    }
  }
  return out;
}

// Fodpr イベントの mention: タグからメンションされた pubkey 一覧を取り出す
function mentionTagOf(e: FodprEvent): string[] {
  return e.tags.filter((t) => t.startsWith('mention:')).map((t) => t.slice('mention:'.length));
}

// ── メンション(Nostr) ──────────────────────────────────────────

// Nostr 用: 名前・hex・npub から pubkey を解決する lookup
function buildNostrMentionLookup(profileMap: Record<string, NostrEvent>): Map<string, { pk: string; name: string }> {
  const m = new Map<string, { pk: string; name: string }>();
  for (const pk of Object.keys(profileMap)) {
    const name = nostrDisplayName(pk, profileMap) ?? pk.slice(0, 12);
    m.set(pk, { pk, name });
    m.set(name, { pk, name });
    try {
      m.set(hexToNpub(pk), { pk, name });
    } catch {
      /* bech32 変換失敗は無視 */
    }
  }
  return m;
}

// content 内の `@名前` / `@hex` / `@npub` を名前解決して NIP-10 の p タグへ変換する(重複排除)
function buildNostrMentionPTags(content: string, lookup: Map<string, { pk: string; name: string }>): NostrTags {
  const seen = new Set<string>();
  const out: NostrTags = [];
  const re = /@([^\s@,。、!！?？;；]+)/g;
  let mm: RegExpExecArray | null;
  while ((mm = re.exec(content)) !== null) {
    const u = lookup.get(mm[1]);
    if (u && !seen.has(u.pk)) {
      seen.add(u.pk);
      out.push(['p', u.pk]);
    }
  }
  return out;
}

// Fodpr 本文の :shortcode:(絵文字)と @名前/@hex(メンション)を描画する。
// メンションは名前解決できる場合に限りプロフィールを開くボタンにする。
function renderFodprContent(
  content: string,
  emojiMap: Record<string, string>,
  mentionLookup: Map<string, MentionUser>,
  onOpenUser: (pubkeyHex: string) => void,
): ReactNode[] {
  const TOKEN_RE = /(:[A-Za-z0-9_-]+:)|(@[^\s@,。、!！?？;；]+)/g;
  const parts: string[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = TOKEN_RE.exec(content)) !== null) {
    if (m.index > last) parts.push(content.slice(last, m.index));
    parts.push(m[0]);
    last = m.index + m[0].length;
  }
  if (last < content.length) parts.push(content.slice(last));

  const out: ReactNode[] = [];
  for (const part of parts) {
    if (!part) continue;
    const emoji = /^:([A-Za-z0-9_-]+):$/.exec(part);
    if (emoji) {
      const url = emojiMap[emoji[1]];
      if (url) {
        out.push(
          <img
            key={`e${out.length}`}
            src={url}
            alt={emoji[1]}
            title={emoji[1]}
            loading="lazy"
            className="inline-block h-[1.35em] w-[1.35em] max-w-[1.35em] align-[-0.25em] rounded-[0.2em] object-contain"
          />,
        );
        continue;
      }
    }
    const mention = /^@(.+)$/.exec(part);
    if (mention) {
      const u = mentionLookup.get(mention[1]);
      if (u) {
        out.push(
          <button
            key={`m${out.length}`}
            onClick={() => onOpenUser(u.pk)}
            className="text-primary transition-colors hover:text-primary-hover hover:underline"
            title="プロフィールを開く"
          >
            @{u.name}
          </button>,
        );
        continue;
      }
    }
    out.push(<SteganographyText key={`t${out.length}`} content={part} />);
  }
  return out;
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

function quoteTargetOf(e: FodprEvent): string | null {
  for (const t of e.tags) {
    if (t.startsWith('quote:')) return t.slice('quote:'.length);
  }
  return null;
}

// リプライイベントのタグ(reply:<対象の dedupeKey>)から対象イベントのキーを取り出す
function replyTag(e: FodprEvent): string | null {
  for (const t of e.tags) {
    if (t.startsWith('reply:')) return t.slice('reply:'.length);
  }
  return null;
}

// リプライの対象投稿者名(表示用)。対象イベントが見つからない場合は null
function replyParentName(
  e: FodprEvent,
  eventByKey: Map<string, FodprEvent>,
  profileMap: Record<string, FodprEvent>,
): string | null {
  const key = replyTag(e);
  if (!key) return null;
  const target = eventByKey.get(key);
  if (!target) return null;
  return resolveDisplayName(CryptoUtils.bytesToHex(target.pubkey), profileMap);
}

// イベント本文の短い抜粋(引用プレビュー用)
function eventSnippet(e: FodprEvent | undefined): string {
  if (!e) return '';
  if (e.transType === TransTypeBinary) {
    const media = parseImageContent(eventContentStr(e));
    if (media) return media.mime.startsWith('video/') ? '動画' : '画像';
    return '[バイナリ]';
  }
  const s = eventContentStr(e).trim();
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

type ReactionItem = { emoji: string; pubkey: string; createdAt: number };
type ReactionMap = Map<string, ReactionItem[]>;

// 対象イベントの dedupeKey をキーに、そのイベントへのリプライを束ねる
type ReplyMap = Map<string, FodprEvent[]>;

// 投稿(テキスト/画像)を最新順(createdAt 降順)に並べる。同時刻は署名で安定ソート。
function sortPostsDesc(posts: FodprEvent[]): FodprEvent[] {
  return [...posts].sort((a, b) => {
    if (b.createdAt !== a.createdAt) return b.createdAt - a.createdAt;
    return CryptoUtils.bytesToHex(b.signature) > CryptoUtils.bytesToHex(a.signature) ? 1 : -1;
  });
}

// 通知を最新順(createdAt 降順)で並べる
function sortByCreatedAt<T extends { createdAt: number }>(list: T[]): T[] {
  return [...list].sort((a, b) => b.createdAt - a.createdAt);
}

// 既読通知 ID 集合を localStorage から読み込む(壊れていれば空)
function loadReadNotifIds(): Set<string> {
  try {
    const raw = localStorage.getItem('prrr_notif_read');
    if (!raw) return new Set();
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) return new Set(arr.filter((x): x is string => typeof x === 'string'));
  } catch {
    /* 壊れていれば空 */
  }
  return new Set();
}

// 既読通知 ID 集合を localStorage へ保存する
function saveReadNotifIds(ids: Set<string>) {
  try {
    localStorage.setItem('prrr_notif_read', JSON.stringify([...ids]));
  } catch {
    /* 保存失敗は無視 */
  }
}

// タイムスタンプ(秒)を「〜前」表記にする
function relativeTime(ts: number): string {
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60) return 'たった今';
  if (diff < 3600) return `${Math.floor(diff / 60)}分前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}時間前`;
  if (diff < 86400 * 7) return `${Math.floor(diff / 86400)}日前`;
  return new Date(ts * 1000).toLocaleDateString();
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

// 通知の種類と発生元
type NotificationSource = 'fodpr' | 'nostr';
type NotificationType = 'react' | 'reply' | 'repost' | 'quote' | 'mention';

// 通知1件: 誰が・どの投稿に・いつアクションしたか
type Notification = {
  id: string;
  source: NotificationSource;
  type: NotificationType;
  senderPubkey: string;
  targetKey: string;
  createdAt: number;
};

// 閉じる(×)アイコン
function CloseIcon({ className }: { className?: string }) {
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
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}

// 通知タブ(タイムラインと同じ一覧 UI)
function NotificationsView({
  notifications,
  readNotifIds,
  onMarkRead,
  onMarkAllRead,
  onOpenPost,
  profileMap,
  nostrProfileMap,
  eventByKey,
  nostrNoteById,
  onOpenUser,
  onReact,
  onUndoReact,
  onRepost,
  onUndoRepost,
  onQuote,
  onReply,
  onDelete,
  selfPubkeyHex,
  selfRepostTargets,
  reactions,
  // 追加: インタラクション取得用
  replyMap,
  nostrReplyMap,
  links,
  nostrRepostMap,
  nostrReactions,
  nostrReposts,
  noteById,
  mentionLookup,
}: {
  notifications: Notification[];
  readNotifIds: Set<string>;
  onMarkRead: (id: string) => void;
  onMarkAllRead: () => void;
  onOpenPost: (n: Notification) => void;
  profileMap: Record<string, FodprEvent>;
  nostrProfileMap: Record<string, NostrEvent>;
  // 投稿検索用
  eventByKey: Map<string, FodprEvent>;
  nostrNoteById: Record<string, NostrEvent>;
// Fodprアクション用
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (...args: any[]) => void;
  onUndoReact?: (...args: any[]) => void;
  onRepost: (...args: any[]) => void;
  onUndoRepost?: (...args: any[]) => void;
  onQuote: (...args: any[]) => void;
  onReply: (...args: any[]) => void;
  onDelete: (...args: any[]) => void;
  selfPubkeyHex: string;
  selfRepostTargets?: Set<string>;
  reactions?: ReactionMap;
  // Nostr用
  nostrReactions?: Map<string, NostrEvent[]>;
  nostrReposts?: Map<string, NostrEvent[]>;
  noteById?: Record<string, NostrEvent>;
  // インタラクション取得用
  replyMap?: ReplyMap;
  nostrReplyMap?: Map<string, NostrEvent[]>;
  links?: FodprEvent[];
  nostrRepostMap?: Map<string, NostrEvent[]>;
  mentionLookup: Map<string, MentionUser>;
}) {
  const sorted = sortByCreatedAt(notifications);
  const nostrMentionLookup = useMemo(() => buildNostrMentionLookup(nostrProfileMap), [nostrProfileMap]);
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between px-1">
        <h2 className="text-lg font-semibold text-white">通知</h2>
        {notifications.length > 0 && (
          <button
            onClick={onMarkAllRead}
            className="rounded-full border border-white/15 px-3 py-1.5 text-xs text-gray-300 transition-colors hover:bg-white/10"
          >
            すべて既読
          </button>
        )}
      </div>
      {sorted.length === 0 ? (
        <p className="pt-8 text-center text-sm text-gray-500">通知はありません</p>
      ) : (
        <div className="space-y-3">
          {sorted.map((n) => {
            const unread = !readNotifIds.has(n.id);
            // 対象投稿を取得
            const targetPost = n.source === 'fodpr'
              ? eventByKey.get(n.targetKey)
              : nostrNoteById[n.targetKey];
            if (!targetPost) return null;

            const senderName = n.source === 'fodpr'
              ? resolveDisplayName(n.senderPubkey, profileMap)
              : nostrDisplayName(n.senderPubkey, nostrProfileMap);
            const typeLabel =
              n.type === 'react' ? 'リアクション' :
              n.type === 'reply' ? '返信' :
              n.type === 'repost' ? 'リポスト' :
              n.type === 'mention' ? 'あなたをメンション' : '引用';

            // インタラクション元のイベントを取得（返信/引用/リポスト/リアクション）
            let interactionEvent: FodprEvent | NostrEvent | null = null;
            if (n.source === 'fodpr') {
              const senderPubkeyHex = n.senderPubkey;
              if (n.type === 'reply' && replyMap) {
                const replies = replyMap.get(n.targetKey) ?? [];
                interactionEvent = replies.find((e) => CryptoUtils.bytesToHex(e.pubkey) === senderPubkeyHex) ?? null;
              } else if (n.type === 'quote' && links) {
                interactionEvent = links.find((e) => {
                  const qt = quoteTargetOf(e);
                  return qt === n.targetKey && CryptoUtils.bytesToHex(e.pubkey) === senderPubkeyHex;
                }) ?? null;
              } else if (n.type === 'repost' && links) {
                interactionEvent = links.find((e) => {
                  const rt = repostTarget(e);
                  return rt === n.targetKey && quoteTargetOf(e) === null && CryptoUtils.bytesToHex(e.pubkey) === senderPubkeyHex;
                }) ?? null;
              } else if (n.type === 'react' && reactions && links) {
                const reacts = reactions.get(n.targetKey) ?? [];
                const reacted = reacts.find((r) => r.pubkey === senderPubkeyHex);
                if (reacted) {
                  // リアクションイベント自体を探す
                  const reactEvents = links.filter((e) => {
                    const rt = reactionTarget(e);
                    return rt === n.targetKey && CryptoUtils.bytesToHex(e.pubkey) === senderPubkeyHex && eventContentStr(e) === reacted.emoji;
                  });
                  interactionEvent = reactEvents[0] ?? null;
                }
              }
            } else {
              const senderPubkey = n.senderPubkey;
              if (n.type === 'reply' && nostrReplyMap) {
                const replies = nostrReplyMap.get(n.targetKey) ?? [];
                interactionEvent = replies.find((e) => e.pubkey === senderPubkey && firstETagMarker(e) !== 'q') ?? null;
              } else if (n.type === 'quote' && nostrReplyMap) {
                const quotes = nostrReplyMap.get(n.targetKey) ?? [];
                interactionEvent = quotes.find((e) => e.pubkey === senderPubkey && firstETagMarker(e) === 'q') ?? null;
              } else if (n.type === 'repost' && nostrRepostMap) {
                const reposts = nostrRepostMap.get(n.targetKey) ?? [];
                interactionEvent = reposts.find((e) => e.pubkey === senderPubkey) ?? null;
              } else if (n.type === 'react' && nostrReactions) {
                const reacts = nostrReactions.get(n.targetKey) ?? [];
                interactionEvent = reacts.find((e) => e.pubkey === senderPubkey) ?? null;
              }
            }

            return (
              <div key={n.id} className="space-y-2">
                {/* 通知ヘッダー(タップで既読にして対象投稿を開く) */}
                <button
                  onClick={() => {
                    onMarkRead(n.id);
                    onOpenPost(n);
                  }}
                  className={`block w-full rounded-xl border px-3 py-2 text-left text-sm transition-colors ${
                    unread ? 'border-primary/40 bg-primary/5 hover:bg-primary/10' : 'border-white/10 bg-black/20 hover:bg-white/5'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className={'h-2 w-2 shrink-0 rounded-full ' + (unread ? 'bg-primary' : 'bg-transparent')} />
                    <span className="font-medium text-white">{senderName}</span>
                    <span className="text-gray-400"> が </span>
                    <span className="font-medium text-primary">{typeLabel}</span>
                    <span className="text-gray-400"> しました</span>
                    <span className="ml-auto text-xs text-gray-500">{relativeTime(n.createdAt)}</span>
                  </div>
                  <span className="mt-1 block text-xs text-gray-500 hover:underline">
                    {unread ? 'タップして既読にして開く' : 'タップして開く'}
                  </span>
                </button>
                {/* 対象投稿＋インタラクションをスレッド風に表示 */}
                {n.source === 'fodpr' ? (
                  <>
                    <PostCard
                      e={targetPost as FodprEvent}
                      profileMap={profileMap}
                      eventByKey={eventByKey}
                      reactions={reactions!.get(dedupeKey(targetPost as FodprEvent))}
                      selfPubkeyHex={selfPubkeyHex}
                      selfRepostTargets={selfRepostTargets!}
                      onOpenUser={onOpenUser}
                      onReact={onReact}
                      onUndoReact={onUndoReact!}
                      onRepost={onRepost}
                      onUndoRepost={onUndoRepost!}
                      onQuote={onQuote}
                      onReply={onReply}
                      onDelete={onDelete}
                      mentionLookup={mentionLookup}
                    />
                    {interactionEvent && (
                      <div className="ml-3 mt-2 border-l-2 border-primary/30 pl-3 space-y-2">
                        <div className="flex items-center gap-1.5 text-xs text-primary">
                          <ReplyIcon className="h-3 w-3" />
                          <span>上記の投稿への{typeLabel}</span>
                        </div>
                        <PostCard
                          e={interactionEvent as FodprEvent}
                          profileMap={profileMap}
                          eventByKey={eventByKey}
                          reactions={reactions!.get(dedupeKey(interactionEvent as FodprEvent))}
                          selfPubkeyHex={selfPubkeyHex}
                          selfRepostTargets={selfRepostTargets!}
                          onOpenUser={onOpenUser}
                          onReact={onReact}
                          onUndoReact={onUndoReact!}
                          onRepost={onRepost}
                          onUndoRepost={onUndoRepost!}
                          onQuote={onQuote}
                          onReply={onReply}
                          onDelete={onDelete}
                          embedded={true}
                          mentionLookup={mentionLookup}
                        />
                      </div>
                    )}
                  </>
                ) : (
                  <>
                    <NostrNoteCard
                      e={targetPost as NostrEvent}
                      profileMap={nostrProfileMap}
                      reactions={nostrReactions?.get((targetPost as NostrEvent).id)}
                      reposts={nostrReposts?.get((targetPost as NostrEvent).id)}
                      selfPubkeyHex={selfPubkeyHex}
                      loggedIn={!!selfPubkeyHex}
                      onOpenUser={onOpenUser}
                      onReact={onReact}
                      onRepost={onRepost}
                      onQuote={onQuote}
                      onReply={onReply}
                      onDelete={onDelete}
                      noteById={noteById}
                      mentionLookup={nostrMentionLookup}
                    />
                    {interactionEvent && (
                      <div className="ml-3 mt-2 border-l-2 border-primary/30 pl-3 space-y-2">
                        <div className="flex items-center gap-1.5 text-xs text-primary">
                          <ReplyIcon className="h-3 w-3" />
                          <span>上記の投稿への{typeLabel}</span>
                        </div>
                        <NostrNoteCard
                          e={interactionEvent as NostrEvent}
                          profileMap={nostrProfileMap}
                          reactions={nostrReactions?.get((interactionEvent as NostrEvent).id)}
                          reposts={nostrReposts?.get((interactionEvent as NostrEvent).id)}
                          selfPubkeyHex={selfPubkeyHex}
                          loggedIn={!!selfPubkeyHex}
                          onOpenUser={onOpenUser}
                          onReact={onReact}
                          onRepost={onRepost}
                          onQuote={onQuote}
                          onReply={onReply}
                          onDelete={onDelete}
                          noteById={noteById}
                          mentionLookup={nostrMentionLookup}
                        />
                      </div>
                    )}
                  </>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// 通知クリック時に表示する対象投稿のオーバーレイ
function NotifPostViewer({
  post,
  source,
  onClose,
  onOpenUser,
}: {
  post: FodprEvent | NostrEvent;
  source: NotificationSource;
  onClose: () => void;
  onOpenUser: (pubkeyHex: string) => void;
}) {
  const pkHex = source === 'fodpr' ? CryptoUtils.bytesToHex((post as FodprEvent).pubkey) : (post as NostrEvent).pubkey;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-bg/95 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg overflow-hidden rounded-2xl border border-white/15 bg-[#0d1422]/95 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
          <span className="text-sm font-semibold text-white">通知の投稿</span>
          <button
            onClick={onClose}
            aria-label="閉じる"
            title="閉じる"
            className="rounded-full p-1 text-gray-300 transition-colors hover:bg-white/10"
          >
            <CloseIcon className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-3 p-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                onOpenUser(pkHex);
                onClose();
              }}
              className="flex min-w-0 items-center gap-2 text-left"
            >
              <Avatar
                picture={null}
                pubkeyHex={pkHex}
                name={pkHex.slice(0, 7)}
                className="h-10 w-10 text-sm"
              />
              <span className="truncate font-medium text-white">{pkHex.slice(0, 7)}</span>
            </button>
            {source === 'nostr' && (
              <span className="text-xs text-gray-400">{new Date((post as NostrEvent).created_at * 1000).toLocaleString()}</span>
            )}
            {source === 'fodpr' && (
              <span className="text-xs text-gray-400">{new Date((post as FodprEvent).createdAt * 1000).toLocaleString()}</span>
            )}
          </div>
          {source === 'nostr' && (
            <>
              <p className="whitespace-pre-wrap break-words text-gray-100">
                {renderCustomEmojis((post as NostrEvent).content, parseNostrEmojiTags((post as NostrEvent).tags))}
              </p>
              {(post as NostrEvent).kind === 1 &&
                nostrImageUrls(post as NostrEvent).length > 0 &&
                nostrImageUrls(post as NostrEvent).map((img, i) => (
                  <img
                    key={i}
                    src={img.url}
                    alt=""
                    loading="lazy"
                    className="max-h-96 w-auto max-w-full rounded-xl"
                  />
                ))}
            </>
          )}
          {source === 'fodpr' && (
            <>
              <p className="whitespace-pre-wrap break-words text-gray-100">
                {renderCustomEmojis(eventContentStr(post as FodprEvent), parseFodprEmojiTags((post as FodprEvent).tags))}
              </p>
              {(post as FodprEvent).transType === TransTypeBinary &&
                (() => {
                  const media = parseImageContent(eventContentStr(post as FodprEvent));
                  if (!media) return null;
                  return (
                    <img
                      src={`data:${media.mime};base64,${media.base64}`}
                      alt=""
                      loading="lazy"
                      className="max-h-96 w-auto max-w-full rounded-xl"
                    />
                  );
                })()}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const NAV_ITEMS = [
  { id: 'timeline', label: 'タイムライン' },
  { id: 'notifications', label: '通知' },
  { id: 'profile', label: 'プロフィール' },
  { id: 'settings', label: '設定' },
] as const;

type ViewId = (typeof NAV_ITEMS)[number]['id'];

// Nostr タブのナビメニュー(タイムライン + プロフィール + 設定)
const NOSTR_NAV_ITEMS = [
  { id: 'timeline', label: 'タイムライン' },
  { id: 'notifications', label: '通知' },
  { id: 'profile', label: 'プロフィール' },
  { id: 'settings', label: '設定' },
] as const;

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

// メディア投稿の content(<mime>:<base64>)の上限。
// リレーは受信フレーム 16MB を上限としており、超えるフレームは接続切断(または
// 古いビルドではサーバー停止)を引き起こす。base64 は 1.33 倍に膨らむため、
// base64 文字列長で 12MB(実データ約9MB)に制限する。
const MAX_MEDIA_BASE64_LENGTH = 12 * 1024 * 1024;

// data URL が投稿可能な上限を超えているか判定する(超えていればエラーメッセージ)
function mediaTooLargeError(dataUrlLength: number): string | null {
  if (dataUrlLength > MAX_MEDIA_BASE64_LENGTH) {
    return 'メディアが大きすぎます(投稿可能なのは約 9MB まで)。別のファイルを選んでください。';
  }
  return null;
}

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

  // ネットワークタブ(Fodpr / Nostr)
  const [activeTab, setActiveTab] = useState<ProtocolTab>('fodpr');

  // 閲覧のみ(鍵なし)モード。ログイン画面の「閲覧だけする」で入る
  const [guestMode, setGuestMode] = useState(false);

  // Nostr 秘密鍵(nsec)は Fodpr の fsec とは別に保持する
  const [nostrPrivKey, setNostrPrivKey] = useState<string | null>(null);
  // NIP-07: ブラウザ拡張ログイン時の公開鍵(秘密鍵は拡張内に保持され、ここには持たない)
  const [nostrNip07Pubkey, setNostrNip07Pubkey] = useState<string | null>(null);
  // NIP-79 (Nosskey): パスキーの credential ID + 公開鍵。秘密鍵は PRF で再生するので
  // ここには秘密鍵を持たない(再ログインの手がかかりとして credential ID 惰利する)。
   const [nostrPasskeyCred, setNostrPasskeyCred] = useState<NosskeyCred | null>(null);
   const nostrPubkeyHex = useMemo(
     () =>
       nostrPrivKey
         ? getPublicKeyFromSecret(nostrPrivKey)
         : nostrNip07Pubkey ?? '',
     [nostrPrivKey, nostrNip07Pubkey],
   );

   // ログイン方法(nsec / NIP-07 / パスキー)を判定。パスキーでログイン中は nostrPrivKey が
   // メモリにないと分からない(nsec と同じ値を持つ)ため、nostrPasskeyCred がセットされて
   // いるかで区別する。
   const nostrLoginMethod: 'nsec' | 'nip07' | 'passkey' | null = useMemo(
     () =>
       nostrPrivKey
         ? nostrPasskeyCred
           ? 'passkey'
           : 'nsec'
         : nostrNip07Pubkey
           ? 'nip07'
           : null,
     [nostrPrivKey, nostrNip07Pubkey, nostrPasskeyCred],
   );

  // TL 上の Nostr ユーザー名をクリックしたときに開く「他ユーザーのプロフィール」
  const [nostrOpenPubkey, setNostrOpenPubkey] = useState<string | null>(null);

  // 投稿欄(下部コンポーザ)の表示/非表示。設定は localStorage に保存する
  const [composerHidden, setComposerHidden] = useState<boolean>(
    () => localStorage.getItem('fodpr_composer_hidden') === '1',
  );

  // モバイル用の中大モーダル投稿欄(既定は非表示)
  const [mobileComposerOpen, setMobileComposerOpen] = useState(false);
  // 既読通知ID集合(localStorage永続化)
  const [readNotifIds, setReadNotifIds] = useState<Set<string>>(() => loadReadNotifIds());
  // 通知から対象投稿をオーバーレイ表示用
  const [notifPost, setNotifPost] = useState<{ post: FodprEvent | NostrEvent; source: 'fodpr' | 'nostr' } | null>(null);
  const isSm = useIsSm();

  // クライアント実装ドキュメントページを新しいタブで開く
  function openDocs() {
    const url = new URL('docs.html', window.location.href);
    window.open(url.href, '_blank', 'noopener');
  }

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

  // Nostr リレー(複数・Nostr タブの設定画面から変更可能)
  const [nostrRelayUrls, setNostrRelayUrls] = useState<string[]>(loadNostrRelays);
  const nostrRelay = useNostrRelay(nostrRelayUrls);

  // 自分の NIP-65 kind 10002 リレーリスト(取得できた場合のみ)。read/write 送信先の判定に使う
  const [nostrRelayList, setNostrRelayList] = useState<RelayList | null>(null);
  const nostrRelayUrlsKey = nostrRelayUrls.join('\n');

  // ログイン中(nsec または NIP-07)は kind 10002 を取得して読み書きリレーを把握する
  useEffect(() => {
    if (!nostrPubkeyHex) {
      setNostrRelayList(null);
      return;
    }
    const pk = nostrPubkeyHex;
    const urls = nostrRelayUrls.length ? nostrRelayUrls : DEFAULT_NOSTR_RELAYS;
    let cancelled = false;
    fetchNostrRelayList(urls, pk)
      .then((rl) => {
        if (!cancelled) setNostrRelayList(rl);
      })
      .catch(() => {
        if (!cancelled) setNostrRelayList(null);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nostrPubkeyHex, nostrRelayUrlsKey]);

  // 自クライアントの Nostr 投稿を即座にフィードへ反映するためのローカル蓄積(Optimistic)
  const [nostrLocalEvents, setNostrLocalEvents] = useState<NostrEvent[]>([]);

  // Nostr 返信モード中の対象イベント { id, pubkey }
  const [nostrReplyTarget, setNostrReplyTarget] = useState<{ id: string; pubkey: string } | null>(null);

  // Nostr 引用モード中の対象イベント { id, pubkey }(非 null ならコンポーザが引用モード)
  const [nostrQuoteTarget, setNostrQuoteTarget] = useState<{ id: string; pubkey: string } | null>(null);

  // コンポーザ入力
  const [noteText, setNoteText] = useState('');
  const [name, setName] = useState('');
  const [about, setAbout] = useState('');
  const [picture, setPicture] = useState('');

  // 引用リポスト中の対象イベントの dedupeKey(非 null ならコンポーザが引用モード)
  const [quoteTarget, setQuoteTarget] = useState<string | null>(null);

  // リプライ中の対象イベントの dedupeKey(非 null ならコンポーザが返信モード)
  const [replyTarget, setReplyTarget] = useState<string | null>(null);

  // PWA 更新検知用
  const [pwaUpdateAvailable, setPwaUpdateAvailable] = useState(false);
  // 画像タップでのオーバーレイ表示(Fodpr・Nostr 共通)
  const [imageOverlayUrl, setImageOverlayUrl] = useState<string | null>(null);

  // PWA 更新検知
  // - sw.js は install 時に skipWaiting するため、新 SW が適用されると
  //   controllerchange が発生する。初回の claim(初めてコントロールされた時)は
  //   「更新」ではないので誤判定しない。
  // - 起動時と 60 秒ごとに reg.update() で新バージョンを確認する。
  useEffect(() => {
    if (!('serviceWorker' in navigator)) return;
    let hadController = !!navigator.serviceWorker.controller;
    const onControllerChange = () => {
      if (hadController) setPwaUpdateAvailable(true);
      hadController = true;
    };
    navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);
    const checkUpdate = () => {
      navigator.serviceWorker
        .getRegistrations()
        .then((regs) => {
          for (const reg of regs) reg.update().catch(() => {});
        })
        .catch(() => {});
    };
    checkUpdate();
    const timer = window.setInterval(checkUpdate, 60_000);
    return () => {
      navigator.serviceWorker.removeEventListener('controllerchange', onControllerChange);
      window.clearInterval(timer);
    };
  }, []);

  // PWA 更新適用
  function applyPwaUpdate() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistrations().then((regs) => {
        regs.forEach((reg) => reg.unregister());
      });
      window.location.reload();
    }
  }

  // ────────────────────────────────────────────────────────────────────────
  // ブラウザ通知(Notification API)
  // 自分の投稿へ新着返信/リアクション/リポスト/引用が来たら、タブが背面のときに
  // OS の通知枠でお知らせする。設定でオン/オフし、localStorage に保存する。
  // ────────────────────────────────────────────────────────────────────────
  const [browserNotifEnabled, setBrowserNotifEnabled] = useState<boolean>(() => {
    try {
      return localStorage.getItem(BROWSER_NOTIF_STORAGE_KEY) === '1';
    } catch {
      return false;
    }
  });
  const [notifPermission, setNotifPermission] = useState<NotificationPermission>(
    () => (typeof Notification !== 'undefined' ? Notification.permission : 'default'),
  );
  // バーンダウン防止: 一度ブラウザ通知を飛ばした通知 id を記憶する。
   // ページリロード後も再通知しないよう localStorage へ永続化する。
   const notifiedIdsRef = useRef<Set<string>>(loadNotifiedIds());

   // ブラウザ通知の基準時刻。ページを開いた瞬間以降に作成された通知だけを
   // OS 通知として飛ばし、起動時一括取得で届く過去の通知は飛ばさない。
const notifWatermarkRef = useRef(Math.floor(Date.now() / 1000));

    // ────────────────────────────────────────────────────────────────────────
    // 統合ネットワーク層 (F2F / Relay / RtcGroup)
    // ────────────────────────────────────────────────────────────────────────
    const [networkMode, setNetworkMode] = useState<NetworkMode>(() => {
      try {
        return (localStorage.getItem(NETWORK_MODE_STORAGE_KEY) as NetworkMode) || 'relay';
      } catch {
        return 'relay';
      }
    });
    const [networkPeerCount, setNetworkPeerCount] = useState(0);
    const [networkGroups, setNetworkGroups] = useState<(F2FGroupInfo | RtcGroupInfo)[]>([]);
    const [networkLastError, setNetworkLastError] = useState<string | null>(null);
    const [networkSeedNodes, setNetworkSeedNodes] = useState<F2FPeerInfo[]>([]);
    const [networkBootstrapDone, setNetworkBootstrapDone] = useState(false);
    const [invitationCode, setInvitationCode] = useState<string | null>(null);

    const networkManagerRef = useRef<NetworkManager | null>(null);

    function setNetworkModePersisted(next: NetworkMode) {
      setNetworkMode(next);
      try {
        localStorage.setItem(NETWORK_MODE_STORAGE_KEY, next);
      } catch {
        /* ignore */
      }
    }

    useEffect(() => {
      const mgr = createNetworkManager({
        mode: networkMode,
        privKeyHex: privKey ?? '',
        relayClients: Array.from(relay.clients.values()),
        seedRelayUrl: relayUrls[0],
      });

      mgr.onEvent = (ev) => {
        if (ev.type === 'peer_connected' || ev.type === 'peer_disconnected') {
          setNetworkPeerCount(mgr.getPeerCount());
        } else if (ev.type === 'group_updated' || ev.type === 'group_joined') {
          setNetworkGroups(mgr.getGroups());
        } else if (ev.type === 'seed_nodes') {
          setNetworkSeedNodes(ev.nodes);
        } else if (ev.type === 'error') {
          setNetworkLastError(ev.message);
        }
      };

      networkManagerRef.current = mgr;
      setNetworkPeerCount(mgr.getPeerCount());
      setNetworkGroups(mgr.getGroups());
      setInvitationCode(null);

      return () => {
        mgr.close();
      };
    }, [networkMode, privKey, relayUrlsKey]);

    async function handleNetworkBootstrap() {
      const mgr = networkManagerRef.current;
      if (!mgr || networkMode !== 'f2f') return;
      // F2FManager の bootstrap を呼ぶには cast が必要
      const f2fMgr = mgr as any;
      if (typeof f2fMgr.bootstrap === 'function') {
        setNetworkBootstrapDone(false);
        const ok = await f2fMgr.bootstrap();
        if (ok) setNetworkBootstrapDone(true);
      }
    }

    async function handleNetworkCreateGroup() {
      const mgr = networkManagerRef.current;
      if (!mgr) return;
      if (networkMode === 'f2f') {
        const f2fMgr = mgr as any;
        if (typeof f2fMgr.createGroup === 'function') {
          const group = f2fMgr.createGroup();
          setNetworkGroups(mgr.getGroups());
          setNetworkLastError(null);
          return group;
        }
      } else if (networkMode === 'rtcgroup') {
        const rtgMgr = mgr as any;
        if (typeof rtgMgr.createGroup === 'function') {
          const group = rtgMgr.createGroup();
          setNetworkGroups(mgr.getGroups());
          setNetworkLastError(null);
          return group;
        }
      }
    }

    async function handleNetworkJoinGroup(groupId: string) {
      const mgr = networkManagerRef.current;
      if (!mgr || networkMode !== 'rtcgroup') return;
      const rtgMgr = mgr as any;
      if (typeof rtgMgr.joinGroup === 'function') {
        const group = rtgMgr.joinGroup(groupId);
        setNetworkGroups(mgr.getGroups());
        setNetworkLastError(null);
        return group;
      }
    }

    async function handleNetworkCreateInvitation() {
      const mgr = networkManagerRef.current;
      if (!mgr || networkMode !== 'f2f') return;
      const f2fMgr = mgr as any;
      if (typeof f2fMgr.createInvitation === 'function') {
        const code = await f2fMgr.createInvitation();
        setInvitationCode(code);
      }
    }

    async function handleNetworkConnectInvitation(code: string) {
      const mgr = networkManagerRef.current;
      if (!mgr || networkMode !== 'f2f') return;
      const f2fMgr = mgr as any;
      if (typeof f2fMgr.connectWithInvitation === 'function') {
        await f2fMgr.connectWithInvitation(code);
      }
    }

   // ミュート中の pubkey(Fodpr / Nostr 共通、localStorage 永続化)
   const [mutedPubkeys, setMutedPubkeys] = useState<Set<string>>(loadMutedPubkeys);
   function toggleMute(pubkeyHex: string) {
     setMutedPubkeys((prev) => {
       const next = new Set(prev);
       if (next.has(pubkeyHex)) next.delete(pubkeyHex);
       else next.add(pubkeyHex);
       saveMutedPubkeys(next);
       return next;
     });
   }

   // 設定でオンにしたタイミングで権限をリクエストする
   function setBrowserNotifsEnabled(next: boolean) {
     setBrowserNotifEnabled(next);
     try {
       localStorage.setItem(BROWSER_NOTIF_STORAGE_KEY, next ? '1' : '0');
     } catch {
       /* ignore */
     }
   }

   async function requestNotificationPermission() {
     if (typeof Notification === 'undefined') return;
     const p = await Notification.requestPermission();
     setNotifPermission(p);
     if (p === 'granted') setBrowserNotifsEnabled(true);
     else setBrowserNotifEnabled(false);
   }

   // ページロード直後に権限状況を同期(ユーザーがブラウザ設定で許可していた場合も反映)
   useEffect(() => {
     if (typeof Notification === 'undefined') return;
     setNotifPermission(Notification.permission);
     if (Notification.permission === 'granted' && !browserNotifEnabled) setBrowserNotifsEnabled(true);
     // eslint-disable-next-line react-hooks/exhaustive-deps
   }, []);


  // 画像/動画/ファイル投稿(Binary)用の添付状態
  const [mediaDataUrl, setMediaDataUrl] = useState<string | null>(null);
  const [mediaName, setMediaName] = useState<string | null>(null);
  const [mediaSize, setMediaSize] = useState(0);
  const [mediaError, setMediaError] = useState<string | null>(null);
  const [mediaType, setMediaType] = useState<'image' | 'video' | 'file' | null>(null);
  const [mediaThumbnail, setMediaThumbnail] = useState<string | null>(null);

  // 自クライアントの投稿を即座にフィードに反映するためのローカル蓄積(Optimistic)
  const [localEvents, setLocalEvents] = useState<FodprEvent[]>([]);

  // 削除済みイベントの dedupeKey 集合。削除後もリレーが過去の PUSH を保持するため、
  // 受信済みイベントもここで非表示にする(Optimistic 削除を永続化する)。
  const [deletedKeys, setDeletedKeys] = useState<Set<string>>(new Set());

  // 起動時: 暗号化された秘密鍵(Fodpr fsec / Nostr nsec)を復号して自動ログインする
  // (Fodpr は旧平文保存からの移行も行う)
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

      let nhex: string | null = null;
      try {
        nhex = await loadNostrSecret();
      } catch {
        nhex = null;
      }
      if (cancelled) return;
      if (nhex && /^[0-9a-f]{64}$/i.test(nhex)) {
        try {
          getPublicKeyFromSecret(nhex); // 不正な鍵はログインしない
          setNostrPrivKey(nhex);
          // fsec なし + nsec のみでゲストモードに入っていた場合、リロード後も復元する
          if (!hex && localStorage.getItem(NOSTR_GUEST_STORAGE_KEY) === '1') {
            setGuestMode(true);
            setActiveTab('nostr');
          }
        } catch {
          setNostrPrivKey(null);
        }
      }

       // NIP-07 でログインしていた場合、公開鍵だけを復元する(鍵は拡張内に保持されている)
      if (!nhex) {
        try {
          const nip07 = localStorage.getItem(NIP07_PUBKEY_STORAGE_KEY);
          if (nip07 && /^[0-9a-f]{64}$/i.test(nip07)) {
            setNostrNip07Pubkey(nip07);
            if (!hex && localStorage.getItem(NOSTR_GUEST_STORAGE_KEY) === '1') {
              setGuestMode(true);
              setActiveTab('nostr');
            }
          }
        } catch {
          /* 無視 */
        }
      }

      // NIP-79 (Nosskey) パスキーが登録済みなら credential ID + 公開鍵を復元する。
      // 秘密鍵は復元できない(ログイン画面で再照認)ため、ここでは credential 情報だけ保持する。
      try {
        const cred = localStorage.getItem(NOSSKEY_CRED_STORAGE_KEY);
        if (cred) {
          const parsed = JSON.parse(cred) as NosskeyCred;
          if (parsed.credId && /^[0-9a-f]{64}$/i.test(parsed.pubkey)) {
            setNostrPasskeyCred(parsed);
          }
        }
      } catch {
        /* 無視 */
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

  // サーバー受信 + 自投稿をマージ(重複排除)してフィードのソースにする。
  // 削除済みのイベントはここで除外する。
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
    return merged.filter((e) => !deletedKeys.has(dedupeKey(e)));
  }, [receivedEvents, localEvents, deletedKeys]);

  const { profiles, notes, binaries, reactions, replies, links, others } = useMemo(
    () => splitEvents(allEvents),
    [allEvents],
  );
  const profileMap = useMemo(() => latestProfilePerPubkey(profiles), [profiles]);

  // プロフィールフォームの初期値: 保存済みプロフィールがあれば初回に反映する
  // (リロード後も名前・自己紹介・画像が空にならないようにする)
  useEffect(() => {
    if (!privKey) return;
    const self = profileMap[pubkeyHex];
    if (!self) return;
    const p = parseProfile(eventContentStr(self));
    if (!name && !about && !picture) {
      setName(p.name ?? '');
      setAbout(p.about ?? '');
      setPicture(p.picture ?? '');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profileMap, privKey, pubkeyHex]);

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
      if (!key || !eventContentStr(e).trim()) continue;
      const list = m.get(key) ?? [];
      list.push({ emoji: eventContentStr(e), pubkey: CryptoUtils.bytesToHex(e.pubkey), createdAt: e.createdAt });
      m.set(key, list);
    }
    return m;
  }, [reactions]);

  // リプライを対象イベントの dedupeKey ごとにまとめる
  const replyMap: ReplyMap = useMemo(() => {
    const m: ReplyMap = new Map();
    for (const e of replies) {
      const key = replyTag(e);
      if (!key) continue;
      const list = m.get(key) ?? [];
      list.push(e);
      m.set(key, list);
    }
    return m;
  }, [replies]);

  // 自分が投稿したリアクションイベントを対象の dedupeKey ごとにまとめる(取り消し用)
  const selfReactionEventsByKey = useMemo(() => {
    const m = new Map<string, FodprEvent[]>();
    for (const e of reactions) {
      const key = reactionTarget(e);
      if (!key) continue;
      if (CryptoUtils.bytesToHex(e.pubkey) !== pubkeyHex) continue;
      const list = m.get(key) ?? [];
      list.push(e);
      m.set(key, list);
    }
    return m;
  }, [reactions, pubkeyHex]);

  // 自分がリポストした対象の dedupeKey 集合(取り消し表示用)
  const selfRepostTargets = useMemo(() => {
    const s = new Set<string>();
    for (const e of links) {
      const t = repostTarget(e);
      if (t && quoteTargetOf(e) === null && CryptoUtils.bytesToHex(e.pubkey) === pubkeyHex) s.add(t);
    }
    return s;
  }, [links, pubkeyHex]);

  // Fodpr の @メンションを @名前/@hex から pubkey へ解決する lookup
  const mentionLookup = useMemo(() => buildMentionLookup(mentionUsers(profileMap)), [profileMap]);

  // ────────────────────────────────────────────────────────────────────────
  // Nostr タブのイベント導出
  // ────────────────────────────────────────────────────────────────────────
  const nostrReceivedEvents = useMemo(
    () =>
      nostrRelay.messages.filter(
        (m): m is Extract<typeof m, { kind: 'event' }> => m.kind === 'event',
      ).map((m) => m.event),
    [nostrRelay.messages],
  );

  // サーバー受信 + 自投稿(Optimistic)を id で重複排除する
  const nostrAllEvents = useMemo(() => {
    const seen = new Set<string>();
    const merged: NostrEvent[] = [];
    for (const e of nostrReceivedEvents) {
      if (seen.has(e.id)) continue;
      seen.add(e.id);
      merged.push(e);
    }
    for (const e of nostrLocalEvents) {
      if (seen.has(e.id)) continue;
      seen.add(e.id);
      merged.push(e);
    }
    return merged;
  }, [nostrReceivedEvents, nostrLocalEvents]);

  // kind 5 削除要求で指定されたイベント id(表示時に除外する)
  const nostrDeletedIds = useMemo(() => {
    const s = new Set<string>();
    for (const e of nostrAllEvents) {
      if (e.kind !== 5) continue;
      for (const t of e.tags) {
        if (t[0] === 'e' && typeof t[1] === 'string' && t[1]) s.add(t[1]);
      }
    }
    return s;
  }, [nostrAllEvents]);

  // pubkey → 最新の kind 0(プロフィール)
  const nostrProfileMap = useMemo(() => {
    const m: Record<string, NostrEvent> = {};
    for (const e of nostrAllEvents) {
      if (e.kind !== 0) continue;
      const prev = m[e.pubkey];
      if (!prev || e.created_at > prev.created_at) m[e.pubkey] = e;
    }
    return m;
  }, [nostrAllEvents]);

  // kind 1(削除済みは除く)
  const nostrNotes = useMemo(
    () => nostrAllEvents.filter((e) => e.kind === 1 && !nostrDeletedIds.has(e.id)),
    [nostrAllEvents, nostrDeletedIds],
  );

  // Nostr の @メンションを @名前/@hex/@npub から pubkey へ解決する lookup
  const nostrMentionLookup = useMemo(() => buildNostrMentionLookup(nostrProfileMap), [nostrProfileMap]);

  // インラインノート参照(nostr:note1...)のプレビュー用: id → イベントの引きテーブル
  const nostrNoteById = useMemo(
    () => Object.fromEntries(nostrNotes.map((n) => [n.id, n])),
    [nostrNotes],
  );

  // kind 7 リアクション / kind 6 リポスト / kind 1 リプライを対象イベント id ごとに束ねる
  // (kind 5 で削除されたイベントは集計から除外する)
  const nostrReactionMap = useMemo(() => {
    const m = new Map<string, NostrEvent[]>();
    for (const e of nostrAllEvents) {
      if (e.kind !== 7 || nostrDeletedIds.has(e.id)) continue;
      const tid = firstETag(e);
      if (!tid) continue;
      const list = m.get(tid) ?? [];
      list.push(e);
      m.set(tid, list);
    }
    return m;
  }, [nostrAllEvents, nostrDeletedIds]);

  const nostrRepostMap = useMemo(() => {
    const m = new Map<string, NostrEvent[]>();
    for (const e of nostrAllEvents) {
      if (e.kind !== 6 || nostrDeletedIds.has(e.id)) continue;
      const tid = firstETag(e);
      if (!tid) continue;
      const list = m.get(tid) ?? [];
      list.push(e);
      m.set(tid, list);
    }
    return m;
  }, [nostrAllEvents, nostrDeletedIds]);

  const nostrReplyMap = useMemo(() => {
    const m = new Map<string, NostrEvent[]>();
    for (const e of nostrAllEvents) {
      if (e.kind !== 1 || nostrDeletedIds.has(e.id)) continue;
      const tid = firstETag(e);
      if (!tid) continue;
      const list = m.get(tid) ?? [];
      list.push(e);
      m.set(tid, list);
    }
    return m;
  }, [nostrAllEvents, nostrDeletedIds]);

  // ────────────────────────────────────────────────────────────────────────
  // 通知の導出
  // 自分の投稿(Fodpr=dedupeKey / Nostr=note id)を対象にした
  // リアクション・返信・リポスト・引用を通知として組み立てる。
  // ────────────────────────────────────────────────────────────────────────
  // 自分の Fodpr 投稿の dedupeKey 集合
  const myFodprKeys = useMemo(() => {
    const s = new Set<string>();
    if (!pubkeyHex) return s;
    for (const e of allEvents) {
      if (CryptoUtils.bytesToHex(e.pubkey) === pubkeyHex) {
        if (e.transType === TransTypeJSON) {
          try {
        const obj = JSON.parse(eventContentStr(e));
            if (obj?.mode === 'profile') continue;
          } catch {
            /* profile 判定失敗は投稿として扱う */
          }
        }
        s.add(dedupeKey(e));
      }
    }
    return s;
  }, [allEvents, pubkeyHex]);

  // 自分の Nostr 投稿(kind 1)のイベント id 集合
  const myNostrNoteIds = useMemo(() => {
    const s = new Set<string>();
    if (!nostrPubkeyHex) return s;
    for (const e of nostrAllEvents) {
      if (e.kind === 1 && e.pubkey === nostrPubkeyHex) s.add(e.id);
    }
    return s;
  }, [nostrAllEvents, nostrPubkeyHex]);

  // 通知一覧(最新順)
  const notifications = useMemo<Notification[]>(() => {
    const out: Notification[] = [];
    // Fodpr: リアクション
    for (const [targetKey, items] of reactionMap) {
      if (!myFodprKeys.has(targetKey)) continue;
      for (const r of items) {
        if (r.pubkey === pubkeyHex) continue;
        out.push({
          id: `f:react:${targetKey}:${r.pubkey}:${r.emoji}`,
          source: 'fodpr',
          type: 'react',
          senderPubkey: r.pubkey,
          targetKey,
          createdAt: r.createdAt,
        });
      }
    }
    // Fodpr: 返信
    for (const [targetKey, list] of replyMap) {
      if (!myFodprKeys.has(targetKey)) continue;
      for (const e of list) {
        const pk = CryptoUtils.bytesToHex(e.pubkey);
        if (pk === pubkeyHex) continue;
        out.push({
          id: `f:reply:${targetKey}:${dedupeKey(e)}`,
          source: 'fodpr',
          type: 'reply',
          senderPubkey: pk,
          targetKey,
          createdAt: e.createdAt,
        });
      }
    }
    // Fodpr: リポスト/引用
    for (const e of links) {
      const t = repostTarget(e);
      if (!t || !myFodprKeys.has(t)) continue;
      const pk = CryptoUtils.bytesToHex(e.pubkey);
      if (pk === pubkeyHex) continue;
      const isQuote = quoteTargetOf(e) !== null;
      out.push({
        id: `f:${isQuote ? 'quote' : 'repost'}:${t}:${dedupeKey(e)}`,
        source: 'fodpr',
        type: isQuote ? 'quote' : 'repost',
        senderPubkey: pk,
        targetKey: t,
        createdAt: e.createdAt,
      });
    }
    // Fodpr: メンション(mention:<自分のpubkey> タグ付きの投稿)
    for (const e of allEvents) {
      const pk = CryptoUtils.bytesToHex(e.pubkey);
      if (pk === pubkeyHex) continue;
      if (e.transType === TransTypeJSON) continue;
      if (!mentionTagOf(e).includes(pubkeyHex)) continue;
      const key = dedupeKey(e);
      if (myFodprKeys.has(key)) continue;
      out.push({
        id: `f:mention:${key}:${pubkeyHex}`,
        source: 'fodpr',
        type: 'mention',
        senderPubkey: pk,
        targetKey: key,
        createdAt: e.createdAt,
      });
    }
    // Nostr: リアクション(kind 7)
    for (const [targetId, list] of nostrReactionMap) {
      if (!myNostrNoteIds.has(targetId)) continue;
      for (const e of list) {
        if (e.pubkey === nostrPubkeyHex) continue;
        out.push({
          id: `n:react:${targetId}:${e.id}`,
          source: 'nostr',
          type: 'react',
          senderPubkey: e.pubkey,
          targetKey: targetId,
          createdAt: e.created_at,
        });
      }
    }
    // Nostr: 返信/引用(kind 1、marker='q' は引用)
    for (const [targetId, list] of nostrReplyMap) {
      if (!myNostrNoteIds.has(targetId)) continue;
      for (const e of list) {
        if (e.pubkey === nostrPubkeyHex) continue;
        const isQuote = firstETagMarker(e) === 'q';
        out.push({
          id: `n:${isQuote ? 'quote' : 'reply'}:${targetId}:${e.id}`,
          source: 'nostr',
          type: isQuote ? 'quote' : 'reply',
          senderPubkey: e.pubkey,
          targetKey: targetId,
          createdAt: e.created_at,
        });
      }
    }
    // Nostr: リポスト(kind 6)
    for (const [targetId, list] of nostrRepostMap) {
      if (!myNostrNoteIds.has(targetId)) continue;
      for (const e of list) {
        if (e.pubkey === nostrPubkeyHex) continue;
        out.push({
          id: `n:repost:${targetId}:${e.id}`,
          source: 'nostr',
          type: 'repost',
          senderPubkey: e.pubkey,
          targetKey: targetId,
          createdAt: e.created_at,
        });
      }
    }
    // Nostr: メンション(kind 1 の p タグに自分が含まれる投稿)
    if (nostrPubkeyHex) {
      for (const e of nostrAllEvents) {
        if (e.kind !== 1 || nostrDeletedIds.has(e.id)) continue;
        if (e.pubkey === nostrPubkeyHex) continue;
        const hasP = e.tags.some((t) => t[0] === 'p' && t[1] === nostrPubkeyHex);
        if (!hasP) continue;
        if (myNostrNoteIds.has(e.id)) continue;
        out.push({
          id: `n:mention:${e.id}:${nostrPubkeyHex}`,
          source: 'nostr',
          type: 'mention',
          senderPubkey: e.pubkey,
          targetKey: e.id,
          createdAt: e.created_at,
        });
      }
    }
    // ミュート中のユーザーからの通知は表示しない
    return sortByCreatedAt(out.filter((n) => !mutedPubkeys.has(n.senderPubkey)));
  }, [
    reactionMap,
    replyMap,
    links,
    allEvents,
    myFodprKeys,
    myNostrNoteIds,
    nostrReactionMap,
    nostrReplyMap,
    nostrRepostMap,
    pubkeyHex,
    nostrPubkeyHex,
    mutedPubkeys,
  ]);

  // Fodpr 側 / Nostr 側それぞれの通知。各ネットワークのタブでは自分の側の通知だけを表示する
  const fodprNotifications = useMemo(
    () => notifications.filter((n) => n.source === 'fodpr'),
    [notifications],
  );
  const nostrNotifications = useMemo(
    () => notifications.filter((n) => n.source === 'nostr'),
    [notifications],
  );
  const activeNotifications = activeTab === 'fodpr' ? fodprNotifications : nostrNotifications;

  // 各ネットワークの未読通知数(ナビの「通知」にバッジ表示する)
  const unreadCountByTab = {
    fodpr: fodprNotifications.filter((n) => !readNotifIds.has(n.id)).length,
    nostr: nostrNotifications.filter((n) => !readNotifIds.has(n.id)).length,
  };

  // 通知種別の日本語ラベル
  const typeLabels: Record<NotificationType, string> = {
    react: 'リアクション',
    reply: '返信',
    repost: 'リポスト',
    quote: '引用',
    mention: 'メンション',
  };

  // 新着未読通知が来たらブラウザ通知を飛ばす(タブが背面のとき重点的に)
  useEffect(() => {
    if (!browserNotifEnabled || notifPermission !== 'granted') return;
    const seen = notifiedIdsRef.current;
    let fired = false;
    let changed = false;
    for (const n of notifications) {
      if (seen.has(n.id)) continue;
      // 一度飛ばした/既読でも id は記憶して再通知しない
      seen.add(n.id);
      changed = true;
      // 起動時など一括取得で届いた過去の通知(ページを開く前に作成されたもの)は飛ばさない
      if (n.createdAt > 0 && n.createdAt < notifWatermarkRef.current) continue;
      // 未読かつ最前面で通知タブを開いていない場合のみ飛ばす
      let shouldFire = false;
      if (!readNotifIds.has(n.id)) {
        const onNotifView =
          view === 'notifications' && activeTab === (n.source === 'fodpr' ? 'fodpr' : 'nostr');
        shouldFire = document.hidden || !onNotifView;
      }
      if (!shouldFire) continue;
      const name =
        n.source === 'fodpr'
          ? resolveDisplayName(n.senderPubkey, profileMap)
          : nostrDisplayName(n.senderPubkey, nostrProfileMap);
      try {
        new Notification(n.source === 'fodpr' ? 'Fodpr 通知' : 'Nostr 通知', {
          body: `${name} が${typeLabels[n.type]}しました`,
          tag: n.id,
          icon: '/icon-192.png',
        });
        fired = true;
      } catch {
        /* ignore */
      }
    }
    // 永続化(サイズが大きくなりすぎないよう古いものをトリム)
    if (changed) {
      const arr = Array.from(seen);
      if (arr.length > 1000) {
        for (const id of arr.slice(0, arr.length - 1000)) seen.delete(id);
      }
      try {
        localStorage.setItem(NOTIF_NOTIFIED_STORAGE_KEY, JSON.stringify(Array.from(seen)));
      } catch {
        /* ignore */
      }
    }
    // 一度でも通知を飛ばしたなら未読バッジ数を更新
    if (fired && typeof navigator !== 'undefined' && 'setAppBadge' in navigator) {
      try {
        void (navigator as any).setAppBadge(
          notifications.filter((n) => !readNotifIds.has(n.id)).length || 1,
        );
      } catch {
        /* ignore */
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [notifications, browserNotifEnabled, notifPermission, readNotifIds, view, activeTab]);

  // 通知を既読にする(タップ/クリック時)
  function markRead(id: string) {
    setReadNotifIds((prev) => {
      const next = new Set(prev);
      next.add(id);
      saveReadNotifIds(next);
      return next;
    });
  }

  // すべて既読にする(表示中のネットワーク側の通知のみ)
  function markAllRead() {
    setReadNotifIds((prev) => {
      const next = new Set(prev);
      for (const n of activeNotifications) next.add(n.id);
      saveReadNotifIds(next);
      return next;
    });
  }

  // 通知から対象投稿を開く(NotifPostViewer オーバーレイ)
  function openNotificationPost(n: Notification) {
    if (n.source === 'fodpr') {
      const post = eventByKey.get(n.targetKey);
      if (post) setNotifPost({ post, source: 'fodpr' });
    } else {
      const post = nostrAllEvents.find((e) => e.id === n.targetKey);
      if (post) setNotifPost({ post, source: 'nostr' });
    }
  }

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

  // ────────────────────────────────────────────────────────────────────────
  // 削除の他端末への反映
  // リレーは DEL を購読者へブロードキャストしないため、定期的に REQ(All) を
  // 張り直して「以前にあったのに今は無いイベント = 他端末で削除された」を検出する。
  // ────────────────────────────────────────────────────────────────────────
  const knownKeysRef = useRef<Set<string>>(new Set());
  const liveKeysRef = useRef<Set<string>>(new Set());
  const syncSubRef = useRef<string | null>(null);
  const localEventsRef = useRef<FodprEvent[]>([]);
  // relay.messages は React 18 の自動バッチングで1回のコミットに複数のメッセージが
  // まとめられることがあるため、前回効果を処理してから到達したインデックスを保持して
  // 逐一すべてのメッセージを走査する(直近1件のみ見るとイベントが見落とされる)
  const syncMsgIdxRef = useRef(0);
  useEffect(() => {
    localEventsRef.current = localEvents;
  }, [localEvents]);

  // 受信・自投稿イベントを「これまでに見た鍵」へ記録する
  useEffect(() => {
    const seen = knownKeysRef.current;
    for (const e of receivedEvents) seen.add(dedupeKey(e));
    for (const e of localEvents) seen.add(dedupeKey(e));
  }, [receivedEvents, localEvents]);

  function startSyncReq() {
    if (!relay.connected) return;
    if (syncSubRef.current) return;
    const subId = 'sync_' + Date.now();
    syncSubRef.current = subId;
    liveKeysRef.current = new Set();
    try {
      relay.sendReq({ subId, transType: TransTypeAll, tagKey: '', tagVal: '' });
    } catch {
      syncSubRef.current = null;
    }
  }

  // 接続直後(5秒後)と定期的(30秒ごと)に再同期して他端末の削除を反映する
  useEffect(() => {
    if (!relay.connected) return;
    const t = setTimeout(startSyncReq, 5000);
    return () => clearTimeout(t);
  }, [relay.connected]);
  useEffect(() => {
    const t = setInterval(startSyncReq, 30000);
    return () => clearInterval(t);
  }, [relay.connected]);

  // EOE を受け取ったら「既知 − 現在生きている鍵」= 削除済みを deletedKeys へ加える
  useEffect(() => {
    const msgs = relay.messages;
    const syncId = syncSubRef.current;
    // 前回この効果が走った時点からの新規メッセージをすべて処理する(バッチによる途中経過の吸過)
    for (let i = syncMsgIdxRef.current; i < msgs.length; i++) {
      const m = msgs[i];
      if (!syncId) break;
      if (m.kind === 'event' && m.subId === syncId) {
        liveKeysRef.current.add(dedupeKey(m.event));
      } else if (
        m.kind === 'text' &&
        m.text.startsWith('EOE:') &&
        m.text.includes(syncId)
      ) {
        const live = liveKeysRef.current;
        for (const e of localEventsRef.current) live.add(dedupeKey(e));
        const deleted = new Set<string>();
        for (const k of knownKeysRef.current) {
          if (!live.has(k)) deleted.add(k);
        }
        if (deleted.size > 0) {
          setDeletedKeys((prev) => {
            const next = new Set(prev);
            for (const k of deleted) next.add(k);
            return next;
          });
        }
        knownKeysRef.current = live;
        liveKeysRef.current = new Set();
        syncSubRef.current = null;
        // この EOE でサブスクリプションは終了したので、それ以降のメッセージは
        // 次の sync 用に無視してカーソルだけ進める
        break;
      }
    }
    syncMsgIdxRef.current = msgs.length;
  }, [relay.messages]);

  // Nostr リレー接続後に kind 0/1/5/6/7 を購読する。
  // NIP-65 の read マーカーがあれば read リレーだけから読み込む。
  // 初回は直近ウィンドウを小さく取得して UI を早く立ち上げ、その後に過去分を
  // 時間ウィンドウごとに分割して段階取得する。1 回の REQ で大量イベント
  // (limit 10000 相当)が一気に届くのを避けるため、ウィンドウごとに少し間隔を開ける。
  useEffect(() => {
    if (!nostrRelay.connected) return;
    const readTargets =
      nostrRelayList && (nostrRelayList.read.length > 0 || nostrRelayList.both.length > 0)
        ? [...nostrRelayList.read, ...nostrRelayList.both]
        : null;
    const send = (subId: string, filters: Record<string, unknown>[]) => {
      try {
        if (readTargets) {
          nostrRelay.sendReqTo(readTargets, subId, filters);
        } else {
          nostrRelay.sendReq(subId, filters);
        }
      } catch {
        /* 未接続中は無視 */
      }
    };
    const now = Math.floor(Date.now() / 1000);
    const DAY = 86400;
    // [since, until] の時間ウィンドウ。先頭ほど優先(直近ほど先に取得する)
    const windows: { since: number; until: number | null; limit: number }[] = [
      { since: now - 7 * DAY, until: null, limit: 800 },
      { since: now - 30 * DAY, until: now - 7 * DAY, limit: 1000 },
      { since: now - 180 * DAY, until: now - 30 * DAY, limit: 1500 },
      { since: 0, until: now - 180 * DAY, limit: 2000 },
    ];
    const base = 'nostr_main_' + Date.now();
    const timers: number[] = [];
    windows.forEach((w, i) => {
      timers.push(
        window.setTimeout(() => {
          const filters: Record<string, unknown>[] = [{ kinds: [0, 1, 5, 6, 7] }];
          if (w.since > 0) filters[0].since = w.since;
          if (w.until) filters[0].until = w.until;
          filters[0].limit = w.limit;
          send(base + '_' + i, filters);
        }, 300 + i * 900),
      );
    });
    return () => {
      for (const t of timers) clearTimeout(t);
    };
  }, [nostrRelay.connected, nostrRelay.sendReq, nostrRelay.sendReqTo, nostrRelayList]);

  // emoemo(koteitan さんの NIP-30 絵文字マネージャ)対応:
  // kind 30030(絵文字パック)と、ログイン中なら自分の kind 10030(マイ絵文字リスト)を取得する。
  useEffect(() => {
    if (!nostrRelay.connected) return;
    const t = setTimeout(() => {
      const filters: Record<string, unknown>[] = [{ kinds: [30030], limit: 200 }];
      if (nostrPubkeyHex) filters.push({ kinds: [10030], authors: [nostrPubkeyHex] });
      const readTargets =
        nostrRelayList && (nostrRelayList.read.length > 0 || nostrRelayList.both.length > 0)
          ? [...nostrRelayList.read, ...nostrRelayList.both]
          : null;
      try {
        if (readTargets) {
          nostrRelay.sendReqTo(readTargets, 'nostr_emoemo_' + Date.now(), filters);
        } else {
          nostrRelay.sendReq('nostr_emoemo_' + Date.now(), filters);
        }
      } catch {
        /* 未接続中は無視 */
      }
    }, 400);
    return () => clearTimeout(t);
  }, [nostrRelay.connected, nostrRelay.sendReq, nostrRelay.sendReqTo, nostrRelayList, nostrPubkeyHex]);

  // emoemo から取得した絵文字をレジストリへ登録し、ピッカー表示用 state にも反映する
  const [externalEmojis, setExternalEmojis] = useState<CustomEmojiDef[]>([]);
  useEffect(() => {
    const defs = parseEmoemoEvents(nostrAllEvents);
    clearExternalEmojis();
    for (const d of defs) registerExternalEmoji(d);
    setExternalEmojis(defs);
  }, [nostrAllEvents]);

  // ピッカー用一覧(ビルトイン + emoemo)。externalEmojis の更新時に作り直す
  const pickerEmojis = useMemo(() => allEmojis(), [externalEmojis]);

  // タイムラインに登場した pubkey の kind 0(プロフィール)を未取得分だけ取得する。
  // メイン購読の limit で kind 0 が取り切れないことがあるため、authors 指定で補完する。
  const nostrProfileRequestedRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    if (!nostrRelay.connected) return;
    if (nostrAllEvents.length === 0) return;
    const wanted = new Set<string>();
    for (const e of nostrAllEvents) {
      if (e.kind !== 1 && e.kind !== 6 && e.kind !== 7) continue;
      if (nostrProfileMap[e.pubkey]) continue;
      if (nostrProfileRequestedRef.current.has(e.pubkey)) continue;
      wanted.add(e.pubkey);
    }
    const pending = [...wanted];
    if (pending.length === 0) return;
    for (const p of pending) nostrProfileRequestedRef.current.add(p);
    // 100 件ずつに分けて REQ する
    const readTargets =
      nostrRelayList && (nostrRelayList.read.length > 0 || nostrRelayList.both.length > 0)
        ? [...nostrRelayList.read, ...nostrRelayList.both]
        : null;
    for (let i = 0; i < pending.length; i += 100) {
      const chunk = pending.slice(i, i + 100);
      const filters = [{ kinds: [0], authors: chunk }];
      try {
        if (readTargets) {
          nostrRelay.sendReqTo(readTargets, 'nostr_kind0_' + Date.now() + '_' + i, filters);
        } else {
          nostrRelay.sendReq('nostr_kind0_' + Date.now() + '_' + i, filters);
        }
      } catch {
        /* 未接続中は無視 */
      }
    }
  }, [nostrAllEvents, nostrProfileMap, nostrRelay.connected, nostrRelay.sendReq, nostrRelay.sendReqTo, nostrRelayList]);

  // 署名済み Nostr イベントを送信し、自フィードに即時反映する。
  // NIP-65 の write マーカーがあれば write リレーだけへ送る。
  function nostrPublish(ev: NostrEvent) {
    setNostrLocalEvents((prev) => [...prev, ev]);
    try {
      const writeTargets =
        nostrRelayList && (nostrRelayList.write.length > 0 || nostrRelayList.both.length > 0)
          ? [...nostrRelayList.write, ...nostrRelayList.both]
          : null;
      if (writeTargets) {
        nostrRelay.sendEventTo(writeTargets, ev);
      } else {
        nostrRelay.sendEvent(ev);
      }
    } catch {
      /* 未接続中は送信できない(再接続後の REQ で自イベントも取得される) */
    }
  }

  // 署名済みイベントを全リレーへ送信する
  function sendSignedEvent(transType: number, content: string, signatureHex: string, tags: string[] = []) {
    const event: FodprEvent = {
      transType,
      createdAt: Math.floor(Date.now() / 1000),
      pubkey: pubkeyBytes,
      tags,
      content: new TextEncoder().encode(content),
      signature: CryptoUtils.hexToBytes(signatureHex),
    };
    // Optimistic: 自フィードに即反映
    setLocalEvents((prev) => [event, ...prev]);
    relay.sendEvent(event);
  }

  // イベントを削除する(DEL メッセージを送信)
  async function deleteEvent(_targetKey: string, targetEvent: FodprEvent) {
    if (!privKey || !relay.connected) return;

    // 削除対象の公開鍵と自分の鍵が一致するか確認
    const targetPubkeyHex = CryptoUtils.bytesToHex(targetEvent.pubkey);
    const selfPubkeyHex = CryptoUtils.bytesToHex(pubkeyBytes);
    if (targetPubkeyHex !== selfPubkeyHex) {
      alert('自分の投稿しか削除できません');
      return;
    }

    // DEL 要求を組み立てる(署名対象は Protocol.encodeDelSignedData が生成)
    const delReq: FodprDelReq = {
      transType: targetEvent.transType,
      targetType: DelTargetEvent,
      pubkey: targetEvent.pubkey,
      createdAt: targetEvent.createdAt,
      contentHash: new Uint8Array(sha256(targetEvent.content)),
      eventId: new Uint8Array(),
      signature: new Uint8Array(),
    };
    const signedData = Protocol.encodeDelSignedData(delReq);
    const sigHex = await CryptoUtils.signMessage(privKey, signedData);
    delReq.signature = CryptoUtils.hexToBytes(sigHex);

    // 送信 (relay.sendDel が MsgTypeDel(0x03) 付きパケットを送信する)
    try {
      relay.sendDel(delReq);
      // Optimistic: ローカル + 受信済みを問わずフィードから削除
      const key = dedupeKey(targetEvent);
      setDeletedKeys((prev) => new Set(prev).add(key));
      setLocalEvents((prev) => prev.filter((e) => dedupeKey(e) !== key));
    } catch (e) {
      console.error('Delete failed:', e);
      alert('削除に失敗しました');
    }
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
        const tooLarge = mediaTooLargeError(media.dataUrl.length);
        if (tooLarge) {
          setMediaError(tooLarge);
          return;
        }
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
        const tooLarge = mediaTooLargeError(dataUrl.length);
        if (tooLarge) {
          setMediaError(tooLarge);
          return;
        }
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
      const tooLarge = mediaTooLargeError(dataUrl.length);
      if (tooLarge) {
        setMediaError(tooLarge);
        return;
      }
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
      sendSignedEvent(TransTypeString, content, sig, [
        `quote:${quoteTarget}`,
        ...buildFodprMentionTags(content, mentionLookup),
        ...buildFodprEmojiTags(content),
      ]);
      setNoteText('');
      setQuoteTarget(null);
      // 投稿後は入力欄を閉じる(デスクトップは表示を維持、モバイルはモーダルを閉じる)
      setMobileComposerOpen(false);
      if (!isSm) setComposerHidden(true);
      return;
    }

    // リプライ: 本文 + reply:<対象> タグの TransTypeString(対象の投稿への返信)
    if (replyTarget) {
      if (!content) return;
      const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));
      sendSignedEvent(TransTypeString, content, sig, [
        `reply:${replyTarget}`,
        ...buildFodprMentionTags(content, mentionLookup),
        ...buildFodprEmojiTags(content),
      ]);
      setNoteText('');
      setReplyTarget(null);
      // 投稿後は入力欄を閉じる(デスクトップは表示を維持、モバイルはモーダルを閉じる)
      setMobileComposerOpen(false);
      if (!isSm) setComposerHidden(true);
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
      // サーバー(リレー)の受信上限 16MB を超えると接続切断やサーバー停止を
      // 招くため、投稿直前に必ずサイズを検証する。
      const tooLarge = mediaTooLargeError(mediaContent.length);
      if (tooLarge) {
        setMediaError(tooLarge);
        return;
      }
      const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(mediaContent));
      const tags = [
        `caption:${caption}`,
        `filename:${mediaName}`,
        `mediatype:${mediaType}`,
        ...buildFodprMentionTags(caption, mentionLookup),
        ...buildFodprEmojiTags(caption),
      ];
      sendSignedEvent(TransTypeBinary, mediaContent, sig, tags);
      setNoteText('');
      setMediaDataUrl(null);
      setMediaName(null);
      setMediaSize(0);
      setMediaType(null);
      setMediaThumbnail(null);
      // 投稿後は入力欄を閉じる(デスクトップは表示を維持、モバイルはモーダルを閉じる)
      setMobileComposerOpen(false);
      if (!isSm) {
        setComposerHidden(true);
        localStorage.setItem('fodpr_composer_hidden', '1');
      }
      return;
    }

    if (!content) return;
    const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));
    sendSignedEvent(TransTypeString, content, sig, [
      ...buildFodprMentionTags(content, mentionLookup),
      ...buildFodprEmojiTags(content),
    ]);
    setNoteText('');
    // 投稿後は入力欄を閉じる(デスクトップは表示を維持、モバイルはモーダルを閉じる)
    setMobileComposerOpen(false);
    if (!isSm) setComposerHidden(true);
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

  // リプライ開始: タイムラインへ戻ってコンポーザを返信モードにする
  function startReply(targetKey: string) {
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
    setReplyTarget(targetKey);
  }

  // プロフィール(JSON mode: profile)を投稿するハンドラ。
  // 引数を省略すると現在の入力値を使う(Nostr インポート時は明示的に渡す)。
  const postProfile = async (nameVal?: string, aboutVal?: string, pictureVal?: string) => {
    const n = (nameVal ?? name).trim();
    const ab = aboutVal !== undefined ? aboutVal : about;
    const pic = (pictureVal !== undefined ? pictureVal : picture).trim();
    if (!n) return;
    if (!privKey) return;
    const profile = { mode: 'profile', name: n, about: ab || undefined, picture: pic || undefined };
    const content = JSON.stringify(profile);
    const sig = await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content));
    sendSignedEvent(TransTypeJSON, content, CryptoUtils.bytesToHex(sig));
    // 保存後も入力内容を保持する(自己紹介・名前・画像が消えないようにする)
    setName(n);
    setAbout(ab ?? '');
    setPicture(pic);
  };

  // fsec(または HEX)でログインし、暗号化して保存する
  async function handleLogin(input: string) {
    const hex = normalizeSecretKey(input);
    CryptoUtils.getPublicKey(hex); // 不正な鍵はここでエラーになる
    await saveSecret(hex);
    setPrivKey(hex);
  }

  // nsec(または HEX)で Nostr にログインし、暗号化して保存する
  async function handleNostrLogin(input: string) {
    const hex = normalizeNostrSecretKey(input);
    getPublicKeyFromSecret(hex); // 不正な鍵はここでエラーになる
    await saveNostrSecret(hex);
    setNostrPrivKey(hex);
    // fsec 未ログインなら閲覧モードで入り、Nostr タブを表示する
    if (!privKey) {
      setGuestMode(true);
      setActiveTab('nostr');
      localStorage.setItem(NOSTR_GUEST_STORAGE_KEY, '1');
    }
  }

  // NIP-07(ブラウザ拡張)でログインする。秘密鍵は拡張内に保持され、このクライアントは
  // 公開鍵だけを localStorage へ保存してログイン状態を復元する。
  async function handleNostrNip07Login() {
    const ext = window.nostr;
    if (!ext || typeof ext.getPublicKey !== 'function') {
      throw new Error('NIP-07 対応のブラウザ拡張(Alby など)が見つかりません');
    }
    const pubkey = await ext.getPublicKey();
    if (!/^[0-9a-f]{64}$/.test(pubkey)) throw new Error('拡張から取得した公開鍵が不正です');
    setNostrNip07Pubkey(pubkey);
    try {
      localStorage.setItem(NIP07_PUBKEY_STORAGE_KEY, pubkey);
    } catch {
      /* 保存失敗は無視 */
    }
    // fsec 未ログインなら閲覧モードで入り、Nostr タブを表示する
    if (!privKey) {
      setGuestMode(true);
      setActiveTab('nostr');
      localStorage.setItem(NOSTR_GUEST_STORAGE_KEY, '1');
    }
  }

  // NIP-79 (Nosskey / PRF direct usage)で新規にパスキーを作り Nostr 鍵を派生してログイン。
  // 秘密鍵はパスキーの PRF でしか再生できないため、秘密鍵はメモリ上の nostrPrivKey に
  // のみ保持する(keystore へ永続化しない)。
  async function handleNostrPasskeyRegister() {
    const { privKey, pubkey, credId } = await registerNosskeyPasskey();
    // 不正な鍵(極めて稀)は prfToPrivateKey 内部で throw 済み
    setNostrPrivKey(privKey);
    setNostrPasskeyCred({ credId, pubkey });
    try {
      localStorage.setItem(NOSSKEY_CRED_STORAGE_KEY, JSON.stringify({ credId, pubkey }));
    } catch {
      /* 保存失敗は無視 */
    }
    if (!privKey) {
      setGuestMode(true);
      setActiveTab('nostr');
      localStorage.setItem(NOSTR_GUEST_STORAGE_KEY, '1');
    }
  }

// NIP-79 (Nosskey)で登録済みのパスキーから WebAuthn 照証を要求し秘密鍵を再生してログイン。
    // PRF は認証(生体)を伴うため、ページリロード後は毎回この手続きで再生する必要がある。
    async function handleNostrPasskeyLogin() {
      if (!nostrPasskeyCred) throw new Error('パスキー(credential)が登録されていません');
      const { privKey } = await loginNosskeyPasskey();
      setNostrPrivKey(privKey);
      if (!privKey) {
        setGuestMode(true);
        setActiveTab('nostr');
        localStorage.setItem(NOSTR_GUEST_STORAGE_KEY, '1');
      }
    }

    // NIP-79 パスキー(credential)の登録情報を完全に削除する。
    // 新しいパスキーを作ると新しい Nostr アイデンティティになるため、
    // 切り替えたいときに使う。現在パスキーでログイン中ならログアウトも伴う。
    function handleNostrPasskeyRemove() {
      setNostrPasskeyCred(null);
      try {
        localStorage.removeItem(NOSSKEY_CRED_STORAGE_KEY);
      } catch {
        /* 無視 */
      }
      // ログイン中の方法がパスキーならセッションも破棄しログイン画面へ戻す
      if (nostrLoginMethod === 'passkey') {
        void clearNostrSecret();
        setNostrPrivKey(null);
        setNostrNip07Pubkey(null);
        setNostrLocalEvents([]);
        setNostrOpenPubkey(null);
        setNostrReplyTarget(null);
        setNostrQuoteTarget(null);
        localStorage.removeItem(NOSTR_GUEST_STORAGE_KEY);
        if (!privKey) setGuestMode(false);
      }
    }

    // Nosskey (nosskey-sdk) で新規登録 (PRF direct mode)
    async function handleNostrNosskeyRegister() {
      const { privKey, pubkey, credId } = await registerNosskeyPasskey();
      setNostrPrivKey(privKey);
      setNostrPasskeyCred({ credId, pubkey });
      try {
        localStorage.setItem(NOSSKEY_CRED_STORAGE_KEY, JSON.stringify({ credId, pubkey }));
      } catch {
        /* 保存失敗は無視 */
      }
      if (!privKey) {
        setGuestMode(true);
        setActiveTab('nostr');
        localStorage.setItem(NOSTR_GUEST_STORAGE_KEY, '1');
      }
    }

    // Nosskey (nosskey-sdk) でログイン
    async function handleNostrNosskeyLogin() {
      const cred = getStoredNosskeyCred();
      if (!cred) throw new Error('Nosskey credential が登録されていません');
      const { privKey } = await loginNosskeyPasskey();
      setNostrPrivKey(privKey);
      if (!privKey) {
        setGuestMode(true);
        setActiveTab('nostr');
        localStorage.setItem(NOSTR_GUEST_STORAGE_KEY, '1');
      }
    }

    // 既存の nsec を Nosskey に保存 (wrap mode - nsec を PRF 派生 KEK で暗号化)
    async function handleNostrSaveNsecToNosskey(nsecInput: string) {
      const hex = normalizeNostrSecretKey(nsecInput);
      getPublicKeyFromSecret(hex); // 不正な鍵はここでエラーになる
      const { pubkey, credId } = await saveNsecToNosskey(hex);
      setNostrPrivKey(hex);
      setNostrPasskeyCred({ credId, pubkey });
      try {
        localStorage.setItem(NOSSKEY_CRED_STORAGE_KEY, JSON.stringify({ credId, pubkey }));
      } catch {
        /* 保存失敗は無視 */
      }
      if (!privKey) {
        setGuestMode(true);
        setActiveTab('nostr');
        localStorage.setItem(NOSTR_GUEST_STORAGE_KEY, '1');
      }
    }


  // Nostr イベントへの署名。nsec を持っていればローカル署名、NIP-07 ログインなら
  // ブラウザ拡張へ署名を依頼する。
  async function signNostrEvent(ev: UnsignedNostrEvent): Promise<NostrEvent> {
    if (nostrPrivKey) {
      return signEventAsync(nostrPrivKey, ev);
    }
    const ext = window.nostr;
    if (!ext || typeof ext.signEvent !== 'function' || !nostrNip07Pubkey) {
      throw new Error('Nostr 署名に必要な鍵がありません(nsec または NIP-07 でログインしてください)');
    }
    const signed = await ext.signEvent({
      kind: ev.kind,
      tags: ev.tags,
      content: ev.content,
      created_at: ev.created_at,
    });
    return {
      id: signed.id,
      pubkey: signed.pubkey ?? nostrPubkeyHex,
      created_at: signed.created_at ?? ev.created_at,
      kind: ev.kind,
      tags: ev.tags,
      content: ev.content,
      sig: signed.sig,
    };
  }

  // Nostr ログアウト(nsec と NIP-07 の両方からログアウトする)
  function handleNostrLogout() {
    void clearNostrSecret();
    setNostrPrivKey(null);
    setNostrNip07Pubkey(null);
    try {
      localStorage.removeItem(NIP07_PUBKEY_STORAGE_KEY);
    } catch {
      /* 無視 */
    }
    setNostrLocalEvents([]);
    setNostrOpenPubkey(null);
    setNostrReplyTarget(null);
    setNostrQuoteTarget(null);
    localStorage.removeItem(NOSTR_GUEST_STORAGE_KEY);
    // fsec も無ければログイン画面へ戻す
    if (!privKey) setGuestMode(false);
  }

  // 鍵なしで閲覧だけ入る
  function handleGuest() {
    setGuestMode(true);
    localStorage.removeItem(NOSTR_GUEST_STORAGE_KEY);
  }

  // 自分のリアクションを取り消す(該当イベントを DEL)
  async function handleUndoReact(targetKey: string) {
    const mine = selfReactionEventsByKey.get(targetKey) ?? [];
    for (const e of mine) {
      await deleteEvent(dedupeKey(e), e);
    }
  }

  // 自分のリポストを取り消す(該当イベントを DEL)
  async function handleUndoRepost(targetKey: string) {
    const mine = links.filter(
      (e) =>
        quoteTargetOf(e) === null &&
        repostTarget(e) === targetKey &&
        CryptoUtils.bytesToHex(e.pubkey) === pubkeyHex,
    );
    for (const e of mine) {
      await deleteEvent(dedupeKey(e), e);
    }
  }

  // Nostr テキスト投稿(kind 1)。replyTarget があれば返信タグ、quoteTarget があれば引用タグ(marker='q')を付ける。
  // content 内の :shortcode: に対応する NIP-30 の emoji タグも付与する。
  async function handleNostrPost(
    text: string,
    replyTarget?: { id: string; pubkey: string } | null,
    quoteTarget?: { id: string; pubkey: string } | null,
  ) {
    if (!nostrPubkeyHex) return;
    const content = text.trim();
    if (!content) return;
    const baseTags: NostrTags = replyTarget
      ? buildReplyTags(replyTarget.id, replyTarget.pubkey)
      : quoteTarget
        ? buildQuoteTags(quoteTarget.id, quoteTarget.pubkey)
        : [];
    const tags = [
      ...baseTags,
      ['client', 'Prrr'],
      ...buildNostrMentionPTags(content, buildNostrMentionLookup(nostrProfileMap)),
      ...buildNostrEmojiTags(content),
    ];
    const ev = makeNostrEvent(nostrPubkeyHex, Math.floor(Date.now() / 1000), 1, tags, content);
    const signed = await signNostrEvent(ev);
    nostrPublish(signed);
  }

  // Nostr リアクション(kind 7)。既に自分が反応していれば kind 5 で取り消す
  async function handleNostrReact(noteId: string, targetPubkey: string) {
    if (!nostrPubkeyHex) return;
    const existing = (nostrReactionMap.get(noteId) ?? []).find(
      (e) => e.pubkey === nostrPubkeyHex && ['❤️', '+'].includes(e.content.trim()),
    );
    if (existing) {
      await handleNostrDelete(existing);
      return;
    }
    const ev = makeNostrEvent(
      nostrPubkeyHex,
      Math.floor(Date.now() / 1000),
      7,
      buildReactionTags(noteId, targetPubkey),
      '❤️',
    );
    const signed = await signNostrEvent(ev);
    nostrPublish(signed);
  }

  // Nostr リポスト(kind 6)。既にリポストしていれば kind 5 で取り消す
  async function handleNostrRepost(noteId: string, targetPubkey: string) {
    if (!nostrPubkeyHex) return;
    const existing = (nostrRepostMap.get(noteId) ?? []).find((e) => e.pubkey === nostrPubkeyHex);
    if (existing) {
      await handleNostrDelete(existing);
      return;
    }
    const ev = makeNostrEvent(
      nostrPubkeyHex,
      Math.floor(Date.now() / 1000),
      6,
      [
        ['e', noteId],
        ['p', targetPubkey],
      ],
      '',
    );
    const signed = await signNostrEvent(ev);
    nostrPublish(signed);
  }

  // Nostr 削除(kind 5)
  async function handleNostrDelete(ev: NostrEvent) {
    if (!nostrPubkeyHex) return;
    const del = makeNostrEvent(nostrPubkeyHex, Math.floor(Date.now() / 1000), 5, [['e', ev.id]], '');
    const signed = await signNostrEvent(del);
    nostrPublish(signed);
  }

  // Fodpr プロフィールへ Nostr の kind 0 をインポートする。
  // nsec でログイン済みならそのまま、未ログインなら入力された nsec を使う。
  async function handleNostrImport(nsecInput?: string) {
    if (!privKey) throw new Error('先に fsec で Fodpr にログインしてください');
    // 公開鍵は nsec / NIP-07 のどちらからでも取得できる(kind 0 は読むだけなので署名不要)
    let pk = nostrPrivKey ? getPublicKeyFromSecret(nostrPrivKey) : nostrNip07Pubkey;
    if (!pk && nsecInput && nsecInput.trim()) {
      const hex = normalizeNostrSecretKey(nsecInput);
      pk = getPublicKeyFromSecret(hex);
      await saveNostrSecret(hex);
      setNostrPrivKey(hex);
    }
    if (!pk) throw new Error('nsec を入力するか、NIP-07 でログインしてください');
    const urls = nostrRelayUrls.length ? nostrRelayUrls : DEFAULT_NOSTR_RELAYS;
    const kind0 = await fetchNostrKind0(urls, pk);
    if (!kind0) throw new Error('Nostr にプロフィール(kind 0)が公開されていません');
    const meta = parseKind0Metadata(kind0.content);
    const displayName = kind0DisplayName(meta);
    if (!displayName && !meta.about && !meta.picture) {
      throw new Error('kind 0 に取り込める項目がありません');
    }
    // フォームへ反映してからプロフィールを投稿する(名前が空なら保存のみ)
    const nameVal = displayName ?? '';
    if (nameVal.trim()) {
      await postProfile(nameVal, meta.about ?? '', meta.picture ?? '');
    }
    setName(nameVal);
    setAbout(meta.about ?? '');
    setPicture(meta.picture ?? '');
  }

  // Nostr プロフィール(kind 0)を公開する。既存の metadata を引き継ぎつつ、
  // 入力された表示名・自己紹介・画像で上書きして全リレーへ投稿する。
  async function handleNostrSaveProfile(nameVal: string, aboutVal: string, pictureVal: string) {
    if (!nostrPubkeyHex) throw new Error('先に nsec または NIP-07 でログインしてください');
    const pk = nostrPubkeyHex;
    const existing = nostrProfileMap[pk];
    const prev = existing ? parseKind0Metadata(existing.content) : {};
    const trimmedName = nameVal.trim();
    if (!trimmedName && !aboutVal.trim() && !pictureVal.trim()) {
      throw new Error('名前・自己紹介・画像のいずれかを入力してください');
    }
    const content = JSON.stringify({
      ...prev,
      name: trimmedName || prev.name || '',
      display_name: trimmedName || prev.display_name || '',
      about: aboutVal || undefined,
      picture: pictureVal.trim() || undefined,
    });
    const ev = makeNostrEvent(pk, Math.floor(Date.now() / 1000), 0, [], content);
    const signed = await signNostrEvent(ev);
    nostrPublish(signed);
  }

  // Nostr リレー一覧を更新して保存する
  function updateNostrRelays(urls: string[]) {
    setNostrRelayUrls(urls);
    localStorage.setItem(NOSTR_RELAYS_STORAGE_KEY, JSON.stringify(urls));
  }

  // 新しい鍵を生成してログイン
  async function handleGenerate() {
    const hex = CryptoUtils.generatePrivateKey();
    await saveSecret(hex);
    setPrivKey(hex);
  }

  // 新しい Nostr 鍵(nsec)を生成してログインする
  async function handleGenerateNostr() {
    const hex = CryptoUtils.generatePrivateKey();
    await saveNostrSecret(hex);
    setNostrPrivKey(hex);
    // fsec 未ログインなら閲覧モードで入り、Nostr タブを表示する
    if (!privKey) {
      setGuestMode(true);
      setActiveTab('nostr');
      localStorage.setItem(NOSTR_GUEST_STORAGE_KEY, '1');
    }
  }

  // ログアウト(localStorage / IndexedDB の鍵を破棄してログイン画面へ戻る)
  function handleLogout() {
    void clearSecret();
    setPrivKey(null);
    setGuestMode(false);
    setView('timeline');
    setOpenPubkey(null);
    setQuoteTarget(null);
    setReplyTarget(null);
    setDeletedKeys(new Set());
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
      <div className="relative flex min-h-screen items-center justify-center overflow-hidden text-gray-400">
        <div
          className="absolute inset-0 -z-10"
          style={{
            background:
              'radial-gradient(60rem 60rem at 20% -10%, rgb(77 160 255 / 0.22), transparent 60%), radial-gradient(50rem 50rem at 110% 20%, rgb(120 96 255 / 0.18), transparent 60%), #0e1012',
          }}
          aria-hidden="true"
        />
        <p className="relative z-10 text-sm">読み込み中...</p>
      </div>
    );
  }

   // 未ログイン(fsec なし)ならログイン画面を表示。鍵なしの閲覧モードも選べる。
   if (!privKey && !guestMode) {
     return (
       <LoginScreen
         onLogin={handleLogin}
         onGenerate={handleGenerate}
         onNostrLogin={handleNostrLogin}
         onNostrNip07Login={handleNostrNip07Login}
         onNostrGenerate={handleGenerateNostr}
         onNostrPasskeyLogin={handleNostrPasskeyLogin}
         onNostrPasskeyRegister={handleNostrPasskeyRegister}
         onNostrNosskeyLogin={handleNostrNosskeyLogin}
         onNostrNosskeyRegister={handleNostrNosskeyRegister}
         onNostrSaveNsecToNosskey={handleNostrSaveNsecToNosskey}
         passkeyRegistered={!!nostrPasskeyCred}
         nosskeyRegistered={hasNosskeyCredential()}
         onGuest={handleGuest}
         nostrLoggedIn={!!nostrPubkeyHex}
       />
     );
   }

  const selfName = resolveDisplayName(pubkeyHex, profileMap);

  // Nostr 側の自分表示用(npub 短縮 / kind 0 名)
  const nostrSelfName = nostrPubkeyHex ? nostrDisplayName(nostrPubkeyHex, nostrProfileMap) : '';
  const nostrSelfPicture = nostrPubkeyHex
    ? parseKind0Metadata(nostrProfileMap[nostrPubkeyHex]?.content ?? '').picture ?? null
    : null;

  // 引用モード中は引用対象イベントとその投稿者名を解決してプレビューに使う
  const quoteEvent = quoteTarget ? eventByKey.get(quoteTarget) : undefined;
  const quoteName = quoteEvent
    ? resolveDisplayName(CryptoUtils.bytesToHex(quoteEvent.pubkey), profileMap)
    : undefined;
  // 返信モード中は返信対象イベントとその投稿者名を解決してプレビューに使う
  const replyEvent = replyTarget ? eventByKey.get(replyTarget) : undefined;
  const replyName = replyEvent
    ? resolveDisplayName(CryptoUtils.bytesToHex(replyEvent.pubkey), profileMap)
    : undefined;
  // 投稿欄の表示状態(デスクトップ=下部固定、モバイル=中央モーダル)
  const composerVisible = isSm ? !composerHidden : mobileComposerOpen;

  // ネットワークタブを切り替える。ナビと表示状態はリセットする
  function switchTab(tab: ProtocolTab) {
    setActiveTab(tab);
    setView('timeline');
    setOpenPubkey(null);
    setQuoteTarget(null);
    setReplyTarget(null);
    setNostrOpenPubkey(null);
    setNostrReplyTarget(null);
    setNostrQuoteTarget(null);
  }

  // Nostr タブではタイムライン + プロフィール + 設定(リレー管理)のみ表示する。
  // nsec 未ログイン時はプロフィール項目を隠す。Fodpr はゲスト(閲覧のみ)時は
  // タイムラインだけを表示し、ログイン扱いの表示を避ける。
  // ゲスト(Fodpr 鍵なし)でも設定(リレー変更)は利用できる
  const navItems =
    activeTab === 'fodpr'
      ? privKey
        ? NAV_ITEMS
        : NAV_ITEMS.filter((i) => i.id === 'timeline' || i.id === 'settings')
      : nostrPrivKey || nostrNip07Pubkey
        ? NOSTR_NAV_ITEMS
        : NOSTR_NAV_ITEMS.filter((i) => i.id !== 'profile');

  return (
    <div className="relative h-svh h-[100dvh] overflow-hidden text-gray-100">
      <div
        className="absolute inset-0 -z-10"
        style={{
          background:
            'radial-gradient(60rem 60rem at 20% -10%, rgb(77 160 255 / 0.22), transparent 60%), radial-gradient(50rem 50rem at 110% 20%, rgb(120 96 255 / 0.18), transparent 60%), #0e1012',
        }}
        aria-hidden="true"
      />
      <div className="relative z-10 flex h-full flex-col pt-[env(safe-area-inset-top)]">
        {/* ヘッダー */}
        <header className="flex flex-wrap items-center justify-center gap-2 px-3 py-2.5 sm:gap-3 sm:px-4 sm:py-3">
          <h1 className="mr-auto shrink-0 text-2xl font-bold tracking-tight text-white/90">Prrr</h1>

          {/* ネットワーク切替: Fodpr / Nostr */}
          <LiquidGlass intensity="subtle" refractive className="liquid-glass--nav">
            <nav className="flex items-center gap-1 px-1.5 py-1.5" aria-label="ネットワーク切替">
              {(['fodpr', 'nostr'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => switchTab(tab)}
                  className={
                    'rounded-full px-3.5 py-1.5 text-sm transition-colors ' +
                    (activeTab === tab ? 'bg-primary font-semibold text-bg' : 'text-gray-300 hover:bg-white/10')
                  }
                >
                  {tab === 'fodpr' ? 'Fodpr' : 'Nostr'}
                </button>
              ))}
            </nav>
          </LiquidGlass>

          {/* ナビメニュー */}
          <LiquidGlass intensity="subtle" refractive className="liquid-glass--nav">
            <nav className="flex items-center gap-1 px-1.5 py-1.5">
              {navItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    setView(item.id);
                    setOpenPubkey(null);
                    setQuoteTarget(null);
                    setReplyTarget(null);
                    setNostrOpenPubkey(null);
                  }}
                  className={
                    'relative rounded-full px-3.5 py-1.5 text-sm transition-colors ' +
                    (view === item.id ? 'bg-white/15 text-white' : 'text-gray-300 hover:bg-white/10')
                  }
                >
                  {item.label}
                  {item.id === 'notifications' && unreadCountByTab[activeTab] > 0 && (
                    <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-primary px-1 text-[10px] font-bold text-bg">
                      {unreadCountByTab[activeTab] > 99 ? '99+' : unreadCountByTab[activeTab]}
                    </span>
                  )}
                </button>
              ))}
            </nav>
          </LiquidGlass>

          {/* アカウント: 接続状態 + 投稿欄の開閉(ログアウトは設定画面) */}
          <div className="flex shrink-0 items-center gap-2 text-sm">
            {isSm && activeTab === 'fodpr' && (
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
                {activeTab === 'fodpr' ? (
                  privKey ? (
                    <>
                      <Avatar
                        picture={profilePicture(profileMap[pubkeyHex])}
                        pubkeyHex={pubkeyHex}
                        name={selfName}
                        className="h-6 w-6 text-xs"
                      />
                      <span className={'h-2 w-2 rounded-full ' + (relay.connected ? 'bg-green-400' : 'bg-red-400')} />
                      <span className="hidden font-medium text-white sm:inline">{selfName}</span>
                    </>
                  ) : (
                    <>
                      <span className="h-2 w-2 rounded-full bg-gray-500" />
                      <span className="hidden font-medium text-white sm:inline">ゲスト(閲覧中)</span>
                      <button
                        onClick={() => setGuestMode(false)}
                        className="shrink-0 rounded-full border border-primary/50 bg-primary/10 px-3 py-1.5 text-xs font-semibold text-primary transition-colors hover:bg-primary/20"
                      >
                        ログイン
                      </button>
                    </>
                  )
                ) : nostrPrivKey || nostrNip07Pubkey ? (
                  <>
                    <Avatar
                      picture={nostrSelfPicture}
                      pubkeyHex={nostrPubkeyHex}
                      name={nostrSelfName}
                      className="h-6 w-6 text-xs"
                    />
                    <span
                      className={'h-2 w-2 rounded-full ' + (nostrRelay.connected ? 'bg-green-400' : 'bg-red-400')}
                    />
                    <span className="hidden font-medium text-white sm:inline">{nostrSelfName}</span>
                  </>
                ) : (
                  <>
                    <span className="h-2 w-2 rounded-full bg-gray-500" />
                    <span className="hidden font-medium text-white sm:inline">nsec 未ログイン</span>
                  </>
                )}
              </div>
            </LiquidGlass>
          </div>
        </header>

        {/* ビュー */}
        <main className="mx-auto w-full max-w-2xl flex-1 overflow-y-auto px-4 pb-4">
          {activeTab === 'fodpr' ? (
            <>
              {openPubkey && (
                <UserProfileView
                  pubkeyHex={openPubkey}
                  profileMap={profileMap}
                  notes={notes}
                  binaries={binaries}
                  replies={replyMap}
                  links={links}
                  eventByKey={eventByKey}
                  reactions={reactionMap}
                  selfPubkeyHex={pubkeyHex}
                  selfRepostTargets={selfRepostTargets}
                  onBack={() => setOpenPubkey(null)}
                  onOpenUser={setOpenPubkey}
                  onReact={handleReact}
                  onUndoReact={handleUndoReact}
                  onRepost={handleRepost}
                  onUndoRepost={handleUndoRepost}
                  onQuote={startQuote}
                  onReply={startReply}
                  onDelete={deleteEvent}
                  mutedPubkeys={mutedPubkeys}
                  onToggleMute={toggleMute}
                  mentionLookup={mentionLookup}
                />
              )}
              {!openPubkey && view === 'timeline' && (
                <div className="space-y-3">
                  {/* デスクトップ: タイムラインの先頭にテキスト投稿欄(Nostr 側と同じく上に固定) */}
                  {isSm && privKey && !composerHidden && (
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
                        replyTarget={replyTarget}
                        replyEvent={replyEvent}
                        replyName={replyName}
                        onCancelReply={() => setReplyTarget(null)}
                        onPickFile={onPickFile}
                        onSubmit={postNote}
                        relayConnected={relay.connected}
                        mediaType={mediaType}
                        mediaThumbnail={mediaThumbnail}
                        emojis={pickerEmojis}
                        mentionUsers={mentionUsers(profileMap)}
                      />
                    </LiquidGlass>
                  )}
                  <Timeline
                    notes={notes}
                    binaries={binaries}
                    replies={replyMap}
                    links={links}
                    others={others}
                    eventByKey={eventByKey}
                    profileMap={profileMap}
                    reactions={reactionMap}
                    selfPubkeyHex={pubkeyHex}
                    selfRepostTargets={selfRepostTargets}
                    mutedPubkeys={mutedPubkeys}
                    mentionLookup={mentionLookup}
                    onOpenUser={setOpenPubkey}
                    onReact={handleReact}
                    onUndoReact={handleUndoReact}
                    onRepost={handleRepost}
                    onUndoRepost={handleUndoRepost}
                    onQuote={startQuote}
                    onReply={startReply}
                    onDelete={deleteEvent}
                  />
                </div>
              )}
              {view === 'notifications' && (
                <NotificationsView
                  notifications={fodprNotifications}
                  readNotifIds={readNotifIds}
                  onMarkRead={markRead}
                  onMarkAllRead={markAllRead}
                  onOpenPost={openNotificationPost}
                  profileMap={profileMap}
                  nostrProfileMap={nostrProfileMap}
                  eventByKey={eventByKey}
                  nostrNoteById={nostrNoteById}
                  onOpenUser={setOpenPubkey}
                  onReact={handleReact}
                  onUndoReact={handleUndoReact}
                  onRepost={handleRepost}
                  onUndoRepost={handleUndoRepost}
                  onQuote={startQuote}
                  onReply={startReply}
                  onDelete={deleteEvent}
                  selfPubkeyHex={pubkeyHex}
                  selfRepostTargets={selfRepostTargets}
                  reactions={reactionMap}
                  replyMap={replyMap}
                  links={links}
                  nostrReplyMap={nostrReplyMap}
                  nostrRepostMap={nostrRepostMap}
                  nostrReactions={nostrReactionMap}
                  nostrReposts={nostrRepostMap}
                  noteById={nostrNoteById}
                  mentionLookup={mentionLookup}
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
                  nostrLoggedIn={!!nostrPrivKey || !!nostrNip07Pubkey}
                  onNostrImport={handleNostrImport}
                />
              )}
              {view === 'settings' && (
                <SettingsView
                  relayUrls={relayUrls}
                  onRelayChange={updateRelays}
                  relayStatus={relay.relayStatus}
                  relayConnected={relay.connected}
                  onLogout={handleLogout}
                  onShowDocs={openDocs}
                  secretHex={privKey}
                  browserNotifEnabled={browserNotifEnabled}
                  notifPermission={notifPermission}
                  onToggleBrowserNotif={setBrowserNotifsEnabled}
                  onRequestNotifPermission={requestNotificationPermission}
                  mutedPubkeys={mutedPubkeys}
                  onToggleMute={toggleMute}
                  profileMap={profileMap}
                  networkMode={networkMode}
                  onSetNetworkMode={setNetworkModePersisted}
                  networkPeerCount={networkPeerCount}
                  networkGroups={networkGroups}
                  networkLastError={networkLastError}
                  networkBootstrapDone={networkBootstrapDone}
                  onNetworkBootstrap={handleNetworkBootstrap}
                  onNetworkCreateGroup={handleNetworkCreateGroup}
                  onNetworkJoinGroup={handleNetworkJoinGroup}
                  onNetworkCreateInvitation={handleNetworkCreateInvitation}
                  onNetworkConnectInvitation={handleNetworkConnectInvitation}
                  networkSeedNodes={networkSeedNodes}
                  invitationCode={invitationCode}
                  setInvitationCode={setInvitationCode}
                />
              )}
            </>
          ) : (
            <>
              {nostrOpenPubkey && (
                <NostrUserModal
                  pubkey={nostrOpenPubkey}
                  profileMap={nostrProfileMap}
                  notes={nostrNotes}
                  replies={nostrReplyMap}
                  onClose={() => setNostrOpenPubkey(null)}
                  ownRelayUrls={nostrRelayUrls}
                  onAddRelay={(url) => updateNostrRelays([...nostrRelayUrls, url])}
                  mutedPubkeys={mutedPubkeys}
                  onToggleMute={toggleMute}
                  onOpenUser={setNostrOpenPubkey}
                />
              )}
              {!nostrOpenPubkey && view === 'timeline' && (
                <NostrTimeline
                  notes={nostrNotes}
                  replies={nostrReplyMap}
                  reactions={nostrReactionMap}
                  reposts={nostrRepostMap}
                  profileMap={nostrProfileMap}
                  selfPubkeyHex={nostrPubkeyHex}
                  loggedIn={!!nostrPrivKey || !!nostrNip07Pubkey}
                  relayConnected={nostrRelay.connected}
                  onOpenUser={setNostrOpenPubkey}
                  onReact={handleNostrReact}
                  onRepost={handleNostrRepost}
                  onReply={(id, pubkey) => setNostrReplyTarget({ id, pubkey })}
                  onQuote={(id, pubkey) => {
                    setNostrReplyTarget(null);
                    setNostrQuoteTarget({ id, pubkey });
                  }}
                  onDelete={handleNostrDelete}
                  onPost={handleNostrPost}
                  replyTarget={nostrReplyTarget}
                  quoteTarget={nostrQuoteTarget}
                  onCancelReply={() => setNostrReplyTarget(null)}
                  onCancelQuote={() => setNostrQuoteTarget(null)}
                  noteById={nostrNoteById}
                  onOpenImage={(url) => setImageOverlayUrl(url)}
                  emojis={pickerEmojis}
                  mutedPubkeys={mutedPubkeys}
                  mentionLookup={nostrMentionLookup}
                />
              )}
              {!nostrOpenPubkey && view === 'notifications' && (
                <NotificationsView
                  notifications={nostrNotifications}
                  readNotifIds={readNotifIds}
                  onMarkRead={markRead}
                  onMarkAllRead={markAllRead}
                  onOpenPost={openNotificationPost}
                  profileMap={profileMap}
                  nostrProfileMap={nostrProfileMap}
                  eventByKey={eventByKey}
                  nostrNoteById={nostrNoteById}
                  onOpenUser={setNostrOpenPubkey}
                  onReact={handleNostrReact}
                  onRepost={handleNostrRepost}
                  onQuote={(id, pubkey) => {
                    setNostrReplyTarget(null);
                    setNostrQuoteTarget({ id, pubkey });
                  }}
                  onReply={(id, pubkey) => setNostrReplyTarget({ id, pubkey })}
                  onDelete={handleNostrDelete}
                  selfPubkeyHex={nostrPubkeyHex}
                  selfRepostTargets={new Set()} // Nostrリポスト対象の管理が異なるため空セット
                  nostrReactions={nostrReactionMap}
                  nostrReposts={nostrRepostMap}
                  noteById={nostrNoteById}
                  replyMap={replyMap}
                  links={links}
                  nostrReplyMap={nostrReplyMap}
                  nostrRepostMap={nostrRepostMap}
                  mentionLookup={mentionLookup}
                />
              )}
              {!nostrOpenPubkey && view === 'profile' && (
                <NostrProfileView
                  key={nostrPubkeyHex}
                  pubkeyHex={nostrPubkeyHex}
                  profileMap={nostrProfileMap}
                  relayConnected={nostrRelay.connected}
                  onSave={handleNostrSaveProfile}
                />
              )}
{view === 'settings' && (
                   <NostrSettingsView
                     relayUrls={nostrRelayUrls}
                     onRelayChange={updateNostrRelays}
                     relayStatus={nostrRelay.relayStatus}
                     relayConnected={nostrRelay.connected}
                     onLogout={handleNostrLogout}
                     secretHex={nostrPrivKey}
                     nip07Pubkey={nostrNip07Pubkey}
                     loginMethod={nostrLoginMethod}
                     passkeyCred={nostrPasskeyCred}
                     onNostrPasskeyRemove={handleNostrPasskeyRemove}
                     onNostrSaveNsecToNosskey={handleNostrSaveNsecToNosskey}
                     relayList={nostrRelayList}
                     mutedPubkeys={mutedPubkeys}
                     onToggleMute={toggleMute}
                     profileMap={nostrProfileMap}
                   />
                 )}
            </>
          )}
        </main>

        {/* モバイル: 投稿欄は既定で非表示。右下のペン(FAB)で中央モーダルを開く */}
        {!isSm && activeTab === 'fodpr' && view === 'timeline' && !openPubkey && privKey && (
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
                      replyTarget={replyTarget}
                      replyEvent={replyEvent}
                      replyName={replyName}
                      onCancelReply={() => setReplyTarget(null)}
                      onPickFile={onPickFile}
                      onSubmit={postNote}
                      relayConnected={relay.connected}
                      mediaType={mediaType}
                      mediaThumbnail={mediaThumbnail}
                      emojis={pickerEmojis}
                      mentionUsers={mentionUsers(profileMap)}
                    />
                  </LiquidGlass>
                </div>
              </div>
            )}
          </>
        )}

        {/* 通知クリックで開いた対象投稿のオーバーレイ */}
        {notifPost &&
          createPortal(
            <NotifPostViewer
              post={notifPost.post}
              source={notifPost.source}
              onClose={() => setNotifPost(null)}
              onOpenUser={(pubkeyHex) => {
                if (notifPost.source === 'fodpr') setOpenPubkey(pubkeyHex);
                else setNostrOpenPubkey(pubkeyHex);
              }}
            />,
            document.body,
          )}

        {/* PWA の新しいバージョンが利用可能になったときに表示する更新バナー */}
        {pwaUpdateAvailable && (
          <div className="fixed inset-x-0 bottom-4 z-50 mx-auto w-[min(26rem,calc(100vw-2rem))] rounded-2xl border border-white/15 bg-[#0d1422]/95 p-4 shadow-2xl backdrop-blur">
            <p className="text-sm text-gray-200">新しいバージョンが利用可能です</p>
            <div className="mt-3 flex justify-end gap-2">
              <button
                onClick={applyPwaUpdate}
                className="rounded-full bg-primary px-4 py-2 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover"
              >
                更新する
              </button>
            </div>
          </div>
        )}

        {/* 画像タップオーバーレイ(Fodpr・Nostr 共通) */}
        {imageOverlayUrl &&
          createPortal(
            <>
              <button
                className="fixed inset-0 z-40 cursor-zoom-out bg-bg/90 backdrop-blur-sm"
                aria-label="閉じる"
                onClick={() => setImageOverlayUrl(null)}
              />
              <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
                <img
                  src={imageOverlayUrl}
                  alt=""
                  className="max-h-[90vh] max-w-[90vw] rounded-xl shadow-2xl"
                  onClick={() => setImageOverlayUrl(null)}
                />
              </div>
            </>,
            document.body,
          )}
      </div>
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
  eventByKey,
  reactions,
  selfPubkeyHex,
  selfRepostTargets,
  onOpenUser,
  onReact,
  onUndoReact,
  onRepost,
  onUndoRepost,
  onQuote,
  onReply,
  onDelete,
  embedded = false,
  mentionLookup,
}: {
  e: FodprEvent;
  profileMap: Record<string, FodprEvent>;
  eventByKey: Map<string, FodprEvent>;
  reactions: ReactionItem[] | undefined;
  selfPubkeyHex: string;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onUndoReact: (targetKey: string) => void;
  onRepost: (targetKey: string) => void;
  onUndoRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  onReply: (targetKey: string) => void;
  onDelete: (targetKey: string, targetEvent: FodprEvent) => void;
  selfRepostTargets: Set<string>;
  embedded?: boolean;
  mentionLookup: Map<string, MentionUser>;
}) {
  const pkHex = CryptoUtils.bytesToHex(e.pubkey);
  const name = resolveDisplayName(pkHex, profileMap);
  const pic = profilePicture(profileMap[pkHex]);
  const key = dedupeKey(e);
  const replyParent = replyParentName(e, eventByKey, profileMap);
  const selfReposted = selfRepostTargets.has(key);

  // Binary だがメディアとしてパースできないイベントは簡易表示する
  if (e.transType === TransTypeBinary) {
    const media = parseImageContent(eventContentStr(e));
    if (!media) {
      return (
        <div className="rounded-lg border border-white/10 bg-black/30 p-3 text-sm text-gray-400">
          [Binary event · signature {e.signature.length} bytes]
          <span className="block text-xs">{name}</span>
        </div>
      );
    }
    const caption = captionFromTags(e.tags);
    const filename = filenameFromTags(e.tags);
    const mediaSrc = `data:${media.mime};base64,${media.base64}`;
    const isVideo = media.mime.startsWith('video/');
    const isImage = media.mime.startsWith('image/');
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
              <OwnPostDeleteButton
                targetKey={key}
                targetEvent={e}
                selfPubkeyHex={selfPubkeyHex}
                onDelete={onDelete}
              />
            </div>
            {replyParent && (
              <div className="mt-1 text-xs text-gray-500">
                <ReplyIcon className="mr-1 inline h-3.5 w-3.5" />
                <button
                  onClick={() => onOpenUser(CryptoUtils.bytesToHex(eventByKey.get(replyTag(e) as string)!.pubkey))}
                  className="transition-colors hover:text-gray-300 hover:underline"
                >
                  {replyParent} への返信
                </button>
              </div>
            )}
            {caption && (
              <p className="mt-2 text-lg leading-relaxed whitespace-pre-wrap break-words sm:text-xl">
                {renderFodprContent(caption, parseFodprEmojiTags(e.tags), mentionLookup, onOpenUser)}
              </p>
            )}
            {isVideo ? (
              <video
                controls
                playsInline
                preload="metadata"
                src={mediaSrc}
                className="mt-2 max-h-96 w-auto max-w-full rounded-xl"
              />
            ) : isImage ? (
              <img
                src={mediaSrc}
                alt={caption ?? '画像'}
                loading="lazy"
                className="mt-2 max-h-96 w-auto max-w-full rounded-xl"
              />
            ) : (
              <a
                href={mediaSrc}
                download={filename ?? 'file'}
                className="mt-2 inline-flex items-center gap-2 rounded-xl border border-white/15 bg-black/20 px-3 py-2 text-sm text-gray-200 transition-colors hover:bg-white/10"
              >
                <span>ファイルをダウンロード</span>
                {filename && <span className="break-all text-xs text-gray-400">{filename}</span>}
              </a>
            )}
            <PostActions
              targetKey={key}
              reactions={reactions}
              selfPubkeyHex={selfPubkeyHex}
              embedded={embedded}
              targetEvent={e}
              selfReposted={selfReposted}
              onUndoReact={() => onUndoReact(key)}
              onUndoRepost={() => onUndoRepost(key)}
              onReact={onReact}
              onRepost={onRepost}
              onQuote={onQuote}
              onReply={onReply}
              onDelete={onDelete}
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
            <OwnPostDeleteButton
              targetKey={key}
              targetEvent={e}
              selfPubkeyHex={selfPubkeyHex}
              onDelete={onDelete}
            />
          </div>
          {replyParent && (
            <div className="mt-1 text-xs text-gray-500">
              <ReplyIcon className="mr-1 inline h-3 w-3" />
              <button
                onClick={() => onOpenUser(CryptoUtils.bytesToHex(eventByKey.get(replyTag(e) as string)!.pubkey))}
                className="transition-colors hover:text-gray-300 hover:underline"
              >
                {replyParent} への返信
              </button>
            </div>
          )}
          <p className="mt-2 text-lg leading-relaxed whitespace-pre-wrap break-words sm:text-xl">
            {renderFodprContent(eventContentStr(e), parseFodprEmojiTags(e.tags), mentionLookup, onOpenUser)}
          </p>
          <PostActions
            targetKey={key}
            reactions={reactions}
            selfPubkeyHex={selfPubkeyHex}
            embedded={embedded}
            targetEvent={e}
            selfReposted={selfReposted}
            onUndoReact={() => onUndoReact(key)}
            onUndoRepost={() => onUndoRepost(key)}
            onReact={onReact}
            onRepost={onRepost}
            onQuote={onQuote}
            onReply={onReply}
            onDelete={onDelete}
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
  replyTarget,
  replyEvent,
  replyName,
  onCancelReply,
  onPickFile,
  onSubmit,
  relayConnected,
  mediaType,
  mediaThumbnail,
  emojis,
  mentionUsers,
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
  replyTarget: string | null;
  replyEvent: FodprEvent | undefined;
  replyName: string | undefined;
  onCancelReply: () => void;
  onPickFile: (file: File | undefined) => void;
  onSubmit: () => void;
  relayConnected: boolean;
  mediaType: 'image' | 'video' | 'file' | null;
  mediaThumbnail: string | null;
  emojis: CustomEmojiDef[];
  mentionUsers: MentionUser[];
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const noteRef = useRef<HTMLTextAreaElement>(null);

  // @メンションの自動補完: カーソル直前の「@...」をクエリにして候補を表示する
  const [atQuery, setAtQuery] = useState<string | null>(null);
  const [atStart, setAtStart] = useState(0);
  const [atIndex, setAtIndex] = useState(0);
  const atCandidates = useMemo(() => {
    if (atQuery === null) return [];
    const q = atQuery.toLowerCase();
    return mentionUsers
      .filter((u) => u.name.toLowerCase().includes(q) || u.pk.toLowerCase().startsWith(q))
      .slice(0, 8);
  }, [atQuery, mentionUsers]);

  // カーソル位置の直前の単語が @ で始まる場合、補完状態を更新する
  function updateAtState(textarea: HTMLTextAreaElement) {
    const value = textarea.value;
    const pos = textarea.selectionStart;
    const head = value.slice(0, pos);
    const m = /@([^\s@,。、!！?？;；]*)$/.exec(head);
    if (m) {
      const start = pos - m[0].length;
      setAtStart(start);
      setAtQuery(m[1]);
      setAtIndex(0);
    } else {
      setAtQuery(null);
    }
  }

  function selectMention(u: MentionUser) {
    if (atQuery === null || !noteRef.current) return;
    const ta = noteRef.current;
    const next = ta.value.slice(0, atStart) + '@' + u.name + ta.value.slice(ta.selectionStart);
    setNoteText(next);
    setAtQuery(null);
    // カーソルを挿入末尾へ移動
    requestAnimationFrame(() => {
      ta.focus();
      ta.selectionStart = ta.selectionEnd = atStart + u.name.length + 1;
    });
  }

  // 引用/返信モードに入ったら入力欄へ自動でフォーカスする
  useEffect(() => {
    if (quoteTarget || replyTarget) noteRef.current?.focus();
  }, [quoteTarget, replyTarget]);

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
      {replyTarget && (
        <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-black/20 px-3 py-2">
          <span className="shrink-0 text-xs text-gray-400">返信先:</span>
          <span className="min-w-0 flex-1 truncate text-xs text-gray-300">
            {replyName ? `${replyName}: ${eventSnippet(replyEvent)}` : '返信先の投稿が見つかりません'}
          </span>
          <button
            onClick={onCancelReply}
            className="shrink-0 rounded-lg border border-white/15 px-2.5 py-1 text-xs text-gray-400 transition-colors hover:bg-white/10"
          >
            解除
          </button>
        </div>
      )}
      <div className="flex items-end gap-3">
        <div className="relative min-w-0 flex-1">
          <textarea
            ref={noteRef}
            className="max-h-40 w-full resize-none rounded-xl bg-black/30 p-3 text-base text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
            placeholder={replyTarget ? '返信を投稿する...' : quoteTarget ? '引用して投稿する...' : '何か投稿する...'}
            value={noteText}
            onChange={(e) => {
              setNoteText(e.target.value);
              updateAtState(e.target);
            }}
            onKeyDown={(e) => {
              if (atQuery !== null && atCandidates.length > 0) {
                if (e.key === 'ArrowDown') {
                  e.preventDefault();
                  setAtIndex((i) => (i + 1) % atCandidates.length);
                  return;
                }
                if (e.key === 'ArrowUp') {
                  e.preventDefault();
                  setAtIndex((i) => (i - 1 + atCandidates.length) % atCandidates.length);
                  return;
                }
                if (e.key === 'Enter') {
                  e.preventDefault();
                  selectMention(atCandidates[atIndex]);
                  return;
                }
                if (e.key === 'Escape') {
                  e.preventDefault();
                  setAtQuery(null);
                  return;
                }
              }
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                void onSubmit();
              }
            }}
            rows={2}
          />
          {atQuery !== null && atCandidates.length > 0 && (
            <div className="absolute left-0 right-0 top-full z-20 mt-1 overflow-hidden rounded-xl border border-white/10 bg-bg/95 shadow-lg backdrop-blur">
              {atCandidates.map((u, i) => (
                <button
                  key={u.pk}
                  onClick={() => selectMention(u)}
                  onMouseEnter={() => setAtIndex(i)}
                  className={
                    'flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors ' +
                    (i === atIndex ? 'bg-white/10' : 'hover:bg-white/5')
                  }
                >
                  <span className={'shrink-0 text-primary ' + (i === atIndex ? 'text-primary-hover' : '')}>
                    @{u.name}
                  </span>
                  <span className="ml-auto shrink-0 font-mono text-[10px] text-gray-500">{u.pk.slice(0, 8)}…</span>
                </button>
              ))}
            </div>
          )}
        </div>
        <div className="flex shrink-0 gap-2">
          <button
            onClick={() => fileRef.current?.click()}
            disabled={!relayConnected || !!quoteTarget || !!replyTarget}
            className="rounded-xl border border-white/15 px-3 py-2.5 text-sm font-semibold text-gray-300 transition-colors hover:bg-white/10 disabled:opacity-40 sm:px-4 sm:py-3"
          >
            添付
          </button>
          <EmojiPicker
            emojis={emojis}
            onPick={(def) => {
              if (noteRef.current) setNoteText(insertTextAtCursor(noteRef.current, `:${def.shortcode}:`));
            }}
          />
          <button
            onClick={() => void onSubmit()}
            disabled={
              !relayConnected ||
              (quoteTarget || replyTarget ? !noteText.trim() : !noteText.trim() && !mediaDataUrl)
            }
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

// リプライの吹き出しアイコン
function ReplyIcon({ className }: { className?: string }) {
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
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </svg>
  );
}

// メニューボタンの3点アイコン(縦並びの点)
function KebabIcon({ className }: { className?: string }) {
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
      <circle cx="12" cy="5" r="1" />
      <circle cx="12" cy="12" r="1" />
      <circle cx="12" cy="19" r="1" />
    </svg>
  );
}

// 自分の投稿の右上に表示するメニューボタン。メニューから「削除」を選ぶと投稿が消える。
// 自分の投稿でなければ何も表示しない。
function OwnPostDeleteButton({
  targetKey,
  targetEvent,
  selfPubkeyHex,
  onDelete,
}: {
  targetKey: string;
  targetEvent: FodprEvent | undefined;
  selfPubkeyHex: string;
  onDelete: (targetKey: string, targetEvent: FodprEvent) => void;
}) {
  const isOwnPost = targetEvent && CryptoUtils.bytesToHex(targetEvent.pubkey) === selfPubkeyHex;
  if (!isOwnPost || !targetEvent) return null;

  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuPos = useMemo(() => {
    const el = btnRef.current;
    if (!el) return { display: 'none' };
    const r = el.getBoundingClientRect();
    return { left: r.left, bottom: window.innerHeight - r.top + 6 };
  }, [open]);

  return (
    <>
      <button
        ref={btnRef}
        onClick={() => setOpen((o) => !o)}
        title="メニュー(削除)"
        aria-haspopup="menu"
        aria-expanded={open}
        className="ml-1 shrink-0 rounded-full border border-white/15 p-1 text-gray-400 opacity-60 transition-opacity hover:opacity-100 hover:bg-white/10"
      >
        <KebabIcon className="h-3.5 w-3.5" />
      </button>
      {open &&
        createPortal(
          <>
            <button className="fixed inset-0 z-40 cursor-default" aria-hidden="true" onClick={() => setOpen(false)} />
            <div
              className="fixed z-50 min-w-28 overflow-hidden rounded-xl border border-white/15 bg-[#14161a] shadow-xl"
              style={menuPos}
            >
              <button
                onClick={() => {
                  setOpen(false);
                  if (confirm('この投稿を削除しますか？')) onDelete(targetKey, targetEvent);
                }}
                className="block w-full px-3.5 py-2 text-left text-sm text-red-400 transition-colors hover:bg-red-400/10"
              >
                削除
              </button>
            </div>
          </>,
          document.body,
        )}
    </>
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

// 投稿アクション行: リプライ + ハート(未反応=アウトライン / 反応済み=塗り) + リポスト/引用/削除アイコン。
// リポストアイコンを押すとメニューで「リポスト」「引用」「削除」を選べる。
function PostActions({
  targetKey,
  reactions,
  selfPubkeyHex,
  embedded,
  targetEvent,
  selfReposted,
  onUndoReact,
  onUndoRepost,
  onReact,
  onRepost,
  onQuote,
  onReply,
  onDelete,
}: {
  targetKey: string;
  reactions: ReactionItem[] | undefined;
  selfPubkeyHex: string;
  embedded: boolean;
  targetEvent: FodprEvent | undefined;
  selfReposted: boolean;
  onUndoReact: () => void;
  onUndoRepost: () => void;
  onReact: (targetKey: string, emoji: string) => void;
  onRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  onReply: (targetKey: string) => void;
  onDelete: (targetKey: string, targetEvent: FodprEvent) => void;
}) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const agg = aggregateReactions(reactions, selfPubkeyHex);
  const selfReacted = agg.some((r) => r.self);
  const total = agg.reduce((sum, r) => sum + r.count, 0);
  
  // 自分の投稿かどうか判定
  const isOwnPost = targetEvent && CryptoUtils.bytesToHex(targetEvent.pubkey) === selfPubkeyHex;

  // 開くたびにボタンの現在位置からメニューの表示位置を計算する
  const menuPos = useMemo(() => {
    const el = btnRef.current;
    if (!el) return { display: 'none' };
    const r = el.getBoundingClientRect();
    return { left: r.left, bottom: window.innerHeight - r.top + 6 };
  }, [open]);
  
  return (
    <div className="mt-3 flex flex-wrap items-center gap-1.5">
      <button
        onClick={() => {
          if (selfReacted) onUndoReact();
          else onReact(targetKey, '❤️');
        }}
        title={selfReacted ? 'リアクションを取り消す' : 'リアクション ❤️'}
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
      <button
        onClick={() => onReply(targetKey)}
        title="返信"
        aria-label="返信"
        className="rounded-full border border-white/15 p-1.5 text-gray-300 transition-colors hover:bg-white/10"
      >
        <ReplyIcon className="h-4 w-4" />
      </button>
      {!embedded && (
        <div className="relative">
          <button
            ref={btnRef}
            onClick={() => setOpen((o) => !o)}
            title="共有(リポスト/引用/削除)"
            aria-expanded={open}
            className="rounded-full border border-white/15 p-1.5 text-gray-300 transition-colors hover:bg-white/10"
          >
            <RepostIcon className="h-4 w-4" />
          </button>
          {open &&
            createPortal(
              <>
                <button className="fixed inset-0 z-40 cursor-default" aria-hidden="true" onClick={() => setOpen(false)} />
                <div
                  className="fixed z-50 min-w-36 overflow-hidden rounded-xl border border-white/15 bg-[#14161a] shadow-xl"
                  style={menuPos}
                >
                  <button
                    onClick={() => {
                      setOpen(false);
                      if (selfReposted) onUndoRepost();
                      else onRepost(targetKey);
                    }}
                    className="block w-full px-3.5 py-2 text-left text-sm text-gray-200 transition-colors hover:bg-white/10"
                  >
                    {selfReposted ? 'リポストを取り消す' : 'リポスト'}
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
                  {isOwnPost && (
                    <button
                      onClick={() => {
                        setOpen(false);
                        if (targetEvent) onDelete(targetKey, targetEvent);
                      }}
                      className="block w-full px-3.5 py-2 text-left text-sm text-red-400 transition-colors hover:bg-red-400/10"
                    >
                      削除
                    </button>
                  )}
                </div>
              </>,
              document.body
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
  replies,
  eventByKey,
  selfPubkeyHex,
  selfRepostTargets,
  onOpenUser,
  onReact,
  onUndoReact,
  onRepost,
  onUndoRepost,
  onQuote,
  onReply,
  onDelete,
  depth,
  mentionLookup,
}: {
  e: FodprEvent;
  profileMap: Record<string, FodprEvent>;
  reactions: ReactionMap;
  replies: ReplyMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  selfRepostTargets: Set<string>;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onUndoReact: (targetKey: string) => void;
  onRepost: (targetKey: string) => void;
  onUndoRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  onReply: (targetKey: string) => void;
  onDelete: (targetKey: string, targetEvent: FodprEvent) => void;
  depth: number;
  mentionLookup: Map<string, MentionUser>;
}) {
  const pkHex = CryptoUtils.bytesToHex(e.pubkey);
  const name = resolveDisplayName(pkHex, profileMap);
  const key = dedupeKey(e);
  const isQuote = quoteTargetOf(e) !== null;
  const targetKey = (isQuote ? quoteTargetOf(e) : repostTarget(e)) as string;
  const target = eventByKey.get(targetKey);

  return (
    <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
      <div className="p-3">
        <div className="flex items-baseline gap-2 px-1 pb-2 text-xs text-gray-400">
          <span className="font-semibold">{isQuote ? '引用' : 'リポスト'}</span>
          <span>・ {name}</span>
          <span className="text-gray-500">{new Date(e.createdAt * 1000).toLocaleString()}</span>
          <OwnPostDeleteButton
            targetKey={key}
            targetEvent={e}
            selfPubkeyHex={selfPubkeyHex}
            onDelete={onDelete}
          />
        </div>
        {isQuote && eventContentStr(e).trim() && (
          <p className="mb-2 whitespace-pre-wrap break-words px-1 text-lg leading-relaxed text-gray-100 sm:text-xl">
            {renderFodprContent(eventContentStr(e), parseFodprEmojiTags(e.tags), mentionLookup, onOpenUser)}
          </p>
        )}
        {target ? (
          <div className="overflow-hidden rounded-xl border border-white/10 bg-black/20">
            <TimelineCard
              e={target}
              profileMap={profileMap}
              reactions={reactions}
              replies={replies}
              eventByKey={eventByKey}
              selfPubkeyHex={selfPubkeyHex}
              selfRepostTargets={selfRepostTargets}
              onOpenUser={onOpenUser}
              onReact={onReact}
              onUndoReact={onUndoReact}
              onRepost={onRepost}
              onUndoRepost={onUndoRepost}
              onQuote={onQuote}
              onReply={onReply}
              onDelete={onDelete}
              depth={depth + 1}
              mentionLookup={mentionLookup}
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
// トップレベル(depth=0)の場合は直下のリプライスレッドも表示する
function TimelineCard({
  e,
  profileMap,
  reactions,
  replies,
  eventByKey,
  selfPubkeyHex,
  selfRepostTargets,
  onOpenUser,
  onReact,
  onUndoReact,
  onRepost,
  onUndoRepost,
  onQuote,
  onReply,
  onDelete,
  depth = 0,
  mentionLookup,
}: {
  e: FodprEvent;
  profileMap: Record<string, FodprEvent>;
  reactions: ReactionMap;
  replies: ReplyMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  selfRepostTargets: Set<string>;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onUndoReact: (targetKey: string) => void;
  onRepost: (targetKey: string) => void;
  onUndoRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  onReply: (targetKey: string) => void;
  onDelete: (targetKey: string, targetEvent: FodprEvent) => void;
  depth?: number;
  mentionLookup: Map<string, MentionUser>;
}) {
  const card =
    repostTarget(e) || quoteTargetOf(e) ? (
      depth >= 3 ? (
        <div className="rounded-lg border border-white/10 bg-black/20 p-3 text-xs text-gray-500">
          共有チェーンの上限です
        </div>
      ) : (
        <SharedCard
          e={e}
          profileMap={profileMap}
          reactions={reactions}
          replies={replies}
          eventByKey={eventByKey}
          selfPubkeyHex={selfPubkeyHex}
          selfRepostTargets={selfRepostTargets}
          onOpenUser={onOpenUser}
          onReact={onReact}
          onUndoReact={onUndoReact}
          onRepost={onRepost}
          onUndoRepost={onUndoRepost}
          onQuote={onQuote}
          onReply={onReply}
          onDelete={onDelete}
          depth={depth}
          mentionLookup={mentionLookup}
        />
      )
    ) : (
      <PostCard
        e={e}
        profileMap={profileMap}
        eventByKey={eventByKey}
        reactions={reactions.get(dedupeKey(e))}
        selfPubkeyHex={selfPubkeyHex}
        selfRepostTargets={selfRepostTargets}
        onOpenUser={onOpenUser}
        onReact={onReact}
        onUndoReact={onUndoReact}
        onRepost={onRepost}
        onUndoRepost={onUndoRepost}
        onQuote={onQuote}
        onReply={onReply}
        onDelete={onDelete}
        embedded={depth > 0}
        mentionLookup={mentionLookup}
      />
    );

  // トップレベル表示のときだけ直下のリプライスレッドを畳む
  if (depth === 0) {
    return (
      <div className="space-y-2">
        {card}
        <ReplyThread
          targetKey={dedupeKey(e)}
          replies={replies}
          profileMap={profileMap}
          reactions={reactions}
          eventByKey={eventByKey}
          selfPubkeyHex={selfPubkeyHex}
          selfRepostTargets={selfRepostTargets}
          onOpenUser={onOpenUser}
          onReact={onReact}
          onUndoReact={onUndoReact}
          onRepost={onRepost}
          onUndoRepost={onUndoRepost}
          onQuote={onQuote}
          onReply={onReply}
          onDelete={onDelete}
          mentionLookup={mentionLookup}
        />
      </div>
    );
  }
  return card;
}

/* ────────────────────────────────────────────────────────────────────
   リプライスレッド。対象イベントの dedupeKey から直接の返信を探して
   時系列順(古い順)に表示し、各返信の下にさらに返信があれば再帰で続ける。
   ──────────────────────────────────────────────────────────────────── */
function ReplyThread({
  targetKey,
  replies,
  profileMap,
  reactions,
  eventByKey,
  selfPubkeyHex,
  selfRepostTargets,
  onOpenUser,
  onReact,
  onUndoReact,
  onRepost,
  onUndoRepost,
  onQuote,
  onReply,
  onDelete,
  depth = 0,
  mentionLookup,
}: {
  targetKey: string;
  replies: ReplyMap;
  profileMap: Record<string, FodprEvent>;
  reactions: ReactionMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  selfRepostTargets: Set<string>;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onUndoReact: (targetKey: string) => void;
  onRepost: (targetKey: string) => void;
  onUndoRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  onReply: (targetKey: string) => void;
  onDelete: (targetKey: string, targetEvent: FodprEvent) => void;
  depth?: number;
  mentionLookup: Map<string, MentionUser>;
}) {
  if (depth > 4) return null;
  const list = (replies.get(targetKey) ?? [])
    .slice()
    .sort((a, b) => a.createdAt - b.createdAt || dedupeKey(a).localeCompare(dedupeKey(b)));
  if (list.length === 0) return null;

  return (
    <div className="ml-2 space-y-2 border-l-2 border-white/10 pl-3 sm:ml-3">
      <p className="pt-1 text-[11px] font-medium tracking-wide text-gray-500">返信 {list.length} 件</p>
      {list.map((r) => {
        const rkHex = CryptoUtils.bytesToHex(r.pubkey);
        const rName = resolveDisplayName(rkHex, profileMap);
        const rKey = dedupeKey(r);
        const parentName = replyParentName(r, eventByKey, profileMap);
        return (
          <div key={rKey} className="rounded-xl border border-white/10 bg-black/20 p-3">
          <div className="flex items-baseline gap-2">
            <button
              onClick={() => onOpenUser(rkHex)}
              className="font-semibold text-primary transition-colors hover:text-primary-hover hover:underline"
            >
              {rName}
            </button>
            <span className="text-xs text-gray-500">{new Date(r.createdAt * 1000).toLocaleString()}</span>
            <OwnPostDeleteButton
              targetKey={rKey}
              targetEvent={r}
              selfPubkeyHex={selfPubkeyHex}
              onDelete={onDelete}
            />
          </div>
            <p className="mt-1 whitespace-pre-wrap break-words text-sm leading-relaxed text-gray-100">
              {renderFodprContent(eventContentStr(r), parseFodprEmojiTags(r.tags), mentionLookup, onOpenUser)}
            </p>
            {parentName && (
              <p className="mt-1 text-xs text-gray-500">
                <ReplyIcon className="mr-1 inline h-3 w-3" />
                {parentName} への返信
              </p>
            )}
            <PostActions
              targetKey={rKey}
              reactions={reactions.get(rKey)}
              selfPubkeyHex={selfPubkeyHex}
              embedded
              targetEvent={r}
              selfReposted={selfRepostTargets.has(rKey)}
              onUndoReact={() => onUndoReact(rKey)}
              onUndoRepost={() => onUndoRepost(rKey)}
              onReact={onReact}
              onRepost={() => {}}
              onQuote={() => {}}
              onReply={onReply}
              onDelete={onDelete}
            />
            <ReplyThread
              targetKey={rKey}
              replies={replies}
              profileMap={profileMap}
              reactions={reactions}
              eventByKey={eventByKey}
              selfPubkeyHex={selfPubkeyHex}
              selfRepostTargets={selfRepostTargets}
              onOpenUser={onOpenUser}
              onReact={onReact}
              onUndoReact={onUndoReact}
              onRepost={onRepost}
              onUndoRepost={onUndoRepost}
              onQuote={onQuote}
              onReply={onReply}
              onDelete={onDelete}
              depth={depth + 1}
              mentionLookup={mentionLookup}
            />
          </div>
        );
      })}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   タイムライン(最新順)
   ──────────────────────────────────────────────────────────────────── */
function Timeline({
  notes,
  binaries,
  replies,
  links,
  others,
  profileMap,
  reactions,
  eventByKey,
  selfPubkeyHex,
  selfRepostTargets,
  mutedPubkeys,
  onOpenUser,
  onReact,
  onUndoReact,
  onRepost,
  onUndoRepost,
  onQuote,
  onReply,
  onDelete,
  mentionLookup,
}: {
  notes: FodprEvent[];
  binaries: FodprEvent[];
  replies: ReplyMap;
  links: FodprEvent[];
  others: FodprEvent[];
  profileMap: Record<string, FodprEvent>;
  reactions: ReactionMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  selfRepostTargets: Set<string>;
  mutedPubkeys: Set<string>;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onUndoReact: (targetKey: string) => void;
  onRepost: (targetKey: string) => void;
  onUndoRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  onReply: (targetKey: string) => void;
  onDelete: (targetKey: string, targetEvent: FodprEvent) => void;
  mentionLookup: Map<string, MentionUser>;
}) {
  // テキスト/画像/共有を統合して最新順(上=最新)に並べる(ミュート除外)
  const posts = sortPostsDesc([...notes, ...binaries, ...links]).filter(
    (e) => !mutedPubkeys.has(CryptoUtils.bytesToHex(e.pubkey)),
  );

  // リレーにまだ対象投稿が無いリプライ(親が未取得)は末尾にフォールバック表示する
  const orphanReplies = [...replies.values()]
    .flat()
    .filter((r) => {
      const k = replyTag(r);
      return !k || !eventByKey.has(k);
    })
    .sort((a, b) => b.createdAt - a.createdAt)
    .filter((r) => !mutedPubkeys.has(CryptoUtils.bytesToHex(r.pubkey)));

  // 大量取得時の描画負荷を抑えるため、初期表示は先頭 80 件に制限し「さらに表示」で増やす
  const [visible, setVisible] = useState(80);
  useEffect(() => setVisible(80), [posts.length, orphanReplies.length]);

  return (
    <div className="space-y-3">
      {posts.length === 0 && <p className="pt-8 text-center text-sm text-gray-500">まだ投稿はありません</p>}

      {posts.slice(0, visible).map((e) => (
        <TimelineCard
          key={dedupeKey(e)}
          e={e}
          profileMap={profileMap}
          reactions={reactions}
          replies={replies}
          eventByKey={eventByKey}
          selfPubkeyHex={selfPubkeyHex}
          selfRepostTargets={selfRepostTargets}
          onOpenUser={onOpenUser}
          onReact={onReact}
          onUndoReact={onUndoReact}
          onRepost={onRepost}
          onUndoRepost={onUndoRepost}
          onQuote={onQuote}
          onReply={onReply}
          onDelete={onDelete}
          mentionLookup={mentionLookup}
        />
      ))}

      {posts.length > visible && (
        <button
          onClick={() => setVisible((v) => v + 80)}
          className="w-full rounded-xl border border-white/10 bg-black/30 py-3 text-sm text-gray-300 transition-colors hover:bg-white/10"
        >
          さらに表示 ({posts.length - visible} 件)
        </button>
      )}

      {orphanReplies.length > 0 && (
        <div className="space-y-2 pt-2">
          <p className="text-[11px] font-medium tracking-wide text-gray-500">返信先が見つからない投稿</p>
          {orphanReplies.map((e) => (
            <TimelineCard
              key={dedupeKey(e)}
              e={e}
              profileMap={profileMap}
              reactions={reactions}
              replies={replies}
              eventByKey={eventByKey}
              selfPubkeyHex={selfPubkeyHex}
              selfRepostTargets={selfRepostTargets}
              onOpenUser={onOpenUser}
              onReact={onReact}
              onUndoReact={onUndoReact}
              onRepost={onRepost}
              onUndoRepost={onUndoRepost}
              onQuote={onQuote}
              onReply={onReply}
              onDelete={onDelete}
              mentionLookup={mentionLookup}
            />
          ))}
        </div>
      )}

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
   Nostr ノートカード(kind 1)。名前クリックでプロフィールを開き、
   リアクション(kind 7)/リポスト(kind 6)/返信(kind 1)/削除(kind 5)を行う。
   ──────────────────────────────────────────────────────────────────── */
function NostrNoteCard({
  e,
  profileMap,
  reactions,
  reposts,
  selfPubkeyHex,
  loggedIn,
  onOpenUser,
  onReact,
  onRepost,
  onQuote,
  onReply,
   onDelete,
   noteById,
   onOpenImage,
   mentionLookup,
  }: {

  e: NostrEvent;
  profileMap: Record<string, NostrEvent>;
  reactions: NostrEvent[] | undefined;
  reposts: NostrEvent[] | undefined;
  selfPubkeyHex: string;
  loggedIn: boolean;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (noteId: string, targetPubkey: string) => void;
  onRepost: (noteId: string, targetPubkey: string) => void;
  onQuote: (noteId: string, targetPubkey: string) => void;
  onReply: (noteId: string, targetPubkey: string) => void;
  onDelete: (ev: NostrEvent) => void;
  noteById?: Record<string, NostrEvent>;
  onOpenImage?: (url: string) => void;
  mentionLookup?: Map<string, { pk: string; name: string }> | null;
}) {
  const [repostMenuOpen, setRepostMenuOpen] = useState(false);
  const repostBtnRef = useRef<HTMLButtonElement>(null);
  const repostMenuPos = useMemo(() => {
    const el = repostBtnRef.current;
    if (!el) return { display: 'none' };
    const r = el.getBoundingClientRect();
    return { left: r.left, bottom: window.innerHeight - r.top + 6 };
  }, [repostMenuOpen]);
  const name = nostrDisplayName(e.pubkey, profileMap);
  const meta = parseKind0Metadata(profileMap[e.pubkey]?.content ?? '');
  const agg = aggregateNostrReactions(reactions, selfPubkeyHex);
  const selfReacted = agg.some((r) => r.self);
  const total = agg.reduce((sum, r) => sum + r.count, 0);
  const selfReposted = (reposts ?? []).some((r) => r.pubkey === selfPubkeyHex);
  const repostCount = reposts?.length ?? 0;
  const isOwn = !!selfPubkeyHex && e.pubkey === selfPubkeyHex;
  // 画像(imeta タグ / 本文 URL)は本文から取り除き、画像として表示する
  const imgs = nostrImageUrls(e);
  const inlineImgUrls = inlineImageUrls(e.content);
  const imgUrlSet = new Set(imgs.map((i) => i.url));
  let contentText = e.content;
  for (const u of inlineImgUrls) {
    if (imgUrlSet.has(u)) contentText = contentText.split(u).join('');
  }

  return (
    <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
      <div className="flex gap-3 p-4">
        <button
          onClick={() => onOpenUser(e.pubkey)}
          className="shrink-0 rounded-full transition-transform hover:scale-105"
          title="プロフィールを開く"
        >
          <Avatar picture={meta.picture ?? null} pubkeyHex={e.pubkey} name={name} />
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <button
              onClick={() => onOpenUser(e.pubkey)}
              className="font-semibold text-primary transition-colors hover:text-primary-hover hover:underline"
            >
              {name}
            </button>
            <span className="text-xs text-gray-400">{shortNpub(e.pubkey)}</span>
            <span className="text-xs text-gray-500">{new Date(e.created_at * 1000).toLocaleString()}</span>
            {isOwn && (
              <button
                onClick={() => {
                  if (confirm('この投稿を削除しますか？')) onDelete(e);
                }}
                className="ml-auto shrink-0 rounded-full border border-white/15 p-1 text-gray-400 opacity-60 transition-opacity hover:opacity-100 hover:bg-white/10"
                title="削除"
                aria-label="削除"
              >
                <KebabIcon className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
          <p className="mt-2 text-lg leading-relaxed whitespace-pre-wrap break-words sm:text-xl">
            {renderNostrContent(contentText, parseNostrEmojiTags(e.tags), noteById ?? null, mentionLookup ?? null, onOpenUser)}
          </p>
          {imgs.length > 0 && (
            <div className="mt-2 space-y-2">
              {imgs.map((img, i) => (
                <img
                  key={i}
                  src={img.url}
                  alt=""
                  loading="lazy"
                  onClick={onOpenImage ? () => onOpenImage(img.url) : undefined}
                  className="max-h-96 w-auto max-w-full cursor-zoom-in rounded-xl"
                />
              ))}
            </div>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <button
              onClick={() => {
                if (loggedIn) onReact(e.id, e.pubkey);
              }}
              disabled={!loggedIn}
              title={selfReacted ? 'リアクションを取り消す' : 'リアクション ❤️'}
              aria-pressed={selfReacted}
              className={
                'flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-colors ' +
                (selfReacted
                  ? 'border-primary/60 bg-primary/15 text-primary'
                  : 'border-white/15 text-gray-300 hover:bg-white/10') +
                (!loggedIn ? ' opacity-40' : '')
              }
            >
              <HeartIcon filled={selfReacted} className="h-4 w-4" />
              {total > 0 && <span>{total}</span>}
            </button>
            <button
              onClick={() => {
                if (loggedIn) onReply(e.id, e.pubkey);
              }}
              disabled={!loggedIn}
              title="返信"
              aria-label="返信"
              className={
                'rounded-full border border-white/15 p-1.5 text-gray-300 transition-colors hover:bg-white/10' +
                (!loggedIn ? ' opacity-40' : '')
              }
            >
              <ReplyIcon className="h-4 w-4" />
            </button>
            <div className="relative">
              <button
                ref={repostBtnRef}
                onClick={() => {
                  if (loggedIn) setRepostMenuOpen((o) => !o);
                }}
                disabled={!loggedIn}
                title={selfReposted ? 'リポストを取り消す' : '共有(リポスト/引用)'}
                aria-expanded={repostMenuOpen}
                className={
                  'flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-colors ' +
                  (selfReposted
                    ? 'border-primary/60 bg-primary/15 text-primary'
                    : 'border-white/15 text-gray-300 hover:bg-white/10') +
                  (!loggedIn ? ' opacity-40' : '')
                }
              >
                <RepostIcon className="h-4 w-4" />
                {repostCount > 0 && <span>{repostCount}</span>}
              </button>
              {repostMenuOpen &&
                createPortal(
                  <>
                    <button
                      className="fixed inset-0 z-40 cursor-default"
                      aria-hidden="true"
                      onClick={() => setRepostMenuOpen(false)}
                    />
                    <div
                      className="fixed z-50 min-w-36 overflow-hidden rounded-xl border border-white/15 bg-[#14161a] shadow-xl"
                      style={repostMenuPos}
                    >
                      <button
                        onClick={() => {
                          setRepostMenuOpen(false);
                          if (selfReposted) onRepost(e.id, e.pubkey);
                        }}
                        className="block w-full px-3.5 py-2 text-left text-sm text-gray-200 transition-colors hover:bg-white/10"
                      >
                        {selfReposted ? 'リポストを取り消す' : 'リポスト'}
                      </button>
                      <button
                        onClick={() => {
                          setRepostMenuOpen(false);
                          onQuote(e.id, e.pubkey);
                        }}
                        className="block w-full px-3.5 py-2 text-left text-sm text-gray-200 transition-colors hover:bg-white/10"
                      >
                        引用
                      </button>
                    </div>
                  </>,
                  document.body,
                )}
            </div>
          </div>
        </div>
      </div>
    </LiquidGlass>
  );
}

// Nostr 返信スレッド。対象イベント id への直接返信(kind 1 の e タグ)を古い順に再帰表示する
function NostrReplyThread({
  targetId,
  replies,
  profileMap,
  reactions,
  reposts,
  selfPubkeyHex,
  loggedIn,
  onOpenUser,
  onReact,
  onRepost,
  onQuote,
   onReply,
   onDelete,
   noteById,
   onOpenImage,
   mentionLookup,
   depth = 0,
  }: {
  targetId: string;
  replies: Map<string, NostrEvent[]>;
  profileMap: Record<string, NostrEvent>;
  reactions: Map<string, NostrEvent[]>;
  reposts: Map<string, NostrEvent[]>;
  selfPubkeyHex: string;
  loggedIn: boolean;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (noteId: string, targetPubkey: string) => void;
  onRepost: (noteId: string, targetPubkey: string) => void;
  onQuote: (noteId: string, targetPubkey: string) => void;
  onReply: (noteId: string, targetPubkey: string) => void;
  onDelete: (ev: NostrEvent) => void;
  noteById?: Record<string, NostrEvent>;
  onOpenImage?: (url: string) => void;
  mentionLookup?: Map<string, { pk: string; name: string }> | null;
  depth?: number;
}) {
  if (depth > 4) return null;
  const list = (replies.get(targetId) ?? [])
    .slice()
    .sort((a, b) => a.created_at - b.created_at || (a.id > b.id ? 1 : -1));
  if (list.length === 0) return null;

  return (
    <div className="ml-2 space-y-2 border-l-2 border-white/10 pl-3 sm:ml-3">
      <p className="pt-1 text-[11px] font-medium tracking-wide text-gray-500">返信 {list.length} 件</p>
      {list.map((r) => (
        <div key={r.id} className="space-y-2">
          <NostrNoteCard
            e={r}
            profileMap={profileMap}
            reactions={reactions.get(r.id)}
            reposts={reposts.get(r.id)}
            selfPubkeyHex={selfPubkeyHex}
            loggedIn={loggedIn}
            onOpenUser={onOpenUser}
            onReact={onReact}
            onRepost={onRepost}
            onQuote={onQuote}
            onReply={onReply}
            onDelete={onDelete}
            noteById={noteById}
            onOpenImage={onOpenImage}
            mentionLookup={mentionLookup}
          />
          <NostrReplyThread
            targetId={r.id}
            replies={replies}
            profileMap={profileMap}
            reactions={reactions}
            reposts={reposts}
            selfPubkeyHex={selfPubkeyHex}
            loggedIn={loggedIn}
            onOpenUser={onOpenUser}
            onReact={onReact}
            onRepost={onRepost}
            onQuote={onQuote}
            onReply={onReply}
            onDelete={onDelete}
            noteById={noteById}
            onOpenImage={onOpenImage}
            mentionLookup={mentionLookup}
            depth={depth + 1}
          />
        </div>
      ))}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Nostr タイムライン。上部に投稿欄(kind 1)、本体にノート一覧とスレッド。
   ──────────────────────────────────────────────────────────────────── */
function NostrTimeline({
  notes,
  replies,
  reactions,
  reposts,
  profileMap,
  selfPubkeyHex,
  loggedIn,
  relayConnected,
  onOpenUser,
  onReact,
  onRepost,
  onReply,
  onQuote,
  onDelete,
  onPost,
  replyTarget,
  quoteTarget,
   onCancelReply,
   onCancelQuote,
   noteById: noteByIdProp,
   onOpenImage,
   emojis,
   mutedPubkeys,
   mentionLookup,
}: {
  notes: NostrEvent[];
  replies: Map<string, NostrEvent[]>;
  reactions: Map<string, NostrEvent[]>;
  reposts: Map<string, NostrEvent[]>;
  profileMap: Record<string, NostrEvent>;
  selfPubkeyHex: string;
  loggedIn: boolean;
  relayConnected: boolean;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (noteId: string, targetPubkey: string) => void;
  onRepost: (noteId: string, targetPubkey: string) => void;
  onReply: (noteId: string, targetPubkey: string) => void;
  onQuote: (noteId: string, targetPubkey: string) => void;
  onDelete: (ev: NostrEvent) => void;
  onPost: (
    text: string,
    replyTarget?: { id: string; pubkey: string } | null,
    quoteTarget?: { id: string; pubkey: string } | null,
  ) => Promise<void>;
  replyTarget: { id: string; pubkey: string } | null;
  quoteTarget: { id: string; pubkey: string } | null;
   onCancelReply: () => void;
   onCancelQuote: () => void;
   noteById: Record<string, NostrEvent>;
   onOpenImage: (url: string) => void;
   emojis: CustomEmojiDef[];
   mutedPubkeys: Set<string>;
   mentionLookup?: Map<string, { pk: string; name: string }> | null;
}) {
  const [text, setText] = useState('');
  const noteRef = useRef<HTMLTextAreaElement>(null);

  // 返信/引用モードに入ったら入力欄へ自動フォーカスする(Fodpr コンポーザと同じ挙動)
  useEffect(() => {
    if (replyTarget || quoteTarget) noteRef.current?.focus();
  }, [replyTarget, quoteTarget]);

  const noteIds = useMemo(() => new Set(notes.map((n) => n.id)), [notes]);
  // e タグが無いノート、または対象イベントが未取得のノートをトップレベル表示する
  // (ミュート中のユーザーは除外)
  const roots = useMemo(
    () =>
      sortNostrDesc(
        notes.filter((n) => {
          if (mutedPubkeys.has(n.pubkey)) return false;
          const p = firstETag(n);
          return !p || !noteIds.has(p);
        }),
      ),
    [notes, noteIds, mutedPubkeys],
  );

  const replyNote = replyTarget ? notes.find((n) => n.id === replyTarget.id) : undefined;
  const replyName = replyNote ? nostrDisplayName(replyNote.pubkey, profileMap) : undefined;
  const quoteNote = quoteTarget ? notes.find((n) => n.id === quoteTarget.id) : undefined;
  const quoteName = quoteNote ? nostrDisplayName(quoteNote.pubkey, profileMap) : undefined;

  const noteById = noteByIdProp ?? Object.fromEntries(notes.map((n) => [n.id, n]));

  // 大量取得時の描画負荷を抑えるため、初期表示は先頭 80 件に制限し「さらに表示」で増やす
  const [visible, setVisible] = useState(80);
  useEffect(() => setVisible(80), [roots]);

  function submit() {
    const t = text.trim();
    if (!t || !loggedIn) return;
    void onPost(t, replyTarget, quoteTarget);
    setText('');
    onCancelReply();
    onCancelQuote();
  }

  return (
    <div className="space-y-3">
      {loggedIn ? (
        <LiquidGlass intensity="subtle" refractive className="liquid-glass--card w-full">
          <div className="p-3">
            {replyTarget && replyNote && (
              <div className="mb-2 flex items-center justify-between rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs text-gray-400">
                <span>返信: <span className="text-gray-200">{replyName}</span></span>
                <button onClick={onCancelReply} className="text-gray-500 transition-colors hover:text-gray-300">
                  解除
                </button>
              </div>
            )}
            {quoteTarget && quoteNote && (
              <div className="mb-2 flex items-center justify-between rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs text-gray-400">
                <span>引用: <span className="text-gray-200">{quoteName}</span></span>
                <button onClick={onCancelQuote} className="text-gray-500 transition-colors hover:text-gray-300">
                  解除
                </button>
              </div>
            )}
            <textarea
              ref={noteRef}
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') submit();
              }}
              placeholder={replyTarget ? '返信を書く...' : quoteTarget ? '引用して投稿する...' : 'Nostr に投稿する...'}
              rows={3}
              className="w-full resize-none rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
            />
            <div className="mt-2 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <EmojiPicker
                  emojis={emojis}
                  onPick={(def) => {
                    if (noteRef.current) setText(insertTextAtCursor(noteRef.current, `:${def.shortcode}:`));
                  }}
                />
                <p className="text-xs text-gray-500">{text.length} 文字</p>
              </div>
              <button
                onClick={submit}
                disabled={!relayConnected || !text.trim()}
                className="rounded-xl bg-primary px-5 py-2 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:opacity-40"
              >
                投稿
              </button>
            </div>
          </div>
        </LiquidGlass>
      ) : (
        <p className="rounded-xl border border-white/10 bg-black/30 p-3 text-center text-sm text-gray-500">
          投稿するには nsec でログインしてください(閲覧だけなら下のタイムラインを利用できます)
        </p>
      )}

      {roots.length === 0 ? (
        <p className="pt-8 text-center text-sm text-gray-500">まだ投稿はありません</p>
      ) : (
        roots.slice(0, visible).map((n) => (
          <div key={n.id} className="space-y-2">
            <NostrNoteCard
              e={n}
              profileMap={profileMap}
              reactions={reactions.get(n.id)}
              reposts={reposts.get(n.id)}
              selfPubkeyHex={selfPubkeyHex}
              loggedIn={loggedIn}
              onOpenUser={onOpenUser}
              onReact={onReact}
              onRepost={onRepost}
               onQuote={onQuote}
               onReply={onReply}
               onDelete={onDelete}
               noteById={noteById}
               onOpenImage={onOpenImage}
               mentionLookup={mentionLookup}
             />
             <NostrReplyThread
               targetId={n.id}
               replies={replies}
               profileMap={profileMap}
               reactions={reactions}
               reposts={reposts}
               selfPubkeyHex={selfPubkeyHex}
               loggedIn={loggedIn}
               onOpenUser={onOpenUser}
               onReact={onReact}
               onRepost={onRepost}
               onQuote={onQuote}
               onReply={onReply}
               onDelete={onDelete}
               noteById={noteById}
               onOpenImage={onOpenImage}
               mentionLookup={mentionLookup}
             />
          </div>
        ))
      )}
      {roots.length > visible && (
        <div className="pt-1">
          <button
            onClick={() => setVisible((v) => v + 80)}
            className="w-full rounded-xl border border-white/10 bg-black/30 py-3 text-sm text-gray-300 transition-colors hover:bg-white/10"
          >
            さらに表示 ({roots.length - visible} 件)
          </button>
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   Nostr ユーザー詳細(モーダル)。kind 0 プロフィールと投稿一覧を表示する。
   ──────────────────────────────────────────────────────────────────── */
function NostrUserModal({
  pubkey,
  profileMap,
  notes,
  replies,
  onClose,
  ownRelayUrls,
  onAddRelay,
  mutedPubkeys,
  onToggleMute,
  onOpenUser,
}: {
  pubkey: string;
  profileMap: Record<string, NostrEvent>;
  notes: NostrEvent[];
  replies: Map<string, NostrEvent[]>;
  onClose: () => void;
  ownRelayUrls: string[];
  onAddRelay: (url: string) => void;
  mutedPubkeys: Set<string>;
  onToggleMute: (pubkey: string) => void;
  onOpenUser: (pubkey: string) => void;
}) {
  const profileEv = profileMap[pubkey];
  const meta = parseKind0Metadata(profileEv?.content ?? '');
  const profileEmojiMap = parseNostrEmojiTags(profileEv?.tags ?? []);
  const name = nostrDisplayName(pubkey, profileMap);
  const myNotes = useMemo(() => {
    const all = [...notes, ...[...replies.values()].flat()];
    return sortNostrDesc(all.filter((n) => n.pubkey === pubkey));
  }, [pubkey, notes, replies]);

  // プロフィール画面でもノート参照のインラインプレビュー用
  const userNoteById = useMemo(
    () => Object.fromEntries(myNotes.map((n) => [n.id, n])),
    [myNotes],
  );

  // このユーザーの kind 10002(NIP-65)を一度だけ取得して表示する
  const [theirRelays, setTheirRelays] = useState<RelayList | null>(null);
  const [theirRelaysErr, setTheirRelaysErr] = useState<string | null>(null);
  useEffect(() => {
    setTheirRelays(null);
    setTheirRelaysErr(null);
    fetchNostrRelayList(ownRelayUrls.length ? ownRelayUrls : DEFAULT_NOSTR_RELAYS, pubkey)
      .then((rl) => setTheirRelays(rl))
      .catch((e) => setTheirRelaysErr(e instanceof Error ? e.message : '取得失敗'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pubkey]);

  return createPortal(
    <>
      <button
        className="fixed inset-0 z-40 cursor-default bg-bg/90 backdrop-blur-sm"
        aria-hidden="true"
        onClick={onClose}
      />
      <div className="fixed left-1/2 top-1/2 z-50 max-h-[85vh] w-[min(92vw,36rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-2xl border border-white/15 bg-[#14161a] p-5 shadow-xl">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">{name}</h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onToggleMute(pubkey)}
              className={
                'rounded-full border px-3 py-1.5 text-xs transition-colors ' +
                (mutedPubkeys.has(pubkey)
                  ? 'border-primary/60 bg-primary/10 text-primary'
                  : 'border-white/15 text-gray-300 hover:bg-white/10')
              }
            >
              {mutedPubkeys.has(pubkey) ? 'ミュート解除' : 'ミュート'}
            </button>
            <button
              onClick={onClose}
              className="rounded-full border border-white/15 px-3 py-1.5 text-xs text-gray-300 transition-colors hover:bg-white/10"
            >
              閉じる
            </button>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Avatar picture={meta.picture ?? null} pubkeyHex={pubkey} name={name} className="h-14 w-14 text-xl" />
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-white">{name}</p>
            <p className="text-xs text-gray-500">{shortNpub(pubkey)}</p>
          </div>
        </div>
        {meta.about && (
          <p className="mt-3 whitespace-pre-wrap break-words text-sm text-gray-400">
            {renderCustomEmojis(meta.about, profileEmojiMap)}
          </p>
        )}

        {/* このユーザーの NIP-65 リレーリスト */
         !theirRelaysErr && (
          <div className="mt-3">
            {theirRelays && theirRelays.all.length > 0 ? (
              <>
                <p className="text-xs font-medium text-gray-300">このユーザーのリレー</p>
                <div className="mt-1.5 space-y-1">
                  {theirRelays.all.map((url) => (
                    <div key={url} className="flex items-center gap-1.5">
                      <code className="break-all text-[11px] text-gray-400">{url}</code>
                      {ownRelayUrls.includes(url) ? (
                        <span className="shrink-0 text-[10px] text-gray-500">登録済</span>
                      ) : (
                        <button
                          onClick={() => onAddRelay(url)}
                          className="shrink-0 rounded-lg border border-primary/40 px-1.5 py-0.5 text-[10px] font-semibold text-primary transition-colors hover:bg-primary/10"
                        >
                          追加
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <p className="text-xs text-gray-500">NIP-65 リレーリストは公開されていません</p>
            )}
          </div>
        )}
        {theirRelaysErr && <p className="mt-2 text-xs text-red-400">{theirRelaysErr}</p>}

        <code className="mt-3 block break-all rounded-xl bg-black/30 px-3 py-2.5 text-xs text-gray-300">{pubkey}</code>
         <div className="mt-4 space-y-2">
           {myNotes.length === 0 ? (
             <p className="text-center text-sm text-gray-500 pt-4">まだ投稿はありません</p>
           ) : (
             myNotes.map((n) => (
               <div key={n.id} className="rounded-xl border border-white/10 bg-black/20 p-3">
                 <p className="whitespace-pre-wrap break-words text-sm leading-relaxed text-gray-100">
                   {renderNostrContent(n.content, parseNostrEmojiTags(n.tags), userNoteById, buildNostrMentionLookup(profileMap), onOpenUser)}
                 </p>
                 <p className="mt-1 text-xs text-gray-500">{new Date(n.created_at * 1000).toLocaleString()}</p>
               </div>
             ))
           )}
         </div>
      </div>
    </>,
    document.body,
  );
}

/* ────────────────────────────────────────────────────────────────────
   Nostr 設定。リレー管理と nsec のログアウト。
   ──────────────────────────────────────────────────────────────────── */
function NostrSettingsView({
  relayUrls,
  onRelayChange,
  relayStatus,
  relayConnected,
  onLogout,
  secretHex,
  nip07Pubkey,
  loginMethod,
  passkeyCred,
  onNostrPasskeyRemove,
  onNostrSaveNsecToNosskey,
  relayList,
  mutedPubkeys,
  onToggleMute,
  profileMap,
}: {
  relayUrls: string[];
  onRelayChange: (urls: string[]) => void;
  relayStatus: NostrRelayStatus[];
   relayConnected: boolean;
   onLogout: () => void;
   secretHex: string | null;
   nip07Pubkey: string | null;
   loginMethod: 'nsec' | 'nip07' | 'passkey' | null;
   passkeyCred: NosskeyCred | null;
   onNostrPasskeyRemove: () => void;
   onNostrSaveNsecToNosskey: (nsecHex: string) => Promise<void>;
   relayList: RelayList | null;
   mutedPubkeys: Set<string>;
   onToggleMute: (pubkeyHex: string) => void;
   profileMap: Record<string, NostrEvent>;
}) {
  const [relayInput, setRelayInput] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // ログイン方法に応じた表示用 pubkey(np)と説明文
  const loggedPubkey = secretHex
    ? getPublicKeyFromSecret(secretHex)
    : nip07Pubkey ?? passkeyCred?.pubkey ?? null;
  const loginNote = loginMethod === 'nsec'
    ? 'nsec でログイン中'
    : loginMethod === 'nip07'
      ? 'ブラウザ拡張 (NIP-07) でログイン中'
      : loginMethod === 'passkey'
        ? 'パスキー (Nosskey) でログイン中 ※メモリのみ'
        : null;

  // NIP-65 リレーリストの全 URL を接続先リレーへ追加する
  function importRelays() {
    if (!relayList || relayList.all.length === 0) return;
    const added = relayList.all.filter((u) => !relayUrls.includes(u));
    if (added.length === 0) {
      setMsg('NIP-65 のリレーは全て登録済みです');
      setErr(null);
      return;
    }
    onRelayChange([...relayUrls, ...added]);
    setMsg(`NIP-65 のリレー ${added.length} 件を追加しました`);
    setErr(null);
  }

  const npub = useMemo(() => (loggedPubkey ? hexToNpub(loggedPubkey) : null), [loggedPubkey]);
  const maskedNsec = useMemo(() => {
    if (!secretHex) return null;
    const nsec = hexToNsec(secretHex);
    return nsec.length > 16 ? `${nsec.slice(0, 9)}…${nsec.slice(-6)}` : nsec;
  }, [secretHex]);

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

  return (
    <div className="space-y-3">
      <LiquidGlass intensity="subtle" refractive className="liquid-glass--card w-full">
        <div className="space-y-4 p-5">
          <h2 className="text-lg font-semibold text-white">Nostr 設定</h2>

          <div className="space-y-2">
            <label className="block text-xs text-gray-400">Nostr リレー (複数登録可)</label>
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
                placeholder="wss://relay.yoinekodo.jp/"
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

          {msg && <p className="text-sm text-green-400">{msg}</p>}
          {err && <p className="text-sm text-red-400">{err}</p>}
        </div>
      </LiquidGlass>

      {/* ミュート中のユーザー一覧 */}
      <MuteListCard
        mutedPubkeys={mutedPubkeys}
        onToggleMute={onToggleMute}
        displayNames={Object.fromEntries(Object.keys(profileMap).map((pk) => [pk, nostrDisplayName(pk, profileMap) ?? pk]))}
      />

      {/* NIP-65 リレーリスト(kind 10002) */}
      {loggedPubkey && (
        <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
          <div className="space-y-3 p-4">
            <p className="text-sm font-medium text-white">NIP-65 リレーリスト (kind 10002)</p>
            {relayList && relayList.all.length > 0 ? (
              <>
                <div className="space-y-1.5">
                  {relayList.all.map((url) => {
                    const role = relayList.both.includes(url)
                      ? '読み書き'
                      : relayList.read.includes(url)
                        ? '読み取り専用'
                        : '書き込み専用';
                    return (
                      <div key={url} className="flex items-center gap-2 rounded-xl bg-black/30 px-3 py-2">
                        <span className="min-w-0 flex-1 truncate text-xs text-gray-300">{url}</span>
                        <span className="shrink-0 rounded-lg border border-white/15 px-2 py-0.5 text-[10px] text-gray-400">
                          {role}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <p className="text-xs leading-relaxed text-gray-500">
                  読み取りは read リレー、書き込みは write リレーだけに送信されます。マーカーがないものは読み書き両用です。
                </p>
                <button
                  onClick={importRelays}
                  className="rounded-xl border border-primary/50 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary transition-colors hover:bg-primary/20"
                >
                  接続先リレーへ追加
                </button>
              </>
            ) : (
              <p className="text-xs text-gray-500">
                kind 10002 が公開されていません。接続先リレーへ手動で追加してください。
              </p>
            )}
          </div>
        </LiquidGlass>
      )}

      {/* ログイン状態 */}
      <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
        <div className="space-y-3 p-4">
           {loggedPubkey ? (
             <>
               <div className="space-y-1.5">
                 <p className="text-sm font-medium text-white">Nostr ログイン中 ({loginNote})</p>
                 <p className="break-all text-xs text-gray-400">{npub}</p>
                 {loginMethod === 'nsec' && secretHex && (
                   <code className="block break-all rounded-xl bg-black/30 px-3 py-2.5 text-xs text-gray-300">
                     {maskedNsec}
                   </code>
                 )}
               </div>
               <div className="flex items-center justify-between border-t border-white/10 pt-3">
                 <div>
                   <p className="text-sm font-medium text-white">Nostr をログアウト</p>
                   <p className="mt-0.5 text-xs text-gray-400">
                     {loginMethod === 'nsec'
                       ? 'ローカルの Nostr 秘密鍵を削除します'
                       : loginMethod === 'nip07'
                         ? 'ブラウザ拡張 (NIP-07) のログイン状態を解除します'
                          : 'パスキー (Nosskey) の再照認を要求します(メモリ上の秘密鍵を消去)'}
                   </p>
                 </div>
                 <button
                   onClick={onLogout}
                   className="rounded-xl border border-red-400/40 px-4 py-2 text-sm text-red-300 transition-colors hover:bg-red-400/10"
                 >
                   ログアウト
                 </button>
               </div>

{/* NIP-79 パスキー(credential)の管理: 登録済みなら削除(新規登録でアイデンティティ切替) */}
                {passkeyCred && (
                  <div className="flex items-center justify-between border-t border-white/10 pt-3">
                    <div>
                      <p className="text-sm font-medium text-white">パスキー (Nosskey) 登録を削除</p>
                      <p className="mt-0.5 text-xs text-gray-400">
                        保存済みパスキー credential を忘れます(新規登録で別アイデンティティ)
                      </p>
                    </div>
                    <button
                      onClick={onNostrPasskeyRemove}
                      className="rounded-xl border border-orange-400/40 px-4 py-2 text-sm text-orange-300 transition-colors hover:bg-orange-400/10"
                    >
                      削除
                    </button>
                  </div>
                )}

                {/* nsec を Nosskey (wrap mode) に保存: nsec でログイン中の場合のみ表示 */}
                {loginMethod === 'nsec' && secretHex && (
                  <div className="flex items-center justify-between border-t border-white/10 pt-3">
                    <div>
                      <p className="text-sm font-medium text-white">この nsec を Nosskey に保存</p>
                      <p className="mt-0.5 text-xs text-gray-400">
                        現在の nsec を PRF 派生鍵で暗号化してパスキーに保存します (wrap モード)
                      </p>
                    </div>
                    <button
                      onClick={() => void onNostrSaveNsecToNosskey(secretHex)}
                      className="rounded-xl border border-amber/40 bg-amber/5 px-4 py-2 text-sm text-amber transition-colors hover:bg-amber/10"
                    >
                      Nosskey に保存
                    </button>
                  </div>
                )}
              </>
            ) : passkeyCred ? (
             <div className="flex items-center justify-between">
               <div>
                 <p className="text-sm font-medium text-white">パスキー (Nosskey) が登録済み</p>
                 <p className="mt-0.5 text-xs text-gray-400">
                   ログイン画面の Nostr タブから「パスキーでログイン」で再生できます。
                 </p>
               </div>
               <button
                 onClick={onNostrPasskeyRemove}
                 className="rounded-xl border border-orange-400/40 px-4 py-2 text-sm text-orange-300 transition-colors hover:bg-orange-400/10"
               >
                 削除
               </button>
             </div>
           ) : (
             <p className="text-sm text-gray-400">
               nsec でログインしていません。ログイン画面の Nostr (nsec) タブからログインできます。
             </p>
           )}
        </div>
      </LiquidGlass>
    </div>
  );
}

/* ────────────────────────────────────────────────────────────────────
   自分の Nostr プロフィール(表示名・自己紹介・画像を kind 0 として公開)
   ──────────────────────────────────────────────────────────────────── */
function NostrProfileView({
  pubkeyHex,
  profileMap,
  relayConnected,
  onSave,
}: {
  pubkeyHex: string;
  profileMap: Record<string, NostrEvent>;
  relayConnected: boolean;
  onSave: (name: string, about: string, picture: string) => Promise<void>;
}) {
  const meta = useMemo(() => parseKind0Metadata(profileMap[pubkeyHex]?.content ?? ''), [profileMap, pubkeyHex]);
  const profileEmojiMap = useMemo(
    () => parseNostrEmojiTags(profileMap[pubkeyHex]?.tags ?? []),
    [profileMap, pubkeyHex],
  );
  const selfName = kind0DisplayName(meta) ?? shortNpub(pubkeyHex);
  const [name, setName] = useState(kind0DisplayName(meta) ?? '');
  const [about, setAbout] = useState(meta.about ?? '');
  const [picture, setPicture] = useState(meta.picture ?? '');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
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
      // 相対 URL は他のオリジン/リレー配信先では読めないため、絶対 URL にして保存する
      const absUrl = new URL(url, window.location.href).href;
      setPicture(absUrl);
      setPicStatus(`アップロードしました (${formatBytes(size)} に圧縮)`);
    } catch (e) {
      setPicErr(e instanceof Error ? e.message : 'アップロードに失敗しました');
    } finally {
      setPicBusy(false);
    }
  }

  async function save() {
    setErr(null);
    setMsg(null);
    setBusy(true);
    try {
      await onSave(name, about, picture);
      setMsg('Nostr のプロフィール(kind 0)を公開しました');
      setEditMode(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // 既定は閲覧表示。「編集」ボタンで編集モードへ入る
  const [editMode, setEditMode] = useState(false);

  // 編集モードに入ったら最新の kind 0 の値をフォームへ反映する
  useEffect(() => {
    if (editMode) {
      setName(kind0DisplayName(meta) ?? '');
      setAbout(meta.about ?? '');
      setPicture(meta.picture ?? '');
      setMsg(null);
      setErr(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editMode]);

  return (
    <LiquidGlass intensity="subtle" refractive className="liquid-glass--card w-full">
      <div className="space-y-4 p-5">
        <div className="flex items-center gap-4">
          <Avatar picture={meta.picture ?? null} pubkeyHex={pubkeyHex} name={selfName} className="h-20 w-20 text-2xl" />
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-semibold text-white">Nostr プロフィール</h2>
            <p className="mt-1 text-sm text-gray-400">kind 0 として全リレーへ公開されます</p>
            {!editMode && (
              <>
                <p className="truncate text-sm font-medium text-white">{kind0DisplayName(meta) || selfName}</p>
                {meta.about && (
                  <p className="mt-0.5 whitespace-pre-wrap break-words text-sm text-gray-400">
                    {renderCustomEmojis(meta.about, profileEmojiMap)}
                  </p>
                )}
              </>
            )}
            <p className="mt-1 break-all text-xs text-gray-500">{hexToNpub(pubkeyHex)}</p>
          </div>
          {editMode ? (
            <button
              onClick={() => setEditMode(false)}
              className="shrink-0 rounded-xl border border-white/15 px-4 py-2 text-sm text-gray-300 transition-colors hover:bg-white/10"
            >
              閉じる
            </button>
          ) : (
            <button
              onClick={() => setEditMode(true)}
              className="shrink-0 rounded-xl border border-primary/50 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary transition-colors hover:bg-primary/20"
            >
              編集
            </button>
          )}
        </div>

        {editMode ? (
          <>
            <div className="space-y-2">
              <label className="block text-xs text-gray-400">表示名</label>
              <input
                type="text"
                placeholder="表示名"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
              />
            </div>

            <div className="space-y-2">
              <label className="block text-xs text-gray-400">プロフィール画像 (直リンク URL または画像ファイル)</label>
              <input
                type="url"
                placeholder="https://example.com/icon.png"
                value={picture}
                onChange={(e) => setPicture(e.target.value)}
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
            </div>

            <div className="space-y-2">
              <label className="block text-xs text-gray-400">自己紹介 (任意)</label>
              <input
                type="text"
                placeholder="自己紹介"
                value={about}
                onChange={(e) => setAbout(e.target.value)}
                className="w-full rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
              />
            </div>

            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-1.5 text-xs">
                <span className={'h-2 w-2 rounded-full ' + (relayConnected ? 'bg-green-400' : 'bg-red-400')} />
                <span className={relayConnected ? 'text-green-400' : 'text-red-400'}>
                  {relayConnected ? 'リレーに接続中' : 'リレー未接続'}
                </span>
              </div>
              <button
                onClick={() => void save()}
                disabled={busy || !relayConnected}
                className="rounded-xl bg-primary px-5 py-2 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:opacity-40"
              >
                {busy ? '公開中...' : 'プロフィールを公開'}
              </button>
            </div>

            {msg && <p className="text-sm text-green-400">{msg}</p>}
            {err && <p className="text-sm text-red-400">{err}</p>}
          </>
        ) : (
          <>
            <div className="space-y-1.5">
              <label className="block text-xs text-gray-400">公開鍵</label>
              <code className="block break-all rounded-xl bg-black/30 px-3 py-2.5 text-xs text-gray-300">{hexToNpub(pubkeyHex)}</code>
            </div>
            <p className="text-xs text-gray-500">プロフィールを変更するには「編集」を押してください。</p>
          </>
        )}
      </div>
    </LiquidGlass>
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
  replies,
  links,
  reactions,
  eventByKey,
  selfPubkeyHex,
  selfRepostTargets,
  onBack,
  onOpenUser,
  onReact,
  onUndoReact,
  onRepost,
  onUndoRepost,
  onQuote,
  onReply,
  onDelete,
  mutedPubkeys,
  onToggleMute,
  mentionLookup,
}: {
  pubkeyHex: string;
  profileMap: Record<string, FodprEvent>;
  notes: FodprEvent[];
  binaries: FodprEvent[];
  replies: ReplyMap;
  links: FodprEvent[];
  reactions: ReactionMap;
  eventByKey: Map<string, FodprEvent>;
  selfPubkeyHex: string;
  selfRepostTargets: Set<string>;
  onBack: () => void;
  onOpenUser: (pubkeyHex: string) => void;
  onReact: (targetKey: string, emoji: string) => void;
  onUndoReact: (targetKey: string) => void;
  onRepost: (targetKey: string) => void;
  onUndoRepost: (targetKey: string) => void;
  onQuote: (targetKey: string) => void;
  onReply: (targetKey: string) => void;
  onDelete: (targetKey: string, targetEvent: FodprEvent) => void;
  mutedPubkeys: Set<string>;
  onToggleMute: (pubkeyHex: string) => void;
  mentionLookup: Map<string, MentionUser>;
}) {
  const prof = profileMap[pubkeyHex];
  const p = prof ? parseProfile(eventContentStr(prof)) : {};
  const name = p.name ?? pubkeyHex.slice(0, 12);
  const allReplyEvents: FodprEvent[] = [];
  for (const list of replies.values()) allReplyEvents.push(...list);
  const posts = sortPostsDesc(
    [...notes, ...binaries, ...allReplyEvents, ...links].filter((e) => CryptoUtils.bytesToHex(e.pubkey) === pubkeyHex),
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

          <div className="flex items-start gap-4">
            <Avatar picture={p.picture ?? null} pubkeyHex={pubkeyHex} name={name} className="h-20 w-20 text-2xl" />
            <div className="min-w-0 flex-1">
              <div className="flex items-start justify-between gap-2">
                <h2 className="truncate text-lg font-semibold text-white">{name}</h2>
                <button
                  onClick={() => onToggleMute(pubkeyHex)}
                  className={
                    'shrink-0 rounded-full border px-3 py-1.5 text-xs transition-colors ' +
                    (mutedPubkeys.has(pubkeyHex)
                      ? 'border-primary/60 bg-primary/10 text-primary'
                      : 'border-white/15 text-gray-300 hover:bg-white/10')
                  }
                >
                  {mutedPubkeys.has(pubkeyHex) ? 'ミュート解除' : 'ミュート'}
                </button>
              </div>
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
            replies={replies}
            eventByKey={eventByKey}
            selfPubkeyHex={selfPubkeyHex}
            selfRepostTargets={selfRepostTargets}
            onOpenUser={onOpenUser}
            onReact={onReact}
            onUndoReact={onUndoReact}
            onRepost={onRepost}
            onUndoRepost={onUndoRepost}
            onQuote={onQuote}
            onReply={onReply}
            onDelete={onDelete}
            mentionLookup={mentionLookup}
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
  nostrLoggedIn,
  onNostrImport,
}: {
  pubkeyHex: string;
  selfName: string;
  picture: string;
  name: string;
  about: string;
  onPictureChange: (v: string) => void;
  onNameChange: (v: string) => void;
  onAboutChange: (v: string) => void;
  onSave: () => Promise<void>;
  relayConnected: boolean;
  nostrLoggedIn: boolean;
  onNostrImport: (nsecInput?: string) => Promise<void>;
}) {
  const [picBusy, setPicBusy] = useState(false);
  const [picStatus, setPicStatus] = useState<string | null>(null);
  const [picErr, setPicErr] = useState<string | null>(null);
  const picFileRef = useRef<HTMLInputElement>(null);
  const [importBusy, setImportBusy] = useState(false);
  const [importMsg, setImportMsg] = useState<string | null>(null);
  const [importErr, setImportErr] = useState<string | null>(null);
  const [importNsec, setImportNsec] = useState('');
  // 既定は閲覧表示。「編集」ボタンで編集モードへ入る
  const [editMode, setEditMode] = useState(false);

  async function doSave() {
    await onSave();
    setEditMode(false);
  }

  async function doImport() {
    setImportErr(null);
    setImportMsg(null);
    setImportBusy(true);
    try {
      await onNostrImport(nostrLoggedIn ? undefined : importNsec.trim() || undefined);
      setImportMsg('Nostr のプロフィールをインポートしました');
      setImportNsec('');
    } catch (e) {
      setImportErr(e instanceof Error ? e.message : String(e));
    } finally {
      setImportBusy(false);
    }
  }

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
      // 相対 URL は他のオリジン/リレー配信先では読めないため、絶対 URL にして保存する
      onPictureChange(new URL(url, window.location.href).href);
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
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-semibold text-white">プロフィール</h2>
            {editMode ? (
              <p className="mt-1 text-sm text-gray-400">
                現在の表示名: <span className="font-medium text-primary">{selfName}</span>
              </p>
            ) : (
              <>
                <p className="truncate text-sm font-medium text-white">{name || selfName}</p>
                {about && <p className="mt-0.5 whitespace-pre-wrap break-words text-sm text-gray-400">{about}</p>}
              </>
            )}
          </div>
          {editMode ? (
            <button
              onClick={() => setEditMode(false)}
              className="shrink-0 rounded-xl border border-white/15 px-4 py-2 text-sm text-gray-300 transition-colors hover:bg-white/10"
            >
              閉じる
            </button>
          ) : (
            <button
              onClick={() => setEditMode(true)}
              className="shrink-0 rounded-xl border border-primary/50 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary transition-colors hover:bg-primary/20"
            >
              編集
            </button>
          )}
        </div>

        {editMode ? (
          <>
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

            <div className="space-y-2 border-t border-white/10 pt-4">
              <label className="block text-xs text-gray-400">Nostr からプロフィールをインポート</label>
              <p className="text-xs leading-relaxed text-gray-500">
                Nostr の kind 0 プロフィールから表示名・自己紹介・画像を取り込み、Fodpr のプロフィールとして保存します。
              </p>
              {!nostrLoggedIn && (
                <input
                  type="password"
                  placeholder="nsec1... または 64桁HEX"
                  value={importNsec}
                  onChange={(e) => setImportNsec(e.target.value)}
                  autoComplete="off"
                  className="w-full rounded-xl bg-black/30 px-3 py-2.5 text-sm text-gray-100 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-white/25"
                />
              )}
              <button
                onClick={() => void doImport()}
                disabled={importBusy || !relayConnected}
                className="rounded-xl border border-primary/50 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary transition-colors hover:bg-primary/20 disabled:opacity-40"
              >
                {importBusy ? 'インポート中...' : nostrLoggedIn ? 'Nostr からインポート' : 'nsec を指定してインポート'}
              </button>
              {importMsg && <p className="text-sm text-green-400">{importMsg}</p>}
              {importErr && <p className="text-sm text-red-400">{importErr}</p>}
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => void doSave()}
                disabled={!relayConnected || !name.trim()}
                className="rounded-xl bg-primary px-5 py-2 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover disabled:opacity-40"
              >
                プロフィールを保存
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="space-y-1.5">
              <label className="block text-xs text-gray-400">公開鍵</label>
              <code className="block break-all rounded-xl bg-black/30 px-3 py-2.5 text-xs text-gray-300">{pubkeyHex}</code>
            </div>
            <p className="text-xs text-gray-500">プロフィールを変更するには「編集」を押してください。</p>
          </>
        )}
      </div>
    </LiquidGlass>
  );
}

/* ────────────────────────────────────────────────────────────────────
   ミュート一覧(設定画面用の共通カード)。名前解決は profileMap から行う
   ──────────────────────────────────────────────────────────────────── */
function MuteListCard({
  mutedPubkeys,
  onToggleMute,
  displayNames,
  title = 'ミュート中',
}: {
  mutedPubkeys: Set<string>;
  onToggleMute: (pubkeyHex: string) => void;
  displayNames: Record<string, string>;
  title?: string;
}) {
  if (mutedPubkeys.size === 0) return null;
  const keys = Array.from(mutedPubkeys).sort();
  return (
    <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
      <div className="space-y-3 p-4">
        <p className="text-sm font-medium text-white">
          {title} ({keys.length})
        </p>
        <p className="text-xs leading-relaxed text-gray-500">
          ミュート中のユーザーの投稿・返信・通知は表示されません。解除はボタンから、またはそのユーザーの画面から行えます。
        </p>
        <div className="space-y-1.5">
          {keys.map((pk) => {
            const name = displayNames[pk] ?? pk.slice(0, 12);
            return (
              <div key={pk} className="flex items-center gap-2 rounded-xl bg-black/30 px-3 py-2">
                <span className="min-w-0 flex-1 truncate text-xs text-gray-300">{name}</span>
                <span className="shrink-0 font-mono text-[10px] text-gray-500">{pk.slice(0, 8)}…</span>
                <button
                  onClick={() => onToggleMute(pk)}
                  className="shrink-0 rounded-lg border border-white/15 px-2 py-1 text-xs text-gray-400 transition-colors hover:bg-white/10"
                >
                  ミュート解除
                </button>
              </div>
            );
          })}
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
  browserNotifEnabled,
  notifPermission,
  onToggleBrowserNotif,
  onRequestNotifPermission,
  mutedPubkeys,
  onToggleMute,
  profileMap,
  networkMode,
  onSetNetworkMode,
  networkPeerCount,
  networkGroups,
  networkLastError,
  networkBootstrapDone,
  onNetworkBootstrap,
  onNetworkCreateGroup,
  onNetworkJoinGroup,
  onNetworkCreateInvitation,
  onNetworkConnectInvitation,
  networkSeedNodes,
  invitationCode,
  setInvitationCode: _setInvitationCode,
}: {
  relayUrls: string[];
  onRelayChange: (urls: string[]) => void;
  relayStatus: RelayStatus[];
  relayConnected: boolean;
  onLogout: () => void;
  onShowDocs: () => void;
  secretHex: string | null;
  browserNotifEnabled: boolean;
  notifPermission: NotificationPermission;
  onToggleBrowserNotif: (next: boolean) => void;
  onRequestNotifPermission: () => void;
  mutedPubkeys: Set<string>;
  onToggleMute: (pubkeyHex: string) => void;
  profileMap: Record<string, FodprEvent>;
  networkMode: NetworkMode;
  onSetNetworkMode: (mode: NetworkMode) => void;
  networkPeerCount: number;
  networkGroups: (F2FGroupInfo | RtcGroupInfo)[];
  networkLastError: string | null;
  networkBootstrapDone: boolean;
  onNetworkBootstrap: () => void;
  onNetworkCreateGroup: () => void;
  onNetworkJoinGroup: (groupId: string) => void;
  onNetworkCreateInvitation: () => Promise<void>;
  onNetworkConnectInvitation: (code: string) => Promise<void>;
  networkSeedNodes: F2FPeerInfo[];
  invitationCode: string | null;
  setInvitationCode: (code: string | null) => void;
}) {
  const [relayInput, setRelayInput] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const fsec = useMemo(() => (secretHex ? hexToFsec(secretHex) : ''), [secretHex]);
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
            <label className="block text-xs text-gray-400">ブラウザ通知</label>
            <div className="flex items-center justify-between rounded-xl border border-white/10 bg-black/20 px-3 py-2.5">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-white">
                  {notifPermission === 'granted' ? '通知を許可済み' : '通知未許可'}
                </p>
                <p className="mt-0.5 text-xs text-gray-500">
                  新着返信・リアクションを OS 通知枠で受信します
                </p>
              </div>
              {typeof Notification !== 'undefined' && notifPermission !== 'granted' ? (
                <button
                  onClick={onRequestNotifPermission}
                  className="shrink-0 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-bg transition-colors hover:bg-primary-hover"
                >
                  許可する
                </button>
              ) : (
                <button
                  onClick={() => onToggleBrowserNotif(!browserNotifEnabled)}
                  aria-pressed={browserNotifEnabled}
                  className={
                    'shrink-0 rounded-xl border px-4 py-2 text-sm font-semibold transition-colors ' +
                    (browserNotifEnabled
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-white/15 text-gray-300 hover:bg-white/10')
                  }
                >
                  {browserNotifEnabled ? 'オン' : 'オフ'}
                </button>
              )}
            </div>
            {!!browserNotifEnabled && notifPermission !== 'granted' && (
              <p className="text-xs text-red-400">
                権限が許可されていません。ブラウザの通知設定を確認してください。
              </p>
            )}
          </div>

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

      {/* ネットワークモード設定。fsec 保有ユーザー(fodpr)のみ表示 */}
      {!!secretHex && (
        <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
          <div className="space-y-3 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-white">ネットワークモード</p>
                <p className="mt-0.5 text-xs text-gray-400">P2P 接続方式を選択します</p>
              </div>
            </div>

            <div className="space-y-2 border-t border-white/10 pt-3">
              <div className="flex flex-wrap gap-2">
                {(['f2f', 'rtcgroup', 'relay'] as NetworkMode[]).map((mode) => (
                  <button
                    key={mode}
                    onClick={() => onSetNetworkMode(mode)}
                    className={
                      'shrink-0 rounded-xl border px-4 py-2 text-sm font-semibold transition-colors ' +
                      (networkMode === mode
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-white/15 text-gray-300 hover:bg-white/10')
                    }
                  >
                    {mode === 'f2f' && 'F2F (WoT)'}
                    {mode === 'rtcgroup' && 'RtcGroup (ホスト昇格)'}
                    {mode === 'relay' && 'リレーのみ'}
                  </button>
                ))}
              </div>

              <p className="text-xs text-gray-400">
                {networkMode === 'f2f' && 'Web of Trust 方式。知り合いを介して最大50人まで接続し、招待コードまたはリレーシードでブートストラップ。'}
                {networkMode === 'rtcgroup' && 'ホスト昇格型。最初の接続者がホストとなり、ホスト離脱時に最古参加者が昇格。'}
                {networkMode === 'relay' && 'リレーサーバー経由のみ。P2P 接続を行いません。'}
              </p>

              {networkMode === 'f2f' && (
                <div className="space-y-2.5 border-t border-white/10 pt-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-400">接続ピア数</span>
                    <span className="text-sm font-semibold text-white">{networkPeerCount}</span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-400">キャッシュピア数</span>
                    <span className="text-sm font-semibold text-white">{networkSeedNodes.length}</span>
                  </div>

                  <div className="space-y-2 pt-2 border-t border-white/10">
                      <div className="space-y-2">
                        <p className="text-xs font-medium text-gray-300">招待コードで接続</p>
                        <div className="flex gap-2">
                          <input
                            type="text"
                            placeholder="招待コード (f2finv1...)"
                            className="flex-1 rounded-xl bg-black/30 border border-white/15 px-3 py-2 text-xs text-white placeholder-gray-500"
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') {
                                const code = e.currentTarget.value.trim();
                                if (code) {
                                  e.currentTarget.value = '';
                                  onNetworkConnectInvitation(code);
                                }
                              }
                            }}
                          />
                          <button
                            onClick={() => {
                              const code = prompt('招待コードを入力してください (f2finv1...)');
                              if (code?.trim()) onNetworkConnectInvitation(code.trim());
                            }}
                            className="shrink-0 rounded-xl border border-white/15 px-3 py-2 text-xs font-semibold text-gray-300 transition-colors hover:bg-white/10"
                          >
                            接続
                          </button>
                        </div>
                      </div>

                      <div className="space-y-2 pt-2 border-t border-white/10">
                        <div className="flex items-center gap-2">
                          <p className="text-xs font-medium text-gray-300 shrink-0 w-36">招待コード発行</p>
                          <button
                            onClick={async () => {
                              await onNetworkCreateInvitation();
                            }}
                            className="shrink-0 rounded-xl bg-primary px-3 py-2 text-xs font-semibold text-bg transition-colors hover:bg-primary-hover"
                          >
                            発行
                          </button>
                          {invitationCode && (
                            <>
                              <input
                                type="text"
                                value={invitationCode}
                                readOnly
                                className="flex-1 rounded-xl bg-black/30 border border-white/15 px-3 py-2 text-xs text-white font-mono select-all"
                              />
                              <button
                                onClick={async () => {
                                  await navigator.clipboard.writeText(invitationCode);
                                  setMsg?.('招待コードをコピーしました');
                                  setTimeout(() => setMsg?.(null), 2000);
                                }}
                                className="shrink-0 rounded-xl border border-white/15 px-3 py-2 text-xs font-semibold text-gray-300 transition-colors hover:bg-white/10"
                              >
                                コピー
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    {networkLastError && <p className="text-xs text-red-400">{networkLastError}</p>}

                  <div className="flex flex-wrap gap-2 pt-1">
                    <button
                      onClick={onNetworkBootstrap}
                      className="rounded-xl border border-white/15 px-3 py-1.5 text-xs font-semibold text-gray-300 transition-colors hover:bg-white/10"
                    >
                      {networkBootstrapDone ? '再取得' : 'シード取得'}
                    </button>
                  </div>

                  {networkSeedNodes.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs text-gray-400">シードから取得したピア候補</p>
                      {networkSeedNodes.slice(0, 5).map((p) => (
                        <div key={p.pubkey} className="flex items-center gap-2 rounded-xl bg-black/30 px-3 py-1.5">
                          <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-gray-400">
                            {p.pubkey.slice(0, 16)}…
                          </span>
                          <span className="shrink-0 text-[10px] text-gray-500">信頼 {p.trustScore.toFixed(2)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {networkMode === 'rtcgroup' && (
                <div className="space-y-2.5 border-t border-white/10 pt-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-400">接続ピア数</span>
                    <span className="text-sm font-semibold text-white">{networkPeerCount}</span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-400">参加グループ数</span>
                    <span className="text-sm font-semibold text-white">{networkGroups.length}</span>
                  </div>

                  {networkGroups.length > 0 && (
                    <div className="space-y-1.5">
                      {networkGroups.map((g) => (
                        <div key={g.groupId} className="rounded-xl bg-black/30 px-3 py-2">
                          <div className="flex items-center justify-between">
                            <span className="min-w-0 truncate text-xs text-gray-300">
                              {g.groupId.slice(0, 16)}… ({g.members.length}人)
                            </span>
                            <span
                              className={
                                'shrink-0 rounded-full px-2 py-0.5 text-[10px] ' +
                                (g.isHost ? 'bg-primary/20 text-primary' : 'bg-white/10 text-gray-300')
                              }
                            >
                              {g.isHost ? 'ホスト' : 'ゲスト'}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {networkLastError && <p className="text-xs text-red-400">{networkLastError}</p>}

                  <div className="flex flex-wrap gap-2 pt-1">
                    <button
                      onClick={onNetworkCreateGroup}
                      className="rounded-xl bg-primary px-3 py-1.5 text-xs font-semibold text-bg transition-colors hover:bg-primary-hover"
                    >
                      グループ作成 (ホストになる)
                    </button>
                    <button
                      onClick={() => {
                        const groupId = prompt('ホストの fpub を入力してください');
                        if (groupId) onNetworkJoinGroup(groupId.trim());
                      }}
                      className="rounded-xl border border-white/15 px-3 py-1.5 text-xs font-semibold text-gray-300 transition-colors hover:bg-white/10"
                    >
                      グループ参加 (ホスト fpub 指定)
                    </button>
                  </div>
                </div>
              )}

              {networkMode === 'relay' && (
                <div className="space-y-2.5 border-t border-white/10 pt-3">
                  <p className="text-xs text-gray-400">リレーサーバー経由でメッセージを送受信します。P2P 接続は行いません。</p>
                </div>
              )}
            </div>
          </div>
        </LiquidGlass>
      )}

      {/* ミュート中のユーザー一覧 */}
      <MuteListCard
        mutedPubkeys={mutedPubkeys}
        onToggleMute={onToggleMute}
        displayNames={Object.fromEntries(
          Object.entries(profileMap).map(([pk, ev]) => [pk, parseProfile(eventContentStr(ev)).name ?? pk]),
        )}
      />

      {/* 秘密鍵(マスク表示・コピー) + ログアウト。ゲスト(鍵なし)では非表示 */}
      {!!secretHex && (
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
          </div>
        </LiquidGlass>
      )}

      {/* クライアント実装ガイド(すべてのユーザーに公開) */}
      <LiquidGlass intensity="subtle" refractive={false} className="liquid-glass--card w-full">
        <div className="space-y-3 p-4">
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

// カスタム絵文字ピッカー(NIP-30 の :shortcode: を挿入する)
// 投稿欄の近くに配置し、クリックで絵文字グリッドを開く。
function EmojiPicker({
  onPick,
  align = 'left',
  emojis,
}: {
  onPick: (def: CustomEmojiDef) => void;
  align?: 'left' | 'right';
  emojis?: CustomEmojiDef[];
}) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const popRef = useRef<HTMLDivElement>(null);

  // 外側クリックで閉じる
  useEffect(() => {
    if (!open) return;
    function onClick(ev: MouseEvent) {
      const t = ev.target as Node;
      if (popRef.current?.contains(t) || btnRef.current?.contains(t)) return;
      setOpen(false);
    }
    function onKeydown(ev: KeyboardEvent) {
      if (ev.key === 'Escape') setOpen(false);
    }
    function closeOnScroll() {
      setOpen(false);
    }
    document.addEventListener('mousedown', onClick);
    document.addEventListener('keydown', onKeydown);
    window.addEventListener('scroll', closeOnScroll, true);
    window.addEventListener('resize', closeOnScroll);
    return () => {
      document.removeEventListener('mousedown', onClick);
      document.removeEventListener('keydown', onKeydown);
      window.removeEventListener('scroll', closeOnScroll, true);
      window.removeEventListener('resize', closeOnScroll);
    };
  }, [open]);

  // 画面内に収まるよう位置を補正(ポータル→body直下 fixed、overflow で隠れない)
  useLayoutEffect(() => {
    if (!open || !pos || !popRef.current) return;
    const pr = popRef.current.getBoundingClientRect();
    const W = 256; // w-64
    const g = 8;
    const left = Math.max(
      g,
      align === 'right'
        ? window.innerWidth - W - g
        : Math.min(pos.left, window.innerWidth - W - g),
    );
    let top = pos.top;
    if (top + pr.height > window.innerHeight - g) {
      const b = btnRef.current?.getBoundingClientRect();
      if (b) top = b.top - pr.height - g;
    }
    top = Math.max(g, top);
    setPos({ left, top });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function toggle() {
    if (open) {
      setOpen(false);
      return;
    }
    const r = btnRef.current?.getBoundingClientRect();
    if (!r) {
      setOpen(true);
      return;
    }
    setPos({ left: align === 'right' ? r.right - 256 : r.left, top: r.bottom + 6 });
    setOpen(true);
  }

  return (
    <div className="relative">
      <button
        ref={btnRef}
        onClick={toggle}
        title="カスタム絵文字"
        aria-label="カスタム絵文字"
        aria-expanded={open}
        className="shrink-0 rounded-xl border border-white/15 px-2.5 py-2 text-gray-300 transition-colors hover:bg-white/10"
      >
        <svg
          viewBox="0 0 24 24"
          className="h-5 w-5"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <circle cx="12" cy="12" r="10" />
          <path d="M8 14s1.5 2 4 2 4-2 4-2" />
          <line x1="9" y1="9" x2="9.01" y2="9" />
          <line x1="15" y1="9" x2="15.01" y2="9" />
        </svg>
      </button>
      {open &&
        createPortal(
          <div
            ref={popRef}
            className="fixed z-50 w-64 rounded-2xl border border-white/10 bg-[#14161a]/95 p-2 shadow-2xl backdrop-blur"
            style={pos ? { left: pos.left, top: pos.top } : undefined}
          >
            <div className="grid max-h-64 grid-cols-8 gap-1 overflow-y-auto">
              {(emojis ?? allEmojis()).map((e) => (
                <button
                  key={e.shortcode}
                  onClick={() => {
                    onPick(e);
                    setOpen(false);
                  }}
                  title={`:${e.shortcode}:`}
                  className="flex h-8 w-8 items-center justify-center rounded-lg transition-colors hover:bg-white/10"
                >
                  <img src={e.path} alt={e.shortcode} loading="lazy" className="h-6 w-6 object-contain" />
                </button>
              ))}
            </div>
            <p className="mt-1 border-t border-white/10 pt-1 text-center text-[10px] text-gray-500">
              :shortcode: として挿入されます
            </p>
          </div>,
          document.body,
        )}
    </div>
  );
}

// テキストエリアのカーソル位置へ文字列を挿入し、次の状態を返す
function insertTextAtCursor(textarea: HTMLTextAreaElement, text: string): string {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const next = textarea.value.slice(0, start) + text + textarea.value.slice(end);
  textarea.focus();
  requestAnimationFrame(() => {
    const pos = start + text.length;
    textarea.setSelectionRange(pos, pos);
  });
  return next;
}

/* ────────────────────────────────────────────────────────────────────
   ログイン画面
   fsec(Fodpr)/nsec(Nostr) の入力欄を分けて設け、鍵なしの閲覧モードも選べる。
   ──────────────────────────────────────────────────────────────────── */
function LoginScreen({
  onLogin,
  onGenerate,
  onNostrLogin,
  onNostrNip07Login,
  onNostrGenerate,
  onNostrPasskeyLogin,
  onNostrPasskeyRegister,
  onNostrNosskeyLogin,
  onNostrNosskeyRegister,
  onNostrSaveNsecToNosskey,
  passkeyRegistered,
  nosskeyRegistered,
  onGuest,
  nostrLoggedIn,
}: {
  onLogin: (input: string) => Promise<void>;
  onGenerate: () => Promise<void>;
  onNostrLogin: (input: string) => Promise<void>;
  onNostrNip07Login: () => Promise<void>;
  onNostrGenerate: () => Promise<void>;
  onNostrPasskeyLogin: () => Promise<void>;
  onNostrPasskeyRegister: () => Promise<void>;
  onNostrNosskeyLogin: () => Promise<void>;
  onNostrNosskeyRegister: () => Promise<void>;
  onNostrSaveNsecToNosskey: (nsecHex: string) => Promise<void>;
  passkeyRegistered: boolean;
  nosskeyRegistered: boolean;
  onGuest: () => void;
  nostrLoggedIn: boolean;
}) {
  const [tab, setTab] = useState<'fodpr' | 'nostr'>('fodpr');

  // NIP-07 / NIP-79 (Nosskey) が使えるか(ボタンの表示判定)
  const nip07Available = typeof window !== 'undefined' && !!window.nostr && typeof window.nostr.getPublicKey === 'function';
  const passkeyAvailable = nosskeySupported();
  const [keyInput, setKeyInput] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit() {
    setError('');
    setBusy(true);
    try {
      if (tab === 'fodpr') {
        await onLogin(keyInput);
      } else {
        await onNostrLogin(keyInput);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  // NIP-07 でログインする(拡張が無ければエラーを表示)
  async function nip07Login() {
    setError('');
    setBusy(true);
    try {
      await onNostrNip07Login();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  // ネイティブ パスキー (Passkey) でログイン/新規登録
  async function passkeyLogin() {
    setError('');
    setBusy(true);
    try {
      await onNostrPasskeyLogin();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  async function passkeyRegister() {
    setError('');
    setBusy(true);
    try {
      await onNostrPasskeyRegister();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  // Nosskey (nosskey-sdk) でログイン/新規登録
  async function nosskeyLogin() {
    setError('');
    setBusy(true);
    try {
      await onNostrNosskeyLogin();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  async function nosskeyRegister() {
    setError('');
    setBusy(true);
    try {
      await onNostrNosskeyRegister();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  // 入力された nsec を Nosskey に保存
  async function saveNsecToNosskey() {
    setError('');
    setBusy(true);
    try {
      await onNostrSaveNsecToNosskey(keyInput);
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

  async function generateNostr() {
    setError('');
    setBusy(true);
    try {
      await onNostrGenerate();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden text-gray-100">
      <div
        className="absolute inset-0 -z-10"
        style={{
          background:
            'radial-gradient(60rem 60rem at 20% -10%, rgb(77 160 255 / 0.22), transparent 60%), radial-gradient(50rem 50rem at 110% 20%, rgb(120 96 255 / 0.18), transparent 60%), #0e1012',
        }}
        aria-hidden="true"
      />
      <div className="relative z-10 flex min-h-screen items-center justify-center px-4">
        <LiquidGlass intensity="vision" refractive className="w-full max-w-md">
          <div className="space-y-4 p-7">
            <div>
              <h1 className="text-2xl font-semibold text-white">Prrr</h1>
              <p className="mt-1 text-sm text-gray-300">
                Fodpr と Nostr の両方のタイムラインを利用できます。鍵なしで閲覧だけする場合は下の「閲覧だけする」。
              </p>
            </div>

            {/* fsec / nsec のタブ */}
            <div className="flex gap-1 rounded-xl bg-black/30 p-1">
              {(
                [
                  { id: 'fodpr', label: 'Fodpr (fsec)' },
                  { id: 'nostr', label: 'Nostr (nsec)' },
                ] as const
              ).map((t) => (
                <button
                  key={t.id}
                  onClick={() => {
                    setTab(t.id);
                    setKeyInput('');
                    setError('');
                  }}
                  className={
                    'flex-1 rounded-lg px-3 py-2 text-sm transition-colors ' +
                    (tab === t.id ? 'bg-white/15 font-semibold text-white' : 'text-gray-400 hover:bg-white/5')
                  }
                >
                  {t.label}
                </button>
              ))}
            </div>

            <div className="space-y-2">
              {tab === 'fodpr' ? (
                <>
                  <label className="block text-xs text-gray-400">Fodpr 秘密鍵 (fsec または HEX)</label>
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
                </>
              ) : (
                <>
                  <label className="block text-xs text-gray-400">Nostr 秘密鍵 (nsec または HEX)</label>
                  <input
                    type="password"
                    placeholder="nsec1..."
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
                   {nostrLoggedIn && (
                      <p className="text-xs text-green-400">このブラウザには nsec が保存されています。</p>
                    )}
                  <button
                    onClick={() => void nip07Login()}
                    disabled={busy}
                    className="mt-2 w-full rounded-xl border border-primary/40 bg-primary/5 py-2 text-xs text-primary transition-colors hover:bg-primary/10 disabled:opacity-50"
                  >
                    {nip07Available
                      ? 'ブラウザ拡張 (NIP-07) でログイン'
                       : 'ブラウザ拡 (NIP-07) でログイン — 拡張がありません'}
                  </button>

                  {/* ネイティブ パスキー (Passkey) */}
                  <div className="mt-2 space-y-2">
                    <p className="text-xs text-gray-400">
                      パスキー (Passkey) : 端末の生体認証で Nostr 鍵を作成/ログイン。秘密鍵はパスキー内に保存されます。
                    </p>
                    {passkeyRegistered ? (
                      <button
                        onClick={() => void passkeyLogin()}
                        disabled={busy}
                        className="w-full rounded-xl border border-emerald/40 bg-emerald/5 py-2 text-xs text-emerald transition-colors hover:bg-emerald/10 disabled:opacity-50"
                      >
                        {busy ? '処理中...' : 'パスキー (Passkey) でログイン'}
                      </button>
                    ) : (
                      <button
                        onClick={() => void passkeyRegister()}
                        disabled={busy || !passkeyAvailable}
                        className="w-full rounded-xl border border-emerald/40 bg-emerald/5 py-2 text-xs text-emerald transition-colors hover:bg-emerald/10 disabled:opacity-50"
                      >
                        {!passkeyAvailable
                          ? 'パスキー (Passkey) で新規登録 — 使えません'
                          : busy
                            ? '処理中...'
                            : 'パスキー (Passkey) で新規登録'}
                      </button>
                    )}
                  </div>

                  {/* Nosskey (nosskey-sdk) */}
                  <div className="mt-2 space-y-2">
                    <p className="text-xs text-gray-400">
                      Nosskey : nosskey-sdk を使用。PRF 派生鍵または nsec を暗号化保存。パスキー UI 以外の選択肢として利用可能。
                    </p>
                    {nosskeyRegistered ? (
                      <button
                        onClick={() => void nosskeyLogin()}
                        disabled={busy}
                        className="w-full rounded-xl border border-blue/40 bg-blue/5 py-2 text-xs text-blue transition-colors hover:bg-blue/10 disabled:opacity-50"
                      >
                        {busy ? '処理中...' : 'Nosskey でログイン'}
                      </button>
                    ) : (
                      <button
                        onClick={() => void nosskeyRegister()}
                        disabled={busy || !passkeyAvailable}
                        className="w-full rounded-xl border border-blue/40 bg-blue/5 py-2 text-xs text-blue transition-colors hover:bg-blue/10 disabled:opacity-50"
                      >
                        {!passkeyAvailable
                          ? 'Nosskey で新規登録 — 使えません'
                          : busy
                            ? '処理中...'
                            : 'Nosskey で新規登録'}
                      </button>
                    )}
                    {/* 既存の nsec を Nosskey に保存 (wrap モード) */}
                    {(keyInput.trim() && (keyInput.startsWith('nsec') || /^[0-9a-fA-F]{64}$/.test(keyInput))) && (
                      <button
                        onClick={() => void saveNsecToNosskey()}
                        disabled={busy || !passkeyAvailable}
                        className="w-full rounded-xl border border-amber/40 bg-amber/5 py-2 text-xs text-amber transition-colors hover:bg-amber/10 disabled:opacity-50"
                      >
                        {busy ? '処理中...' : 'この nsec を Nosskey に保存'}
                      </button>
                    )}
                  </div>
                </>
              )}
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
              {tab === 'fodpr' ? (
                <button
                  onClick={() => void generate()}
                  disabled={busy}
                  className="w-full rounded-xl border border-white/15 py-2.5 text-sm text-gray-300 transition-colors hover:bg-white/10"
                >
                  新しい鍵を生成
                </button>
              ) : (
                <button
                  onClick={() => void generateNostr()}
                  disabled={busy}
                  className="w-full rounded-xl border border-white/15 py-2.5 text-sm text-gray-300 transition-colors hover:bg-white/10"
                >
                  Nostr の新しい鍵を生成
                </button>
              )}
              <button
                onClick={onGuest}
                disabled={busy}
                className="w-full rounded-xl border border-white/15 py-2.5 text-sm text-gray-300 transition-colors hover:bg-white/10"
              >
                閲覧だけする(鍵なし)
              </button>
            </div>

            <p className="text-xs leading-relaxed text-gray-400">
              fsec と nsec は別々に保存されます(いずれも AES-256-GCM で暗号化、復号鍵はブラウザの IndexedDB に保持)。
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
export default App;
