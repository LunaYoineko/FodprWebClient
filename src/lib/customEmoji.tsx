// customEmoji.ts
// ----------------
// NIP-30(カスタム絵文字)と、それに相当する Fodpr 側の実装を共有するモジュール。
//
// - Nostr: content 内の `:shortcode:` を、イベントの ["emoji", shortcode, url]
//   タグで解決してインライン画像として表示する。投稿時は使用している
//   shortcode に対応する emoji タグをイベントへ付与する。
// - Fodpr: 同じ `:shortcode:` 記法を、`emoji:<shortcode>:<url>` 形式のタグで
//   実現する(他の Fodpr タグ `reply:` / `react:` 等と同じプレフィックス規約)。

import type { ReactNode } from 'react';
import type { NostrTags, NostrEvent } from './nostrProtocol';
import { decodeNostrUri, type NostrInlineEntity } from './nostrProtocol';
import { SteganographyText } from './steganography';

// ビルトインのカスタム絵文字パック。画像は public/emoji/ 配下の SVG。
// path は origin 相対。投稿時は絶対 URL へ変換してタグへ埋め込む。
export interface CustomEmojiDef {
  shortcode: string;
  path: string;
  label: string;
}

export const CUSTOM_EMOJI: CustomEmojiDef[] = [
  { shortcode: 'prrr', path: '/emoji/prrr.svg', label: 'Prrr' },
  { shortcode: 'fodpr', path: '/emoji/fodpr.svg', label: 'Fodpr' },
  { shortcode: 'love', path: '/emoji/love.svg', label: 'love' },
  { shortcode: 'laugh', path: '/emoji/laugh.svg', label: 'laugh' },
  { shortcode: 'cool', path: '/emoji/cool.svg', label: 'cool' },
  { shortcode: 'wow', path: '/emoji/wow.svg', label: 'wow' },
  { shortcode: 'think', path: '/emoji/think.svg', label: 'think' },
  { shortcode: 'cry', path: '/emoji/cry.svg', label: 'cry' },
  { shortcode: 'angry', path: '/emoji/angry.svg', label: 'angry' },
  { shortcode: 'ok', path: '/emoji/ok.svg', label: 'ok' },
  { shortcode: 'party', path: '/emoji/party.svg', label: 'party' },
  { shortcode: 'fire', path: '/emoji/fire.svg', label: 'fire' },
  { shortcode: 'star', path: '/emoji/star.svg', label: 'star' },
  { shortcode: 'zzz', path: '/emoji/zzz.svg', label: 'zzz' },
  { shortcode: 'pray', path: '/emoji/pray.svg', label: 'pray' },
  { shortcode: 'robot', path: '/emoji/robot.svg', label: 'robot' },
];

// shortcode の正規化(allowlist)。NIP-30: 英数字・ハイフン・アンダースコアのみ。
const SHORTCODE_RE = /^[A-Za-z0-9_-]+$/;

const PACK_BY_CODE: Record<string, CustomEmojiDef> = Object.fromEntries(
  CUSTOM_EMOJI.map((e) => [e.shortcode, e]),
);

// ── 外部(emoemo / NIP-30 パック)絵文字のランタイム登録 ──────────────
// ビルトインパックに加えて、Nostr の kind 10030(マイ絵文字リスト)や
// kind 30030(絵文字パック)から取得した絵文字を shortcode で解決できるようにする。
// 登録順(ビルトイン → emoemo)で後勝ちにすることで、パック側のカスタム絵文字を優先する。
const EXTERNAL_BY_CODE = new Map<string, CustomEmojiDef>();

export function registerExternalEmoji(def: CustomEmojiDef): void {
  EXTERNAL_BY_CODE.set(def.shortcode, def);
}

export function clearExternalEmojis(): void {
  EXTERNAL_BY_CODE.clear();
}

export function isExternalEmoji(code: string): boolean {
  return EXTERNAL_BY_CODE.has(code);
}

// shortcode → 定義(ビルトイン + 外部)を解決する
export function resolveEmojiDef(code: string): CustomEmojiDef | undefined {
  return EXTERNAL_BY_CODE.get(code) ?? PACK_BY_CODE[code];
}

// ピッカー用の一覧(ビルトイン + 外部、shortcode の重複は外部を優先)
export function allEmojis(): CustomEmojiDef[] {
  const seen = new Set<string>();
  const out: CustomEmojiDef[] = [];
  for (const e of CUSTOM_EMOJI) {
    seen.add(e.shortcode);
    out.push(e);
  }
  for (const e of EXTERNAL_BY_CODE.values()) {
    if (!seen.has(e.shortcode)) {
      seen.add(e.shortcode);
      out.push(e);
    }
  }
  return out;
}

// Nostr の kind 10030(マイ絵文字リスト) / kind 30030(絵文字パック)から
// 絵文字定義を抽出する。パックには d タグの識別子を label として付与する。
export function parseEmoemoEvents(events: { kind: number; tags: NostrTags }[]): CustomEmojiDef[] {
  const out: CustomEmojiDef[] = [];
  for (const e of events) {
    if (e.kind !== 10030 && e.kind !== 30030) continue;
    const ident = e.tags.find((t) => t[0] === 'd' && typeof t[1] === 'string' && t[1])?.[1] ?? '';
    const packName = ident || (e.kind === 30030 ? 'emoemo' : 'マイ絵文字');
    for (const t of e.tags) {
      if (t[0] === 'emoji' && typeof t[1] === 'string' && t[1] && typeof t[2] === 'string' && t[2]) {
        out.push({ shortcode: t[1], path: t[2], label: `${packName}: ${t[1]}` });
      }
    }
  }
  return out;
}

export function isValidShortcode(code: string): boolean {
  return SHORTCODE_RE.test(code);
}

// origin 相対 path → 絶対 URL(NIP-30 のタグは絶対 URL でないと他クライアントで解決できない)
export function emojiAbsoluteUrl(path: string): string {
  try {
    return new URL(path, window.location.href).toString();
  } catch {
    return path;
  }
}

// content から `:shortcode:` を収集して重複排除する
export function extractEmojiShortcodes(content: string): string[] {
  const seen: string[] = [];
  const set = new Set<string>();
  const re = /:([A-Za-z0-9_-]+):/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const code = m[1];
    if (!set.has(code)) {
      set.add(code);
      seen.push(code);
    }
  }
  return seen;
}

// ビルトインパック + emoemo 登録済みの shortcode を対象にする
function usedPackEmojis(content: string): CustomEmojiDef[] {
  return extractEmojiShortcodes(content)
    .map((code) => resolveEmojiDef(code))
    .filter((e): e is CustomEmojiDef => !!e);
}

// ── Nostr(NIP-30) ────────────────────────────────────────────────

// content で使われている shortcode 分の ["emoji", shortcode, url] タグを作る
export function buildNostrEmojiTags(content: string): NostrTags {
  return usedPackEmojis(content).map((e) => ['emoji', e.shortcode, emojiAbsoluteUrl(e.path)]);
}

// イベントの tags から shortcode → 絶対URL のマップを組み立てる
export function parseNostrEmojiTags(tags: NostrTags): Record<string, string> {
  const map: Record<string, string> = {};
  for (const t of tags) {
    if (t[0] === 'emoji' && typeof t[1] === 'string' && typeof t[2] === 'string') {
      map[t[1]] = t[2];
    }
  }
  return map;
}

// ── Fodpr(NIP-30 相当) ───────────────────────────────────────────

// content で使われている shortcode 分の `emoji:<shortcode>:<url>` タグを作る
export function buildFodprEmojiTags(content: string): string[] {
  return usedPackEmojis(content).map((e) => `emoji:${e.shortcode}:${emojiAbsoluteUrl(e.path)}`);
}

// Fodpr イベントの tags から shortcode → URL のマップを組み立てる
export function parseFodprEmojiTags(tags: string[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (const t of tags) {
    if (!t.startsWith('emoji:')) continue;
    const rest = t.slice('emoji:'.length);
    const colon = rest.indexOf(':');
    if (colon === -1) continue;
    const code = rest.slice(0, colon);
    const url = rest.slice(colon + 1);
    if (code && url) map[code] = url;
  }
  return map;
}

// ── 共通レンダリング ────────────────────────────────────────────

// content の `:shortcode:` を emojiMap(shortcode→URL)で解決して React 要素へ変換する。
// 解決できない shortcode は原文のまま残す(NIP-30 のフォールバック規則)。
export function renderCustomEmojis(content: string, emojiMap: Record<string, string>): ReactNode[] {
  const parts = content.split(/(:[A-Za-z0-9_-]+:)/g);
  const out: ReactNode[] = [];
  for (const part of parts) {
    if (!part) continue;
    const m = /^:([A-Za-z0-9_-]+):$/.exec(part);
    if (m) {
      const url = emojiMap[m[1]];
      if (url) {
        out.push(
          <img
            key={`e${out.length}`}
            src={url}
            alt={m[1]}
            title={m[1]}
            loading="lazy"
            className="inline-block h-[1.35em] w-[1.35em] max-w-[1.35em] align-[-0.25em] rounded-[0.2em] object-contain"
          />,
        );
        continue;
      }
    }
    out.push(<SteganographyText key={`t${out.length}`} content={part} />);
  }
  return out;
}

// ── Nostr(NIP-21) インライン参照 ──────────────────────────────────

// 裸 NIP-19 bech32 トークン(npub/note/nprofile/nevent/naddr + データ)
const BARE_BCH_RE = /(npub1|note1|nprofile1|nevent1|naddr1)[0-9a-z]{6,}/;

// content の `:shortcode:` / `nostr:<uri>` / 裸 bech32 トークン / `@名前` メンションを
// 走査し React 要素列へ変換する。emojiMap は :shortcode: の解決用。
// noteById が与えられた場合、note 参照先がキャッシュ済みならインラインプレビューを埋め込む。
// mentionLookup / onOpenUser が与えられた場合、@名前/@hex/@npub メンションを
// プロフィールを開くボタンとして描画する。
export function renderNostrContent(
  content: string,
  emojiMap: Record<string, string>,
  noteById: Record<string, NostrEvent> | null = null,
  mentionLookup: Map<string, { pk: string; name: string }> | null = null,
  onOpenUser: ((pk: string) => void) | null = null,
): ReactNode[] {
  const TOKEN_RE = new RegExp(
    '(' +
      // NIP-21 URI
      'nostr:(?:npub|note|nprofile|nevent|naddr)1[0-9a-z]+' +
      '|' +
      // 裸 NIP-19
      '(?:npub|note|nprofile|nevent|naddr)1[0-9a-z]+' +
      '|' +
      // shortcode
      ':[A-Za-z0-9_-]+:' +
      '|' +
      // @メンション
      '@[^\\s@,。、!！?？;；]+' +
      ')',
    'gi',
  );

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
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (!part) continue;
    const seq = i;

    const emoji = /^:([A-Za-z0-9_-]+):$/.exec(part);
    if (emoji) {
      const url = emojiMap[emoji[1]];
      if (url) {
        out.push(
          <img
            key={`e${seq}`}
            src={url}
            alt={emoji[1]}
            title={`:${emoji[1]}:`}
            loading="lazy"
            className="inline-block h-[1.35em] w-[1.35em] max-w-[1.35em] align-[-0.25em] rounded-[0.2em] object-contain"
          />,
        );
        continue;
      }
    }

    const uri = /^nostr:(.+)$/i.exec(part);
    if (uri) {
      out.push(...renderEntity(safeDecode(uri[1]), uri[1], noteById, seq));
      continue;
    }

    const bare = BARE_BCH_RE.exec(part);
    if (bare) {
      out.push(...renderEntity(safeDecode(bare[0]), bare[0], noteById, seq));
      continue;
    }

    const mention = /^@(.+)$/.exec(part);
    if (mention) {
      const u = mentionLookup?.get(mention[1]);
      if (u && onOpenUser) {
        out.push(
          <button
            key={`m${seq}`}
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

    out.push(<SteganographyText key={`t${seq}`} content={part} />);
  }
  return out;
}

function safeDecode(s: string): NostrInlineEntity {
  try {
    return decodeNostrUri(s);
  } catch {
    return { type: 'unknown', value: s };
  }
}

function shortHex(hex: string): string {
  return hex.length > 16 ? hex.slice(0, 8) + '…' : hex;
}

function renderEntity(
  ent: NostrInlineEntity,
  raw: string,
  noteById: Record<string, NostrEvent> | null,
  seq: number,
): ReactNode[] {
  if (ent.type === 'note') {
    const ref = noteById ? noteById[ent.value] : null;
    if (ref) {
      const snippet = (ref.content || '').replace(/\s+/g, ' ').trim().slice(0, 80);
      return [
        <a
          key={`n${seq}`}
          href={`nostr:${raw}`}
          onClick={(e) => e.preventDefault()}
          className="inline-flex flex-col items-start gap-0.5 rounded-lg border border-white/10 bg-black/30 px-2.5 py-1.5 text-xs text-gray-200 underline decoration-1 underline-offset-1"
        >
          <span className="font-mono text-xs text-gray-400">#{shortHex(ent.value)}</span>
          <span className="block break-words text-gray-300">{snippet || '投稿へ移動'}</span>
        </a>,
      ];
    }
    return [
      <a
        key={`n${seq}`}
        href={`nostr:${raw}`}
        className="font-mono text-xs text-primary underline underline-offset-2 decoration-1"
        title="nostr クライアントで開く"
      >
        #{shortHex(ent.value)}
      </a>,
    ];
  }

  if (ent.type === 'npub' || ent.type === 'nprofile') {
    const id = ent.type === 'npub' ? ent.value : ent.value.pubkey;
    return [
      <a
        key={`p${seq}`}
        href={`nostr:${raw}`}
        className="font-mono text-xs text-primary underline underline-offset-2 decoration-1"
        title="nostr クライアントで開く"
      >
        npub…{id.slice(0, 6)}
      </a>,
    ];
  }

  return [
    <a
      key={`u${seq}`}
      href={`nostr:${raw}`}
      className="font-mono text-xs text-primary underline underline-offset-2 decoration-1"
      title="nostr クライアントで開く"
    >
      {raw.slice(0, 24)}…
    </a>,
  ];
}
