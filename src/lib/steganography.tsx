// steganography.tsx
// -----------------
// Nostr/Fodpr 投稿の絵文字に Unicode タグ文字(U+E0100–U+E01EF)で
// 潜在的に埋め込まれた隠しテキストを検出して復号・表示する。
//
// エンコードは行わない(デコードのみ)。encodeHiddenTagChars は互換性のために
// 載走しているが、アプリ本体では使用しない。
//
// 対応する独立ツール: public/docs.html の `セクシー餃子` ページ(gyouza.html)の
// ロジックと同じコードポイントオフセット(0xE00F0)を使い、互換性を保つ。

import { memo, useState } from 'react';

// タグ文字(隠しテキストの本体)を表す正規表現
const TAG_RE = /[\u{E0100}-\u{E01EF}]/u;

// テキストに隠しタグ文字が含まれているか
export function hasHiddenTagChars(text: string): boolean {
  return TAG_RE.test(text || '');
}

// タグ文字列を UTF-8 テキストに復号する。失敗/空なら null。
// byte = codePoint - 0xE00F0 (gyouza.html と同じオフセット)
export function decodeTagChars(tagStr: string): string | null {
  try {
    const bytes: number[] = [];
    for (const ch of tagStr) {
      const cp = ch.codePointAt(0);
      if (cp === undefined) continue;
      if (cp >= 0xe0100 && cp <= 0xe01ef) bytes.push(cp - 0xe00f0);
    }
    if (bytes.length === 0) return null;
    return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}

// ── グラフクラスタ(絵文字)の末尾を返すヘルパ ─────────────────

// 文字列の先頭にある1つのグラフクラスタの長さを返す
function getGraphemeClusterEnd(text: string): number {
  if (!text) return 0;
  if (typeof Intl !== 'undefined' && Intl.Segmenter) {
    try {
      const segmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
      for (const segment of segmenter.segment(text)) {
        return segment.index + segment.segment.length;
      }
    } catch {
      /* fall through */
    }
  }
  const flagPattern = /[\u{1F1E6}-\u{1F1FF}]{2}/u;
  const flagMatch = flagPattern.exec(text);
  if (flagMatch && flagMatch.index === 0) return flagMatch[0].length;
  const emojiPattern =
    /(?:[\p{Emoji_Presentation}\p{Extended_Pictographic}](?:\u{FE0E}|\u{FE0F})?(?:\u200D[\p{Emoji_Presentation}\p{Extended_Pictographic}](?:\u{FE0E}|\u{FE0F})?)*)(?:[\u{1F3FB}-\u{1F3FF}])?/u;
  const match = emojiPattern.exec(text);
  if (match) return match[0].length;
  return text.length > 0 ? 1 : 0;
}

// 文字列の末尾グラフクラスタの [start, end) を返す
function getLastGraphemeClusterRange(text: string): { start: number; end: number } {
  if (!text) return { start: 0, end: 0 };
  if (typeof Intl !== 'undefined' && Intl.Segmenter) {
    try {
      const segmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
      let last: { index: number; segment: string } | null = null;
      for (const segment of segmenter.segment(text)) {
        last = { index: segment.index, segment: segment.segment };
      }
      if (last) return { start: last.index, end: last.index + last.segment.length };
    } catch {
      /* fall through */
    }
  }
  let start = 0;
  let end = 0;
  while (end < text.length) {
    start = end;
    const len = getGraphemeClusterEnd(text.slice(end));
    end += len || 1;
  }
  return { start, end };
}

// --- encode (互換載走。アプリ本体での使用は想定しない) ---

// 文字列を Unicode タグ文字列へエンコードする(gyouza.html と同じ)
export function encodeHiddenTagChars(emoji: string, hiddenText: string): string {
  if (!emoji || !hiddenText) return emoji;
  const { start, end } = getLastGraphemeClusterRange(emoji);
  const prefix = emoji.slice(0, start);
  const target = emoji.slice(start, end);
  const suffix = emoji.slice(end);
  let out = prefix + target;
  const bytes = new TextEncoder().encode(hiddenText);
  for (const byte of bytes) {
    out += String.fromCodePoint(byte + 0xe00f0);
  }
  return out + suffix;
}

// ── デコード表示 ─────────────────────────────────────────────

// 隠しタグ文字列の並びを走査する正規表現(タグ文字2文字以上を1塊)
const TAG_SEQ_RE = /[\u{E0100}-\u{E01EF}]+/gu;

export type StegSegment =
  | { kind: 'text'; text: string }
  | { kind: 'hidden'; emoji: string; hidden: string };

// テキストを走査し、隠しテキスト付きの絵文字と通常テキストへ分割する。
// タグ文字の直前にあるグラフクラスタを「見える絵文字」、タグ文字列を復号したものを
// 「隠しテキスト」とする(gyouza.html の processHiddenTagChars と等価)。
export function splitSteganography(text: string): StegSegment[] {
  const out: StegSegment[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = TAG_SEQ_RE.exec(text)) !== null) {
    const tagStart = m.index;
    const tagStr = m[0];
    // タグ文字の直前のグラフクラスタを可視絵文字とする
    const head = text.slice(0, tagStart);
    const { start } = getLastGraphemeClusterRange(head);
    const emoji = head.slice(start);
    if (start > last) out.push({ kind: 'text', text: text.slice(last, start) });
    out.push({ kind: 'hidden', emoji, hidden: decodeTagChars(tagStr) ?? '' });
    last = tagStart + tagStr.length;
  }
  if (last < text.length) out.push({ kind: 'text', text: text.slice(last) });
  return out;
}

// 隠しテキストをポップアップで表示する絵文字スパン
const HiddenEmoji = memo(function HiddenEmoji({ emoji, hidden }: { emoji: string; hidden: string }) {
  const [open, setOpen] = useState(false);
  return (
    <span
      className="relative inline-block cursor-pointer border-b-2 border-dotted decoration-gray-400/60"
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        setOpen((o) => !o);
      }}
      title="クリックで隠しテキストを表示"
      role="button"
      aria-label="隠しテキストあり"
    >
      {emoji}
      {open && (
        <span
          className="pointer-events-none absolute top-full left-1/2 z-50 -translate-x-1/2 mt-1.5
            w-max max-w-xs rounded-lg border border-white/20 bg-[#1a1324] px-2.5 py-1.5 text-xs text-gray-200 shadow-xl"
          style={{ wordBreak: 'break-all' }}
        >
          {hidden}
        </span>
      )}
    </span>
  );
});

// テキスト中の隠しタグ文字を検出してクリックで復号表示するコンポーネント。
// タグ文字が含まれないテキストはそのまま高速にそのまま返す。
const SteganographyText = memo(function SteganographyText({ content }: { content: string }) {
  if (!content || !hasHiddenTagChars(content)) {
    return <>{content}</>;
  }
  const segments = splitSteganography(content);
  return (
    <>
      {segments.map((seg, i) =>
        seg.kind === 'text' ? (
          <span key={`t${i}`}>{seg.text}</span>
        ) : (
          <HiddenEmoji key={`h${i}`} emoji={seg.emoji} hidden={seg.hidden} />
        ),
      )}
    </>
  );
});

export { SteganographyText };
export default SteganographyText;
