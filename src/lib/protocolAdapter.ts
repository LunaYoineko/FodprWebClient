// protocolAdapter.ts
// --------------------
// Fodpr と Nostr のイベントを統一的な UnifiedEvent 形に正規化する。
// UI コンポーネントはこの UnifiedEvent 型だけを扱う。

import { CryptoUtils } from '@fodpr/crypto';
import {
  TransTypeJSON,
  TransTypeBinary,
  TransTypeString,
} from '@fodpr/protocol';
import type { FodprEvent } from '@fodpr/protocol';
import {
  type NostrEvent,
  type NostrTags,
  findETag,
  findPTag,
} from './nostrProtocol';

export type ProtocolType = 'fodpr' | 'nostr';

export type UnifiedKind =
  | 'profile'
  | 'text'
  | 'media'
  | 'reaction'
  | 'reply'
  | 'repost'
  | 'quote'
  | 'other';

export interface UnifiedTags {
  // threading refs (dedupeKey / event.id)
  reply?: string;
  react?: string;
  repost?: string;
  quote?: string;
  // mentioned pubkey (for profile lookup)
  mentionedPubkey?: string;
  // media
  filename?: string;
  caption?: string;
  mediatype?: string;
  // raw tags for display (e.g. nostr tags)
  raw: string[];
}

export interface UnifiedEvent {
  id: string; // unique key (dedupeKey or event.id)
  protocol: ProtocolType;
  pubkey: string; // hex, compressed for fodpr, x-only for nostr
  createdAt: number; // unix seconds
  kind: UnifiedKind;
  content: string; // text or mime:base64 / JSON
  tags: UnifiedTags;
  sig: string; // hex signature (for dedup)
  // nostr-native fields (kept for protocol-specific operations like delete)
  nostrKind?: number;
  nostrTags?: NostrTags;
  nostrId?: string;
  // fodpr-native fields
  fodprTransType?: number;
}

// --- dedupe key ---
export function unifiedDedupeKey(e: UnifiedEvent): string {
  return e.id;
}

// --- pubkey helpers ---
export function fodprPubkeyHex(e: FodprEvent): string {
  return CryptoUtils.bytesToHex(e.pubkey);
}

// --- Fodpr → Unified ---
const FODPR_TAG_PREFIX = {
  reply: 'reply:',
  react: 'react:',
  repost: 'repost:',
  quote: 'quote:',
  filename: 'filename:',
  caption: 'caption:',
  mediatype: 'mediatype:',
} as const;

function parseFodprTag(tags: string[], prefix: string): string | undefined {
  for (const t of tags) {
    if (t.startsWith(prefix)) return t.slice(prefix.length);
  }
  return undefined;
}

// FodprEvent.content は SDK で Uint8Array になった。文字列として読むときはデコードする。
const eventContentDecoder = new TextDecoder();
function eventContentStr(e: FodprEvent): string {
  const c = e.content as unknown;
  return typeof c === 'string' ? (c as string) : eventContentDecoder.decode(e.content);
}

export function normalizeFodprEvent(e: FodprEvent): UnifiedEvent {
  const pk = CryptoUtils.bytesToHex(e.pubkey);
  const sig = CryptoUtils.bytesToHex(e.signature);
  // dedupe key without timestamp (server may rewrite timestamp)
  const id = `${pk}:${e.transType}:${sig}`;
  const base: Omit<UnifiedEvent, 'kind' | 'content' | 'tags'> = {
    id,
    protocol: 'fodpr',
    pubkey: pk,
    createdAt: e.createdAt,
    sig,
    fodprTransType: e.transType,
  };

  const tags: UnifiedTags = {
    reply: parseFodprTag(e.tags, FODPR_TAG_PREFIX.reply),
    react: parseFodprTag(e.tags, FODPR_TAG_PREFIX.react),
    repost: parseFodprTag(e.tags, FODPR_TAG_PREFIX.repost),
    quote: parseFodprTag(e.tags, FODPR_TAG_PREFIX.quote),
    filename: parseFodprTag(e.tags, FODPR_TAG_PREFIX.filename),
    caption: parseFodprTag(e.tags, FODPR_TAG_PREFIX.caption),
    mediatype: parseFodprTag(e.tags, FODPR_TAG_PREFIX.mediatype),
    raw: e.tags,
  };

  // Determine unified kind
  let kind: UnifiedKind;
  if (e.transType === TransTypeJSON) {
    try {
      const obj = JSON.parse(eventContentStr(e));
      if (obj?.mode === 'profile') kind = 'profile';
      else kind = 'other';
    } catch {
      kind = 'other';
    }
  } else if (e.transType === TransTypeString) {
    if (tags.react) kind = 'reaction';
    else if (tags.repost) kind = 'repost';
    else if (tags.quote) kind = 'quote';
    else if (tags.reply) kind = 'reply';
    else kind = 'text';
  } else if (e.transType === TransTypeBinary) {
    kind = 'media';
  } else {
    kind = 'other';
  }

  // Parse profile content early for convenience
  let profileContent: string | undefined;
  if (kind === 'profile') {
    try {
      const obj = JSON.parse(eventContentStr(e));
      profileContent = JSON.stringify({
        name: obj.name,
        about: obj.about,
        picture: obj.picture,
      });
    } catch {
      profileContent = undefined;
    }
  }

  return {
    ...base,
    kind,
    content: profileContent ?? eventContentStr(e),
    tags,
  };
}

// --- Nostr → Unified ---
export function normalizeNostrEvent(e: NostrEvent): UnifiedEvent {
  const base: Omit<UnifiedEvent, 'kind' | 'content' | 'tags'> = {
    id: e.id,
    protocol: 'nostr',
    pubkey: e.pubkey,
    createdAt: e.created_at,
    sig: e.sig,
    nostrKind: e.kind,
    nostrTags: e.tags,
    nostrId: e.id,
  };

  // Extract threading tags
  const eTag = findETag(e);
  const pTag = findPTag(e);

  // For reactions (kind 7), the 'e' tag is the reaction target
  const isReaction = e.kind === 7;
  // For reposts (kind 6), the 'e' tag is the reposted event
  const isRepost = e.kind === 6;

  const tags: UnifiedTags = {
    reply: !isReaction && !isRepost && eTag ? eTag : undefined,
    react: isReaction && eTag ? eTag : undefined,
    repost: isRepost && eTag ? eTag : undefined,
    mentionedPubkey: pTag ?? undefined,
    raw: flattenNostrTags(e.tags),
  };

  let kind: UnifiedKind;
  switch (e.kind) {
    case 0:
      kind = 'profile';
      break;
    case 1:
      // text note; check if it has reply tag
      if (eTag) kind = 'reply';
      else kind = 'text';
      break;
    case 7:
      kind = 'reaction';
      break;
    case 5:
      kind = 'other'; // deletion — Nostros doesn't display these in the main feed
      break;
    case 6:
      kind = 'repost';
      break;
    default:
      kind = 'other';
  }

  // For nostr media, check for 'image'/'url' tags, kind 20, or media content format
  let content = e.content;
  const mediaContent = parseImageContent(e.content);
  if (e.kind === 20 || (e.kind === 1 && (hasMediaTag(e.tags) || mediaContent))) {
    // kind 20 blob event, kind 1 with media tags, or kind 1 with mime:base64 content
    kind = 'media';
    content = e.content;
    const mediaTags = parseNostrMediaTags(e.tags);
    Object.assign(tags, mediaTags);
  }

  // Parse profile content for kind 0
  if (e.kind === 0) {
    try {
      const obj = JSON.parse(e.content);
      content = JSON.stringify({
        name: obj.name,
        about: obj.about,
        picture: obj.picture,
      });
    } catch {
      // keep raw content
    }
  }

  return {
    ...base,
    kind,
    content,
    tags,
  };
}

function flattenNostrTags(tags: NostrTags): string[] {
  return tags.map((t) => t.join(':'));
}

function hasMediaTag(tags: NostrTags): boolean {
  return tags.some((t) => t[0] === 'image' || t[0] === 'url' || t[0] === 'video' || t[0] === 'audio');
}

function parseNostrMediaTags(tags: NostrTags): Partial<UnifiedTags> {
  const result: Partial<UnifiedTags> = { raw: [] };
  for (const t of tags) {
    const type = t[0];
    const value = t[1];
    if (type === 'image' || type === 'url' || type === 'video' || type === 'audio') {
      result.mediatype = type;
      // For media, store the URL in content
    } else if (type === 'alt') {
      result.caption = String(value ?? '');
    } else if (type === 'name') {
      result.filename = String(value ?? '');
    }
  }
  return result;
}

// --- Profile parsing (unified) ---
export function parseUnifiedProfile(content: string): { name?: string; about?: string; picture?: string } {
  try {
    const obj = JSON.parse(content);
    if (obj && typeof obj === 'object') {
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


// --- Event splitting (unified) ---
export interface UnifiedEventGroups {
  profiles: UnifiedEvent[];
  notes: UnifiedEvent[];
  media: UnifiedEvent[];
  reactions: UnifiedEvent[];
  replies: UnifiedEvent[];
  links: UnifiedEvent[];
  others: UnifiedEvent[];
}

export function splitUnified(events: UnifiedEvent[]): UnifiedEventGroups {
  const out: UnifiedEventGroups = {
    profiles: [],
    notes: [],
    media: [],
    reactions: [],
    replies: [],
    links: [],
    others: [],
  };
  for (const e of events) {
    switch (e.kind) {
      case 'profile':
        out.profiles.push(e);
        break;
      case 'media':
        out.media.push(e);
        break;
      case 'reaction':
        out.reactions.push(e);
        break;
      case 'reply':
        out.replies.push(e);
        break;
      case 'repost':
      case 'quote':
        out.links.push(e);
        break;
      case 'text':
        out.notes.push(e);
        break;
      default:
        out.others.push(e);
    }
  }
  return out;
}

// --- latest profile per pubkey ---
export function latestUnifiedProfilePerPubkey(
  profiles: UnifiedEvent[],
): Record<string, UnifiedEvent> {
  const map: Record<string, UnifiedEvent> = {};
  for (const e of profiles) {
    const prev = map[e.pubkey];
    if (!prev || e.createdAt > prev.createdAt) {
      map[e.pubkey] = e;
    }
  }
  return map;
}

// --- resolve helpers ---
export function unifiedProfileName(e: UnifiedEvent | undefined): string | null {
  if (!e || e.kind !== 'profile') return null;
  return parseUnifiedProfile(e.content).name ?? null;
}

export function unifiedProfilePicture(e: UnifiedEvent | undefined): string | null {
  if (!e || e.kind !== 'profile') return null;
  return parseUnifiedProfile(e.content).picture ?? null;
}

export function resolveUnifiedDisplayName(
  pubkeyHex: string,
  profileMap: Record<string, UnifiedEvent>,
): string {
  return unifiedProfileName(profileMap[pubkeyHex]) ?? pubkeyHex.slice(0, 7);
}

// --- threading helpers ---
export function unifiedReplyTarget(e: UnifiedEvent): string | null {
  return e.tags.reply ?? null;
}

export function unifiedReactionTarget(e: UnifiedEvent): string | null {
  return e.tags.react ?? null;
}

export function unifiedRepostTarget(e: UnifiedEvent): string | null {
  return e.tags.repost ?? null;
}

export function unifiedQuoteTarget(e: UnifiedEvent): string | null {
  return e.tags.quote ?? null;
}

// --- snippet ---
export function unifiedEventSnippet(e: UnifiedEvent | undefined): string {
  if (!e) return '';
  if (e.kind === 'media') {
    const media = parseImageContent(e.content);
    if (media) return media.mime.startsWith('video/') ? '動画' : '画像';
    return '[メディア]';
  }
  const s = e.content.trim();
  return s.length > 80 ? s.slice(0, 80) + '…' : s;
}

// --- media content parsing (shared) ---
const MEDIA_CONTENT_RE = /^(?:img:)?([^:;,]+)(?:;base64)?[,:](.+)$/s;

export function parseImageContent(content: string): { mime: string; base64: string } | null {
  const m = MEDIA_CONTENT_RE.exec(content);
  return m ? { mime: m[1], base64: m[2] } : null;
}

export function unifiedFilenameFromTags(tags: UnifiedTags): string | null {
  return tags.filename ?? null;
}

export function unifiedCaptionFromTags(tags: UnifiedTags): string | null {
  return tags.caption ?? null;
}

// --- sorting ---
export function sortUnifiedPostsDesc(posts: UnifiedEvent[]): UnifiedEvent[] {
  return [...posts].sort((a, b) => {
    if (b.createdAt !== a.createdAt) return b.createdAt - a.createdAt;
    return b.sig > a.sig ? 1 : -1;
  });
}
