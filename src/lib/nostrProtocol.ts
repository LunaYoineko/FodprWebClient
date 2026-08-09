// nostrProtocol.ts
// ----------------
// Nostr プロトコルの中核: イベントのシリアライズ・署名・検証。
// Fodpr プロトコル(@fodpr/protocol)とは異なり、Nostr は「テキスト JSON フレーム」
// 「32バイト x-only 公開鍵」「Schnorr 署名」「event.id = SHA-256(シリアライズ済み本体)」
// を使用する。既存の @noble/secp256k1 + @noble/hashes/sha256 を再利用する。

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';

// --- Types ---

export interface NostrTag {
  [key: string]: string | number;
}

export type NostrTags = string[][];

export interface NostrEvent {
  id: string; // SHA-256 hex of serialized event (without sig)
  pubkey: string; // 32-byte x-only hex
  created_at: number; // unix seconds
  kind: number; // 0, 1, 2, 4, 7, etc.
  tags: NostrTags;
  content: string;
  sig: string; // 64-byte schnorr hex
}

// Unserialized event (no id/sig yet)
export interface UnsignedNostrEvent {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: NostrTags;
  content: string;
}

// Relay client message types (RELEVANT_TO_REPLACE)
export type NostrClientMessage =
  | {
      type: 'REQ';
      subscriptionId: string;
      filters: NostrFilter[];
    }
  | {
      type: 'EVENT';
      event: NostrEvent;
    }
  | {
      type: 'CLOSE';
      subscriptionId: string;
    };

export type NostrServerMessage =
  | { type: 'EVENT'; subscriptionId: string; event: NostrEvent }
  | { type: 'EOSE'; subscriptionId: string }
  | { type: 'NOTICE'; message: string }
  | { type: 'CLOSE'; subscriptionId: string }
  | { type: 'AUTH'; challenge: string };

export interface NostrFilter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  tags?: unknown[];
  since?: number;
  until?: number;
  limit?: number;
  search?: string;
}

// --- bech32 (nsec / npub) ---

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if (((top >> i) & 1) !== 0) {
        chk ^= GENERATOR[i];
      }
    }
  }
  return chk;
}

function expandHrp(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const maxv = (1 << toBits) - 1;
  const out: number[] = [];
  for (const b of data) {
    acc = (acc << fromBits) | b;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error('Invalid padding in convertBits');
  }
  return out;
}

function bech32Encode(hrp: string, data: Uint8Array): string {
  const converted = convertBits(Array.from(data), 8, 5, true);
  const pm = polymod([...expandHrp(hrp), ...converted, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum: number[] = new Array(6);
  for (let i = 0; i < 6; i++) {
    checksum[5 - i] = (pm >>> (i * 5)) & 31;
  }
  return hrp + '1' + [...converted, ...checksum].map((v) => CHARSET[v]).join('');
}

function bech32Decode(bechStr: string, expectedHrp: string): Uint8Array {
  if (bechStr.length < 8) throw new Error('Bech32 string too short');

  const pos = bechStr.lastIndexOf('1');
  if (pos === -1 || pos < 1 || pos + 7 > bechStr.length) throw new Error('Invalid Bech32 format');

  const hrp = bechStr.slice(0, pos).toLowerCase();
  if (hrp !== expectedHrp.toLowerCase()) throw new Error('HRP mismatch: expected ' + expectedHrp);

  const data: number[] = [];
  for (let i = pos + 1; i < bechStr.length; i++) {
    const idx = CHARSET.indexOf(bechStr[i]);
    if (idx === -1) throw new Error('Invalid character in Bech32 string');
    data.push(idx);
  }

  const pm = polymod([...expandHrp(hrp), ...data]);
  if (pm !== 1) throw new Error('Invalid checksum');

  const decoded5bit = data.slice(0, data.length - 6);
  return Uint8Array.from(convertBits(decoded5bit, 5, 8, false));
}

// nsec1... <-> 32-byte hex
export function nsecToHex(nsec: string): string {
  const bytes = bech32Decode(nsec.trim(), 'nsec');
  if (bytes.length !== 32) throw new Error('Invalid nsec length');
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToNsec(secretHex: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < secretHex.length; i += 2) {
    bytes.push(parseInt(secretHex.slice(i, i + 2), 16));
  }
  return bech32Encode('nsec', Uint8Array.from(bytes));
}

// npub1... <-> 32-byte hex (x-only pubkey)
export function npubToHex(npub: string): string {
  const bytes = bech32Decode(npub.trim(), 'npub');
  if (bytes.length !== 32) throw new Error('Invalid npub length');
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToNpub(pubkeyHex: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < pubkeyHex.length; i += 2) {
    bytes.push(parseInt(pubkeyHex.slice(i, i + 2), 16));
  }
  return bech32Encode('npub', Uint8Array.from(bytes));
}

// --- NIP-19 (nevent / nprofile / naddr / note) ---

// 任意の HRP を受け取る汎用 bech32 デコーダ(NIP-19 エンティティ用)
export function bech32DecodeAny(bechStr: string): { hrp: string; data: Uint8Array } {
  if (bechStr.length < 8) throw new Error('Bech32 string too short');

  const pos = bechStr.lastIndexOf('1');
  if (pos === -1 || pos < 1 || pos + 7 > bechStr.length) throw new Error('Invalid Bech32 format');

  const hrp = bechStr.slice(0, pos).toLowerCase();

  const data: number[] = [];
  for (let i = pos + 1; i < bechStr.length; i++) {
    const idx = CHARSET.indexOf(bechStr[i]);
    if (idx === -1) throw new Error('Invalid character in Bech32 string');
    data.push(idx);
  }

  const pm = polymod([...expandHrp(hrp), ...data]);
  if (pm !== 1) throw new Error('Invalid checksum');

  const decoded5bit = data.slice(0, data.length - 6);
  return { hrp, data: Uint8Array.from(convertBits(decoded5bit, 5, 8, false)) };
}

// NIP-19 TLV を { type -> bytes[] } にパースする
function parseTLV(data: Uint8Array): Map<number, Uint8Array[]> {
  const out = new Map<number, Uint8Array[]>();
  let i = 0;
  while (i + 2 <= data.length) {
    const t = data[i];
    const len = data[i + 1];
    if (i + 2 + len > data.length) break;
    const value = data.slice(i + 2, i + 2 + len);
    const arr = out.get(t) ?? [];
    arr.push(value);
    out.set(t, arr);
    i += 2 + len;
  }
  return out;
}

function firstTLV(tlv: Map<number, Uint8Array[]>, t: number): Uint8Array | undefined {
  return tlv.get(t)?.[0];
}

function tlvToHex(b: Uint8Array | undefined): string | undefined {
  return b ? bytesToHex(b) : undefined;
}

function tlvToStr(b: Uint8Array | undefined): string | undefined {
  return b ? new TextDecoder().decode(b) : undefined;
}

// NIP-19 TLV の kind (type 3) は varint エンコード
function tlvToVarint(b: Uint8Array | undefined): number | undefined {
  if (!b || b.length === 0) return undefined;
  let n = 0;
  for (let i = 0; i < b.length; i++) {
    n = n * 128 + (b[i] & 0x7f);
  }
  return n;
}

export interface NostrEventPointer {
  id: string;
  relays?: string[];
  author?: string;
  kind?: number;
}

export interface NostrProfilePointer {
  pubkey: string;
  relays?: string[];
}

export interface NostrAddrPointer {
  identifier: string;
  pubkey: string;
  kind: number;
  relays?: string[];
}

// 単一エンティティのデコード結果(表示用リンク作成に使う)
export type NostrInlineEntity =
  | { type: 'npub'; value: string; relays?: string[] }
  | { type: 'note'; value: string; relays?: string[] }
  | { type: 'nevent'; value: NostrEventPointer; relays?: string[] }
  | { type: 'nprofile'; value: NostrProfilePointer; relays?: string[] }
  | { type: 'naddr'; value: NostrAddrPointer; relays?: string[] }
  | { type: 'unknown'; value: string };

// "nostr:nevent1..." / "nevent1..." 形式の NIP-19 URI をデコードする。
// 失敗時は type:'unknown' を返す(表示はそのまま)。
export function decodeNostrUri(uri: string): NostrInlineEntity {
  const s = uri.trim();
  const body = s.startsWith('nostr:') ? s.slice('nostr:'.length) : s;
  try {
    const { hrp, data } = bech32DecodeAny(body);
    if (hrp === 'npub') {
      if (data.length !== 32) return { type: 'unknown', value: s };
      return { type: 'npub', value: bytesToHex(data) };
    }
    if (hrp === 'note') {
      if (data.length !== 32) return { type: 'unknown', value: s };
      return { type: 'note', value: bytesToHex(data) };
    }
    if (hrp === 'nevent') {
      const tlv = parseTLV(data);
      const id = tlvToHex(firstTLV(tlv, 0));
      if (!id || id.length !== 64) return { type: 'unknown', value: s };
      return {
        type: 'nevent',
        value: {
          id,
          relays: (tlv.get(1) ?? []).map((r) => new TextDecoder().decode(r)),
          author: tlvToHex(firstTLV(tlv, 2)),
          kind: tlvToVarint(firstTLV(tlv, 3)),
        },
      };
    }
    if (hrp === 'nprofile') {
      const tlv = parseTLV(data);
      const pubkey = tlvToHex(firstTLV(tlv, 0));
      if (!pubkey || pubkey.length !== 64) return { type: 'unknown', value: s };
      return {
        type: 'nprofile',
        value: {
          pubkey,
          relays: (tlv.get(1) ?? []).map((r) => new TextDecoder().decode(r)),
        },
      };
    }
    if (hrp === 'naddr') {
      const tlv = parseTLV(data);
      const identifier = tlvToStr(firstTLV(tlv, 0));
      const pubkey = tlvToHex(firstTLV(tlv, 2));
      const kind = tlvToVarint(firstTLV(tlv, 3));
      if (!identifier || !pubkey || pubkey.length !== 64 || kind === undefined) {
        return { type: 'unknown', value: s };
      }
      return {
        type: 'naddr',
        value: {
          identifier,
          pubkey,
          kind,
          relays: (tlv.get(1) ?? []).map((r) => new TextDecoder().decode(r)),
        },
      };
    }
    return { type: 'unknown', value: s };
  } catch {
    return { type: 'unknown', value: s };
  }
}
// --- Event serialization (NIP-01) ---

function serializeEvent(ev: UnsignedNostrEvent): Uint8Array {
  // NIP-01 serialization: array form with leading 0 (version byte).
  // Integers are JSON numbers, not strings.
  const json = JSON.stringify([
    0,
    ev.pubkey,
    ev.created_at,
    ev.kind,
    ev.tags,
    ev.content,
  ]);
  return new TextEncoder().encode(json);
}

// --- Signing ---

// Returns { id, pubkey, ... } (no sig yet)
export function serializeEventForId(ev: UnsignedNostrEvent): Uint8Array {
  return serializeEvent(ev);
}

export function computeEventId(ev: UnsignedNostrEvent): string {
  const serialized = serializeEventForId(ev);
  const hash = sha256(serialized);
  return bytesToHex(hash);
}

export function signEvent(privkeyHex: string, ev: UnsignedNostrEvent): NostrEvent {
  const id = computeEventId(ev);
  const event: NostrEvent = {
    id,
    pubkey: getPublicKeyFromSecret(privkeyHex),
    created_at: ev.created_at,
    kind: ev.kind,
    tags: ev.tags,
    content: ev.content,
    sig: '',
  };
  // NIP-01 signing: schnorr sign over the event id bytes
  const idBytes = hexToBytes(id);
  const privBytes = hexToBytes(privkeyHex);
  const sigBytes = secp.schnorr.sign(idBytes, privBytes);
  event.sig = bytesToHex(sigBytes);
  return event;
}

export async function signEventAsync(privkeyHex: string, ev: UnsignedNostrEvent): Promise<NostrEvent> {
  const id = computeEventId(ev);
  const event: NostrEvent = {
    id,
    pubkey: getPublicKeyFromSecret(privkeyHex),
    created_at: ev.created_at,
    kind: ev.kind,
    tags: ev.tags,
    content: ev.content,
    sig: '',
  };
  const idBytes = hexToBytes(id);
  const privBytes = hexToBytes(privkeyHex);
  const sigBytes = await secp.schnorr.signAsync(idBytes, privBytes);
  event.sig = bytesToHex(sigBytes);
  return event;
}

export function verifyEvent(ev: NostrEvent): boolean {
  try {
    const unsigned: UnsignedNostrEvent = {
      pubkey: ev.pubkey,
      created_at: ev.created_at,
      kind: ev.kind,
      tags: ev.tags,
      content: ev.content,
    };
    const recomputedId = computeEventId(unsigned);
    if (recomputedId !== ev.id) return false;
    const idBytes = hexToBytes(ev.id);
    const pubBytes = hexToBytes(ev.pubkey);
    const sigBytes = hexToBytes(ev.sig);
    return secp.schnorr.verify(sigBytes, idBytes, pubBytes);
  } catch {
    return false;
  }
}

// --- Crypto helpers (reuse @noble/secp256k1 for x-only pubkeys) ---

// @noble/secp256k1 getPublicKey returns 33-byte compressed. Nostr uses 32-byte x-only.
// x-only = compressed pubkey without the leading 0x02/0x03 parity byte.
export function getPublicKeyFromSecret(privkeyHex: string): string {
  const priv = hexToBytes(privkeyHex);
  const compressed = secp.getPublicKey(priv, true); // 33 bytes compressed
  return bytesToHex(compressed.slice(1)); // strip parity byte -> 32 bytes x-only
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hex has odd length');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// --- Event construction helpers ---

export function makeNostrEvent(
  pubkeyHex: string,
  created_at: number,
  kind: number,
  tags: NostrTags,
  content: string
): UnsignedNostrEvent {
  return {
    pubkey: pubkeyHex,
    created_at,
    kind,
    tags,
    content,
  };
}

// Standard kinds
export const NOSTR_KIND = {
  METADATA: 0,
  TEXT: 1,
  RECOMMEND_RELAY: 2,
  ENCRYPTED_DM: 4,
  REACTION: 7,
  DELETE: 5,
  REPOST: 6,
  REPLY: 1,
  GENERIC_RECOMMEND: 2,
} as const;

// --- Relay client messages ---

export function encodeReq(subscriptionId: string, filters: NostrFilter[]): string {
  return JSON.stringify(['REQ', subscriptionId, ...filters]);
}

export function encodeEvent(ev: NostrEvent): string {
  return JSON.stringify(['EVENT', ev]);
}

export function encodeClose(subscriptionId: string): string {
  return JSON.stringify(['CLOSE', subscriptionId]);
}

// --- Threading helpers (NIP-10 / NIP-24) ---

// Find the 'e' tag (reply target) in an event's tags
export function findETag(ev: NostrEvent): string | null {
  for (const tag of ev.tags) {
    if (tag[0] === 'e' && typeof tag[1] === 'string') {
      return tag[1]; // event id
    }
  }
  return null;
}

// Find the 'p' tag (mentioned pubkey)
export function findPTag(ev: NostrEvent): string | null {
  for (const tag of ev.tags) {
    if (tag[0] === 'p' && typeof tag[1] === 'string') {
      return tag[1];
    }
  }
  return null;
}

// Build reply tags (NIP-24 preferred, but NIP-10 compatible)
export function buildReplyTags(targetId: string, targetPubkey: string): NostrTags {
  return [
    ['e', targetId, '', 'reply'],
    ...(targetPubkey ? [['p', targetPubkey]] : []),
  ];
}

// Build quote tags (NIP-10 marker 'q')
export function buildQuoteTags(targetId: string, targetPubkey: string): NostrTags {
  return [
    ['e', targetId, '', 'q'],
    ...(targetPubkey ? [['p', targetPubkey]] : []),
  ];
}

// Build reaction tags
export function buildReactionTags(targetId: string, targetPubkey: string): NostrTags {
  return [
    ['e', targetId, '', 'react'],
    ['p', targetPubkey],
  ];
}

// --- dedup key for local events ---
export function nostrDedupeKey(ev: NostrEvent): string {
  return ev.id;
}

// --- kind 0 (metadata) helpers ---
export interface NostrMetadata {
  name?: string;
  display_name?: string;
  about?: string;
  picture?: string;
  banner?: string;
  nip05?: string;
  website?: string;
  lud06?: string;
  lud16?: string;
}

// kind 0 の content(JSON)をパースする。表示名は display_name を優先し、なければ name。
export function parseKind0Metadata(content: string): NostrMetadata {
  try {
    const obj = JSON.parse(content);
    if (obj && typeof obj === 'object') {
      return {
        name: typeof obj.name === 'string' ? obj.name : undefined,
        display_name: typeof obj.display_name === 'string' ? obj.display_name : undefined,
        about: typeof obj.about === 'string' ? obj.about : undefined,
        picture: typeof obj.picture === 'string' ? obj.picture : undefined,
        banner: typeof obj.banner === 'string' ? obj.banner : undefined,
        nip05: typeof obj.nip05 === 'string' ? obj.nip05 : undefined,
        website: typeof obj.website === 'string' ? obj.website : undefined,
      };
    }
  } catch {
    /* no-op */
  }
  return {};
}

// kind 0 から表示名を取り出す(display_name 優先、なければ name)
export function kind0DisplayName(meta: NostrMetadata): string | null {
  return (meta.display_name ?? meta.name) || null;
}