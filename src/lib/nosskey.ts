// NIP-79 "Passkey-Wrapped Keys a.k.a. Nosskey" — PRF direct usage method.
//
// アイデア: WebAuthn の PRF 拡張を有効にした platform authenticator(パスキー)を作
// る。PRF 出力は (credential secret, salt) の HMAC-SHA256 であり、
// credential + salt が決まれば毎回同じ 32 バイトが再生される。
// これを HKDF-SHA256 に通して secp256k1 の秘密鍵を決定論的に派生する。
//
// 秘密鍵はプリンシパル(パスキー)の中に閉じ込まったままとなるため、このクライアントは
// 秘密鍵を keystore へ永続化せず、ログインのたびに WebAuthn 照認(生体)で再生する。
// localStorage には credential ID + 公開鍵だけを記録し、再ログインの手がかりにする。

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { getPublicKeyFromSecret } from './nostrProtocol';

// PRF/派生のための固定値。origin に依らない固定 salt にすることで、
// 同じ credential でどのオリジンでも同じ鍵が再生される。
// (PRF は credential secret + salt の HMAC なので、salt が一致すれば鍵は再生できる。
//  origin ごとに salt を変えると、異なるオリジンで鍵が変わってしまうため固定とする。)
const NOSSKEY_SALT = utf8ToBytes('prrr:nosskey:prf-salt:v1');
const NOSSKEY_INFO = utf8ToBytes('prrr:nosskey:derive:v1');
const NOSSKEY_SALT_BUF = NOSSKEY_SALT as unknown as BufferSource;

export interface NosskeyCred {
  credId: string; // base64url
  pubkey: string; // HEX
}

// WebAuthn PRF が利用可能な環境かを判定する。
// PRF 自体のサポートは create/get の拡張結果で改めて確認する。
export function nosskeySupported(): boolean {
  if (typeof window === 'undefined') return false;
  const c = (window as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential;
  const n = window.navigator?.credentials;
  return typeof c === 'function' && typeof n?.get === 'function' && typeof n?.create === 'function';
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(b64url: string): Uint8Array {
  const pad = (4 - (b64url.length % 4)) % 4;
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// PRF 出力から Nostr 秘密鍵(HEX)を決定論的に派生。
// HKDF に通すことで secp256k1 スカラーの範囲 1..n-1 に正規化する
// (無効になる確率は 2^-128 未満)。
export function prfToPrivateKey(prfOut: Uint8Array): string {
  const derived = hkdf(sha256, prfOut, NOSSKEY_SALT, NOSSKEY_INFO, 32);
  const hex = bytesToHex(derived);
  // @noble/secp256k1: 無効な鍵は getPublicKeyFromSecret で throw する
  getPublicKeyFromSecret(hex);
  return hex;
}

// WebAuthn 照証から PRF 結果(32 bytes)を取り出す。
function readPrfResult(cred: PublicKeyCredential): Uint8Array | null {
  const out = cred.getClientExtensionResults().prf?.results?.first;
  if (!out) return null;
  if (out instanceof ArrayBuffer) return new Uint8Array(out);
  return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
}

// Passkey(platform authenticator + PRF)を新規作成し Nostr 秘密鍵を派生する。
// NIP-79 PRF direct usage method。
export async function registerNosskeyPasskey(): Promise<{
  privKey: string;
  pubkey: string;
  credId: string;
}> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const user = crypto.getRandomValues(new Uint8Array(16));
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: location.hostname, name: 'Prrr' },
      user: { id: user, name: 'prrr-nosskey', displayName: 'Prrr (Nosskey)' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'required',
      },
      extensions: { prf: { eval: { first: NOSSKEY_SALT_BUF } } },
    },
  })) as PublicKeyCredential;

  const prf = readPrfResult(cred);
  if (!prf) {
    throw new Error('このパスキーは NIP-79 (PRF 拡張) をサポートしていません');
  }
  const privKey = prfToPrivateKey(new Uint8Array(prf));
  const pubkey = getPublicKeyFromSecret(privKey);
  return { privKey, pubkey, credId: bytesToBase64Url(new Uint8Array(cred.rawId)) };
}

// 保存済み credential ID から WebAuthn 照証を要求し Nostr 秘密鍵を再生する。
export async function loginNosskeyPasskey(credIdB64url: string): Promise<{
  privKey: string;
  pubkey: string;
}> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [
        { type: 'public-key', id: base64UrlToBytes(credIdB64url) as unknown as BufferSource },
      ],
      userVerification: 'required',
      extensions: { prf: { eval: { first: NOSSKEY_SALT_BUF } } },
    },
  })) as PublicKeyCredential;

  const prf = readPrfResult(cred);
  if (!prf) {
    throw new Error('NIP-79 (PRF 拡張) で秘密鍵を再生できませんでした');
  }
  const privKey = prfToPrivateKey(new Uint8Array(prf));
  const pubkey = getPublicKeyFromSecret(privKey);
  return { privKey, pubkey };
}
