/**
 * fodprF2f.ts
 * -----------
 * F2F (Friend-to-Friend) クライアントネットワーキングレイヤー (v0.6 メッシュ版)。
 *
 * - WebRTC データチャネルで P2P 接続確立 (FodprData フレーム)
 * - シグナリングは P2P (直接ダイアル / 接続済みメッシュピア経由) のみ。
 *   リレーは存在しない。
 * - ピアキャッシュ (localStorage.fodpr_f2f_peer_cache)
 * - インビテーションコード (Bech32, f2finv1...)
 *
 * グループ管理 (ホスト昇格) とリレー連携は v0.6 で削除された。
 */

import {
  Protocol,
  type FodprData,
  type PeerInfo,
  type PeerList,
  type WoTIntro,
  type InvitationCode,
  SignalOffer,
  SignalAnswer,
  SignalCandidate,
  MsgTypeData,
} from '@fodpr/protocol';
import { CryptoUtils } from '@fodpr/crypto';

export const F2F_PEER_CACHE_KEY = 'fodpr_f2f_peer_cache';
export const MAX_PEER_CACHE_SIZE = 50;

// ---------------------------------------------------------------------------
// ピアキャッシュ (localStorage 保存)
// ---------------------------------------------------------------------------

export interface F2FPeerInfo {
  pubkey: string;
  addresses: string[];
  lastSeen: number;
  trustScore: number;
  country?: string;  // GeoIP 国コード (ISO 3166-1 alpha-2), optional for backward compat
}

export interface F2FPeerCache {
  version: number;
  peers: F2FPeerInfo[];
  lastUpdated: number;
}

export function peerInfoToBinary(p: F2FPeerInfo): Uint8Array {
  return Protocol.encodePeerInfo({
    pubkey: CryptoUtils.hexToBytes(p.pubkey),
    addresses: p.addresses,
    lastSeen: p.lastSeen,
    trustScore: p.trustScore,
  });
}

export function peerInfoFromBinary(data: Uint8Array): F2FPeerInfo {
  const pi = Protocol.decodePeerInfo(data);
  return {
    pubkey: CryptoUtils.bytesToHex(pi.pubkey),
    addresses: pi.addresses,
    lastSeen: Number(pi.lastSeen),
    trustScore: pi.trustScore,
  };
}

// ---------------------------------------------------------------------------
// インビテーションコード (Bech32)
// ---------------------------------------------------------------------------

export async function generateInvitation(
  issuerPrivHex: string,
  targetPubkeyHex: string,
  targetAddresses: string[],
  expiresInSec: number = 7 * 24 * 3600,
  scope: number = 1,
): Promise<string> {
  const issuerBytes = CryptoUtils.hexToBytes(issuerPrivHex);
  const pubkeyBytes = CryptoUtils.getRawCompressedPublicKey(issuerBytes);
  const now = Math.floor(Date.now() / 1000);

  const targetPeer: PeerInfo = {
    pubkey: CryptoUtils.hexToBytes(targetPubkeyHex),
    addresses: targetAddresses,
    lastSeen: now,
    trustScore: 1.0,
  };

  const inv: InvitationCode = {
    version: 1,
    issuer: pubkeyBytes,
    targetPeer,
    expiresAt: now + expiresInSec,
    scope,
    signature: new Uint8Array(64),
  };

  const signedData = Protocol.encodeInvitationSignedData(inv);
  const sigHex = await CryptoUtils.signMessage(issuerPrivHex, signedData);
  inv.signature = CryptoUtils.hexToBytes(sigHex);

  return Protocol.encodeInvitationBech32(inv);
}

export async function parseInvitation(code: string): Promise<InvitationCode> {
  return Protocol.decodeInvitationBech32(code);
}

export function invitationToDisplay(inv: InvitationCode): {
  issuer: string;
  targetPubkey: string;
  targetAddresses: string[];
  expiresAt: number;
  scope: string;
  valid: boolean;
} {
  const now = Math.floor(Date.now() / 1000);
  const valid = now <= Number(inv.expiresAt) && inv.version === 1;
  return {
    issuer: CryptoUtils.bytesToHex(inv.issuer),
    targetPubkey: CryptoUtils.bytesToHex(inv.targetPeer.pubkey),
    targetAddresses: inv.targetPeer.addresses,
    expiresAt: Number(inv.expiresAt),
    scope: inv.scope === 0 ? 'single' : 'WoT (cache share)',
    valid,
  };
}

// ---------------------------------------------------------------------------
// F2F ピア接続 (WebRTC データチャネル)
// ---------------------------------------------------------------------------

export type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'failed';

export interface F2FSignalMessage {
  signalType: number;
  content: string;
}

export class F2FPeerConnection {
  readonly remotePubkey: string;
  readonly localPubkey: string;
  private pc: RTCPeerConnection | null = null;
  private dc: RTCDataChannel | null = null;
  private localPrivHex: string;

  state: ConnectionState = 'connecting';
  private seq = 0;
  createdAt: number;
  lastActivity: number;

  // 送信するシグナル (offer/answer/candidate)。メッシュが P2P 経由で配送する。
  onSignal: ((signal: F2FSignalMessage) => void) | null = null;
  // 受信した FodprData (署名検証済み)。メッシュが tags/content で振り分ける。
  onDataMessage: ((msg: FodprData) => void) | null = null;
  onDisconnect: (() => void) | null = null;

  constructor(params: {
    localPrivHex: string;
    remotePubkeyHex: string;
  }) {
    this.localPrivHex = params.localPrivHex;
    const localPrivBytes = CryptoUtils.hexToBytes(params.localPrivHex);
    const localPubBytes = CryptoUtils.getRawCompressedPublicKey(localPrivBytes);
    this.localPubkey = CryptoUtils.bytesToHex(localPubBytes);
    this.remotePubkey = params.remotePubkeyHex;
    this.createdAt = Date.now();
    this.lastActivity = Date.now();
  }

  // --- アドレス解析 ---

  private parseAddress(addr: string): { ip: string; port: number } | null {
    let match = addr.match(/^\[([^\]]+)\]:(\d+)$/);
    if (match) return { ip: match[1], port: parseInt(match[2]) };
    match = addr.match(/^(.+):(\d+)$/);
    if (match) return { ip: match[1], port: parseInt(match[2]) };
    return null;
  }

  // --- シグナル送信 (メッシュが配送する) ---

  private emitSignal(signalType: number, content: string) {
    this.onSignal?.({ signalType, content });
  }

  // --- WebRTC P2P connection ---

  async initiateConnection(remoteAddresses: string[] = []): Promise<boolean> {
    if (this.state === 'connected') return true;
    if (this.pc) return false;

    this.state = 'connecting';
    this.pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });

    for (const addr of remoteAddresses) {
      try {
        const parsed = this.parseAddress(addr);
        if (parsed) {
          await this.pc.addIceCandidate({
            candidate: `candidate:1 1 UDP 2122252543 ${parsed.port} ${parsed.ip} ${parsed.ip} typ host`,
            sdpMid: '0',
            sdpMLineIndex: 0,
          });
        }
      } catch {
        /* ignore parse errors */
      }
    }

    this.dc = this.pc.createDataChannel('fodpr-f2f');
    this.setupDataChannel(this.dc);
    this.setupConnectionEvents();

    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    this.emitSignal(SignalOffer, offer.sdp ?? '');
    return true;
  }

  async handleOffer(offerSdp: string): Promise<boolean> {
    if (this.state !== 'connecting') return false;
    if (!this.pc) {
      this.pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      this.setupConnectionEvents();
    }

    try {
      await this.pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
      this.pc.ondatachannel = (event) => {
        this.dc = event.channel;
        this.setupDataChannel(this.dc);
      };
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      this.emitSignal(SignalAnswer, answer.sdp ?? '');
      return true;
    } catch {
      this.state = 'failed';
      this.onDisconnect?.();
      return false;
    }
  }

  async handleAnswer(answerSdp: string): Promise<boolean> {
    if (this.state !== 'connecting') return false;
    try {
      await this.pc?.setRemoteDescription({ type: 'answer', sdp: answerSdp });
      return true;
    } catch {
      this.state = 'failed';
      this.onDisconnect?.();
      return false;
    }
  }

  async handleCandidate(candidate: RTCIceCandidateInit) {
    try {
      await this.pc?.addIceCandidate(candidate);
    } catch {
      /* ignore */
    }
  }

  private setupDataChannel(dc: RTCDataChannel) {
    dc.binaryType = 'arraybuffer';

    dc.onopen = () => {
      this.state = 'connected';
      this.lastActivity = Date.now();
    };

    dc.onclose = () => {
      this.state = 'disconnected';
      this.lastActivity = Date.now();
      this.onDisconnect?.();
    };

    dc.onmessage = (event) => {
      this.lastActivity = Date.now();
      const bytes = new Uint8Array(event.data);
      if (bytes.length < 1) return;
      if (bytes[0] === MsgTypeData) {
        try {
          const msg = Protocol.decodeData(bytes.subarray(1));
          const signedData = Protocol.encodeDataSignedData(msg);
          CryptoUtils.verifySignature(msg.sender, signedData, msg.signature)
            .then((ok) => {
              if (!ok) return;
              // リプレイ防止: seq は単調増加のはず
              if (msg.seq <= this.seq && this.seq > 0) return;
              this.seq = msg.seq;
              this.onDataMessage?.(msg);
            })
            .catch(() => {});
        } catch {
          /* デコード失敗は無視 */
        }
      }
    };
  }

  private setupConnectionEvents() {
    if (!this.pc) return;

    this.pc.oniceconnectionstatechange = () => {
      const state = this.pc?.iceConnectionState;
      if (state === 'failed' || state === 'disconnected') {
        this.state = 'disconnected';
        this.onDisconnect?.();
      } else if (state === 'connected') {
        if (this.dc?.readyState === 'open') {
          this.state = 'connected';
        }
      }
    };

    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.emitSignal(SignalCandidate, JSON.stringify(event.candidate.toJSON()));
      }
    };
  }

  // --- データ送信 ---

  /** 生バイト列をデータチャネルに送信する (FodprData に包む)。 */
  private async sendRaw(content: Uint8Array, tags: string[]): Promise<boolean> {
    if (this.state !== 'connected' || !this.dc || this.dc.readyState !== 'open') {
      return false;
    }

    const localPubBytes = CryptoUtils.hexToBytes(this.localPubkey);
    const remotePubBytes = CryptoUtils.hexToBytes(this.remotePubkey);

    const dataMsg: FodprData = {
      sender: localPubBytes,
      target: remotePubBytes,
      seq: this.seq,
      timestamp: Math.floor(Date.now() / 1000),
      tags,
      content,
      signature: new Uint8Array(64),
    };

    const signedData = Protocol.encodeDataSignedData(dataMsg);
    const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
    dataMsg.signature = CryptoUtils.hexToBytes(sigHex);

    const encoded = Protocol.encodeData(dataMsg);
    const frame = new Uint8Array(1 + encoded.length);
    frame[0] = MsgTypeData;
    frame.set(encoded, 1);

    this.dc.send(frame);
    this.seq++;
    this.lastActivity = Date.now();
    return true;
  }

  /** P2P データチャネルで任意の content を送信する (tags で振り分け)。 */
  sendData(content: Uint8Array, tags: string[] = []): Promise<boolean> {
    return this.sendRaw(content, tags);
  }

  close() {
    this.dc?.close();
    this.pc?.close();
    this.state = 'disconnected';
  }
}

// Re-export for consumers
export type { PeerList, WoTIntro };
