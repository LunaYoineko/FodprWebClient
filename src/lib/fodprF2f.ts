/**
 * fodprF2f.ts
 * -----------
 * F2F (Friend-to-Friend) クライアントネットワーキングレイヤー。
 *
 * ホスト-ゲスト星形トポロジの P2P グループを構築・管理する。
 * - シードリレーからピアリスト取得 (bootstrap)
 * - WebRTC データチャネルで P2P 接続確立
 * - F2F シグナリング (F2FSignal, viaRelay=true でリレー経由)
 * - ピアキャッシュ (localStorage)
 * - WoT (Web of Trust) 紹介
 * - インビテーションコード (Bech32)
 * - グループ管理 (ホスト切断時自動昇格)
 *
 * 既存のホスト昇提型 P2P (ホストがリレー上で RtcGroup を管理) とは独立して動作する。
 * F2F はクライアント側でグループを管理し、ホストが切断したら最古のゲストを自動昇格する。
 */

import {
  Protocol,
  type FodprData,
  type F2FSignal,
  type PeerInfo,
  type PeerList,
  type WoTIntro,
  type InvitationCode,
  type F2FGroup,
  type FodprEvent,
  type GroupMember,
  type SeedResponse,
  TransTypeGroup,
  SignalOffer,
  SignalAnswer,
  SignalCandidate,
  MsgTypeData,
} from '@fodpr/protocol';
import { CryptoUtils } from '@fodpr/crypto';
import type { RelayClient } from './relay';

const F2F_PEER_CACHE_KEY = 'fodpr_f2f_peer_cache';
const F2F_GROUPS_KEY = 'fodpr_f2f_groups';
const MAX_PEER_CACHE_SIZE = 50;

// ---------------------------------------------------------------------------
// ピアキャッシュ (localStorage 保存)
// ---------------------------------------------------------------------------

export interface F2FPeerInfo {
  pubkey: string;
  addresses: string[];
  lastSeen: number;
  trustScore: number;
}

export interface F2FPeerCache {
  version: number;
  peers: F2FPeerInfo[];
  lastUpdated: number;
}

function loadPeerCache(): F2FPeerCache {
  try {
    const raw = localStorage.getItem(F2F_PEER_CACHE_KEY);
    if (raw) return JSON.parse(raw);
  } catch {
    /* ignore */
  }
  return { version: 1, peers: [], lastUpdated: 0 };
}

function savePeerCache(cache: F2FPeerCache) {
  try {
    localStorage.setItem(F2F_PEER_CACHE_KEY, JSON.stringify(cache));
  } catch {
    /* ignore */
  }
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
// F2F グループ管理
// ---------------------------------------------------------------------------

export type GroupState = 'idle' | 'active' | 'promoting' | 'disbanded';

export interface F2FGroupMember {
  pubkey: string;
  addresses: string[];
  joinedAt: number;
  isHost: boolean;
  isConnected: boolean;
}

export interface F2FGroupInfo {
  groupId: string;
  hostPubkey: string;
  members: F2FGroupMember[];
  version: number;
  createdAt: number;
  state: GroupState;
  isHost: boolean;
  joinedAt: number;
  lastHeartbeat: number;
}

function loadGroups(): F2FGroupInfo[] {
  try {
    const raw = localStorage.getItem(F2F_GROUPS_KEY);
    if (raw) return JSON.parse(raw) as F2FGroupInfo[];
  } catch {
    /* ignore */
  }
  return [];
}

function saveGroups(groups: F2FGroupInfo[]) {
  try {
    localStorage.setItem(F2F_GROUPS_KEY, JSON.stringify(groups));
  } catch {
    /* ignore */
  }
}

// ---------------------------------------------------------------------------
// F2F ピア接続 (WebRTC データチャネル)
// ---------------------------------------------------------------------------

type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'failed';

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

  // P2P による直接メッセージ受信コールバック
  onDataMessage: ((msg: FodprData) => void) | null = null;
  onF2FSignal: ((signal: F2FSignal) => void) | null = null;
  onPeerList: ((peerList: PeerList) => void) | null = null;
  onWoTIntro: ((intro: WoTIntro) => void) | null = null;
  onInvitation: ((inv: InvitationCode) => void) | null = null;
  onGroup: ((group: F2FGroup) => void) | null = null;
  onDisconnect: (() => void) | null = null;

  private relay: RelayClient | null = null;
  private _relaySubId: string | null = null;

  // Mark the field as used by referencing it
  get relaySubId(): string | null { return this._relaySubId; }

  constructor(params: {
    localPrivHex: string;
    remotePubkeyHex: string;
    relay?: RelayClient;
  }) {
    this.localPrivHex = params.localPrivHex;
    const localPrivBytes = CryptoUtils.hexToBytes(params.localPrivHex);
    const localPubBytes = CryptoUtils.getRawCompressedPublicKey(localPrivBytes);
    this.localPubkey = CryptoUtils.bytesToHex(localPubBytes);
    this.remotePubkey = params.remotePubkeyHex;
    this.relay = params.relay ?? null;
    this.createdAt = Date.now();
    this.lastActivity = Date.now();
  }

  // --- Relay-based signaling (fallback before P2P established) ---

  setRelaySubscription(subId: string) {
    this._relaySubId = subId;
  }

  private sendF2FSignalViaRelay(signal: F2FSignal) {
    if (this.relay) {
      try {
        this.relay.sendF2FSignal(signal);
      } catch {
        /* relay not connected */
      }
    }
  }

  // --- WebRTC P2P connection ---

  async initiateConnection(remoteAddresses: string[] = []): Promise<boolean> {
    if (this.state === 'connected') return true;
    if (this.pc) return false;

    this.state = 'connecting';

    const config: RTCConfiguration = {
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
    };

    this.pc = new RTCPeerConnection(config);

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

    await this.sendSignalOffer(offer.sdp ?? '');
    return true;
  }

  async handleOffer(offerSdp: string): Promise<boolean> {
    if (this.state !== 'connecting') return false;
    if (!this.pc) {
      const config: RTCConfiguration = {
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
      };
      this.pc = new RTCPeerConnection(config);
      this.setupConnectionEvents();
    }

    try {
      await this.pc.setRemoteDescription({ type: 'offer', sdp: offerSdp });
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);

      this.pc.ondatachannel = (event) => {
        this.dc = event.channel;
        this.setupDataChannel(this.dc);
      };

      await this.sendSignalAnswer(answer.sdp ?? '');
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

  private async sendSignalOffer(sdp: string) {
    const localPubBytes = CryptoUtils.hexToBytes(this.localPubkey);
    const remotePubBytes = CryptoUtils.hexToBytes(this.remotePubkey);
    const signal: F2FSignal = {
      signalType: SignalOffer,
      sender: localPubBytes,
      target: remotePubBytes,
      content: sdp,
      signature: new Uint8Array(64),
      viaRelay: true,
    };
    const signedData = Protocol.encodeF2FSignalSignedData(signal);
    const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
    signal.signature = CryptoUtils.hexToBytes(sigHex);
    this.sendF2FSignalViaRelay(signal);
  }

  private async sendSignalAnswer(sdp: string) {
    const localPubBytes = CryptoUtils.hexToBytes(this.localPubkey);
    const remotePubBytes = CryptoUtils.hexToBytes(this.remotePubkey);
    const signal: F2FSignal = {
      signalType: SignalAnswer,
      sender: localPubBytes,
      target: remotePubBytes,
      content: sdp,
      signature: new Uint8Array(64),
      viaRelay: true,
    };
    const signedData = Protocol.encodeF2FSignalSignedData(signal);
    const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
    signal.signature = CryptoUtils.hexToBytes(sigHex);
    this.sendF2FSignalViaRelay(signal);
  }

  async sendSignalCandidate(candidate: RTCIceCandidate) {
    const localPubBytes = CryptoUtils.hexToBytes(this.localPubkey);
    const remotePubBytes = CryptoUtils.hexToBytes(this.remotePubkey);
    const signal: F2FSignal = {
      signalType: SignalCandidate,
      sender: localPubBytes,
      target: remotePubBytes,
      content: JSON.stringify({
        candidate: candidate.candidate,
        sdpMid: candidate.sdpMid,
        sdpMLineIndex: candidate.sdpMLineIndex,
      }),
      signature: new Uint8Array(64),
      viaRelay: true,
    };
    const signedData = Protocol.encodeF2FSignalSignedData(signal);
    const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
    signal.signature = CryptoUtils.hexToBytes(sigHex);
    this.sendF2FSignalViaRelay(signal);
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
        this.handleP2PMessage(bytes.subarray(1));
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
      if (event.candidate && this.relay && this.state === 'connected') {
        this.sendSignalCandidate(event.candidate);
      }
    };
  }

  // P2P データチャネルで受信した F2F メッセージを振り分け
  private handleP2PMessage(data: Uint8Array) {
    if (data.length < 1) return;
    const firstByte = data[0];

    // SignalOffer=1, SignalAnswer=2, SignalCandidate=3
    if (firstByte === SignalOffer || firstByte === SignalAnswer || firstByte === SignalCandidate) {
      try {
        const fsignal = Protocol.decodeF2FSignal(data);
        this.onF2FSignal?.(fsignal);
        return;
      } catch {
        /* not F2FSignal */
      }
    }

    // FodprData starts with pubkey (0x02 or 0x03)
    if (firstByte === 0x02 || firstByte === 0x03) {
      try {
        const fdata = Protocol.decodeData(data);
        this.onDataMessage?.(fdata);
        return;
      } catch {
        /* not FodprData */
      }
    }

    // PeerList: version(8) - first byte is typically 0x00 or small number
    // WoTIntro: introducer pubkey (33 bytes, starts with 0x02/0x03)
    // We try each decoder in order
    try {
      const fdata = Protocol.decodeData(data);
      this.onDataMessage?.(fdata);
      return;
    } catch {
      /* continue */
    }
  }

  // P2P データチャネルでデータ送信
  async sendData(content: Uint8Array, tags: string[] = []): Promise<boolean> {
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

  // P2P データチャネルで F2FSignal 送信 (viaRelay=false)
  async sendF2FSignalDirect(signalType: number, content: string) {
    if (this.state !== 'connected' || !this.dc || this.dc.readyState !== 'open') {
      return;
    }

    const localPubBytes = CryptoUtils.hexToBytes(this.localPubkey);
    const remotePubBytes = CryptoUtils.hexToBytes(this.remotePubkey);
    const signal: F2FSignal = {
      signalType,
      sender: localPubBytes,
      target: remotePubBytes,
      content,
      signature: new Uint8Array(64),
      viaRelay: false,
    };

    const signedData = Protocol.encodeF2FSignalSignedData(signal);
    const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
    signal.signature = CryptoUtils.hexToBytes(sigHex);

    const encoded = Protocol.encodeF2FSignal(signal);
    const frame = new Uint8Array(1 + encoded.length);
    frame[0] = MsgTypeData;
    frame.set(encoded, 1);

    this.dc.send(frame);
  }

  private parseAddress(addr: string): { ip: string; port: number } | null {
    let match = addr.match(/^\[([^\]]+)\]:(\d+)$/);
    if (match) return { ip: match[1], port: parseInt(match[2]) };
    match = addr.match(/^(.+):(\d+)$/);
    if (match) return { ip: match[1], port: parseInt(match[2]) };
    return null;
  }

  close() {
    this.dc?.close();
    this.pc?.close();
    this.state = 'disconnected';
    this._relaySubId = null;
  }
}

// ---------------------------------------------------------------------------
// F2F マネージャー (全体オーケストレーション)
// ---------------------------------------------------------------------------

export type F2FEvent =
  | { type: 'peer_connected'; pubkey: string; addresses: string[] }
  | { type: 'peer_disconnected'; pubkey: string }
  | { type: 'peer_list_received'; from: string; peers: F2FPeerInfo[] }
  | { type: 'wot_intro_received'; from: string; newPeer: F2FPeerInfo }
  | { type: 'invitation_received'; invitation: InvitationCode }
  | { type: 'group_updated'; group: F2FGroupInfo }
  | { type: 'group_host_changed'; groupId: string; oldHost: string; newHost: string }
  | { type: 'data_received'; from: string; content: Uint8Array; tags: string[] }
  | { type: 'error'; message: string }
  | { type: 'seed_nodes'; nodes: F2FPeerInfo[] };

export interface F2FManagerOptions {
  privKeyHex: string;
  relays: RelayClient[];
  seedRelayUrl?: string;
}

export class F2FManager {
  private privKeyHex: string;
  private pubkeyHex: string;
  private relays: RelayClient[];
  private _seedRelayUrl?: string;
  // Referenced via getter to satisfy noUnusedLocals
  get seedRelayUrl(): string | undefined { return this._seedRelayUrl; }

  private peerCache: F2FPeerCache;
  private connections: Map<string, F2FPeerConnection> = new Map();
  private groups: Map<string, F2FGroupInfo> = new Map();

  onEvent: ((event: F2FEvent) => void) | null = null;

  private seedRequested = false;

  constructor(options: F2FManagerOptions) {
    this.privKeyHex = options.privKeyHex;
    this.relays = options.relays;
    this._seedRelayUrl = options.seedRelayUrl;
    const privBytes = CryptoUtils.hexToBytes(options.privKeyHex);
    const pubBytes = CryptoUtils.getRawCompressedPublicKey(privBytes);
    this.pubkeyHex = CryptoUtils.bytesToHex(pubBytes);
    this.peerCache = loadPeerCache();
    this.loadGroups();
  }

  get pubkey(): string {
    return this.pubkeyHex;
  }

  get peerCount(): number {
    return this.connections.size;
  }

  getPeerCache(): F2FPeerInfo[] {
    return this.peerCache.peers;
  }

  getGroups(): F2FGroupInfo[] {
    return Array.from(this.groups.values());
  }

  getConnectionState(pubkeyHex: string): ConnectionState | null {
    const conn = this.connections.get(pubkeyHex);
    return conn ? conn.state : null;
  }

  // --- Bootstrap from seed relay ---

  async bootstrap(): Promise<boolean> {
    const relay = this.relays[0];
    if (!relay) {
      this.onEvent?.({ type: 'error', message: 'No relay available for seed bootstrap' });
      return false;
    }

    try {
      relay.sendSeedRequest(MAX_PEER_CACHE_SIZE);
      this.seedRequested = true;
      return true;
    } catch (e) {
      this.onEvent?.({
        type: 'error',
        message: `Seed bootstrap failed: ${e instanceof Error ? e.message : String(e)}`,
      });
      return false;
    }
  }

  // 招待コードを作成する
  async createInvitation(targetPubkeyHex?: string, expiresInSec = 3600, scope = 1): Promise<string> {
    const addresses = targetPubkeyHex ? [] : ['auto'];
    return generateInvitation(this.privKeyHex, targetPubkeyHex || '', addresses, expiresInSec, scope);
  }

  // 招待コードで接続する
  async connectWithInvitation(code: string): Promise<boolean> {
    try {
      const inv = await parseInvitation(code);
      const now = Math.floor(Date.now() / 1000);
      const valid = now <= Number(inv.expiresAt) && inv.version === 1;
      if (!valid) {
        this.onEvent?.({ type: 'error', message: '無効な招待コードです (期限切れまたはバージョン不一致)' });
        return false;
      }
      const targetPubkey = CryptoUtils.bytesToHex(inv.targetPeer.pubkey);
      const addresses = inv.targetPeer.addresses;
      // 信頼スコアを設定してピアキャッシュに追加
      const peerInfo: F2FPeerInfo = {
        pubkey: targetPubkey,
        addresses,
        lastSeen: Math.floor(Date.now() / 1000),
        trustScore: 1.0,
      };
      this.updatePeerCache([peerInfo]);
      // 接続を試みる
      await this.connectToPeer(targetPubkey);
      this.onEvent?.({ type: 'invitation_received', invitation: inv });
      return true;
    } catch (e) {
      this.onEvent?.({ type: 'error', message: `招待コード接続エラー: ${e instanceof Error ? e.message : String(e)}` });
      return false;
    }
  }

  // シードリレーに自分の情報を登録する (F2F モード開始時)
  async registerSeed(): Promise<boolean> {
    const relay = this.relays[0];
    if (!relay) return false;
    try {
      const pubBytes = CryptoUtils.hexToBytes(this.pubkeyHex);
      const peerInfo: PeerInfo = {
        pubkey: pubBytes,
        addresses: [],
        lastSeen: Math.floor(Date.now() / 1000),
        trustScore: 1.0,
      };
      const announce = JSON.stringify({
        type: 'seed_announce',
        peer: {
          pubkey: CryptoUtils.bytesToHex(peerInfo.pubkey),
          addresses: peerInfo.addresses,
          last_seen: peerInfo.lastSeen,
          trust_score: peerInfo.trustScore,
        },
      });
      relay.sendText(announce);
      return true;
    } catch {
      return false;
    }
  }

  // Handle seed response (called from relay text handler)
  handleSeedResponse(json: string) {
    if (!this.seedRequested) return;
    this.seedRequested = false;

    try {
      const resp: SeedResponse = Protocol.decodeSeedResponse(json);
      const nodes: F2FPeerInfo[] = resp.nodes.map((n) => ({
        pubkey: CryptoUtils.bytesToHex(n.pubkey),
        addresses: n.addresses,
        lastSeen: Math.floor(Date.now() / 1000),
        trustScore: 0.5,
      }));

      this.onEvent?.({ type: 'seed_nodes', nodes });
      this.updatePeerCache(nodes);
      this.onEvent?.({ type: 'peer_list_received', from: 'seed', peers: nodes });
    } catch (e) {
      this.onEvent?.({
        type: 'error',
        message: `Seed response parse error: ${e instanceof Error ? e.message : String(e)}`,
      });
    }
  }

  // --- Peer cache management ---

  private updatePeerCache(newPeers: F2FPeerInfo[]) {
    const now = Math.floor(Date.now() / 1000);
    const merged = [...this.peerCache.peers];
    for (const np of newPeers) {
      const idx = merged.findIndex((p) => p.pubkey === np.pubkey);
      if (idx >= 0) {
        merged[idx] = { ...merged[idx], ...np, lastSeen: now };
      } else {
        merged.push(np);
      }
    }
    merged.sort((a, b) => b.trustScore - a.trustScore);
    const trimmed = merged.slice(0, MAX_PEER_CACHE_SIZE);

    this.peerCache = {
      version: this.peerCache.version + 1,
      peers: trimmed,
      lastUpdated: now,
    };
    savePeerCache(this.peerCache);
  }

  selectPeers(count: number = 5): F2FPeerInfo[] {
    const now = Math.floor(Date.now() / 1000);
    const staleThreshold = 7 * 24 * 3600;
    const fresh = this.peerCache.peers.filter((p) => now - p.lastSeen < staleThreshold);
    const source = fresh.length > 0 ? fresh : this.peerCache.peers;

    const scored = source.map((p) => ({
      peer: p,
      score: p.trustScore * (0.5 + Math.random() * 0.5),
    }));
    scored.sort((a, b) => b.score - a.score);

    return scored.slice(0, count).map((s) => s.peer);
  }

  private updatePeerTrust(pubkeyHex: string, success: boolean) {
    const now = Math.floor(Date.now() / 1000);
    const idx = this.peerCache.peers.findIndex((p) => p.pubkey === pubkeyHex);
    if (idx >= 0) {
      if (success) {
        this.peerCache.peers[idx].trustScore = Math.min(this.peerCache.peers[idx].trustScore + 0.1, 1.0);
      } else {
        this.peerCache.peers[idx].trustScore = Math.max(this.peerCache.peers[idx].trustScore - 0.15, 0.05);
      }
      this.peerCache.peers[idx].lastSeen = now;
    }
    this.peerCache.lastUpdated = now;
    savePeerCache(this.peerCache);
  }

  // --- P2P connection management ---

  async connectToPeer(pubkeyHex: string, addresses: string[] = []): Promise<F2FPeerConnection | null> {
    if (this.connections.has(pubkeyHex)) {
      const existing = this.connections.get(pubkeyHex)!;
      if (existing.state === 'connected') return existing;
    }

    const relay = this.relays[0];
    const conn = new F2FPeerConnection({
      localPrivHex: this.privKeyHex,
      remotePubkeyHex: pubkeyHex,
      relay,
    });

    conn.onDataMessage = (msg) => {
      // Handle PeerList exchange
      if (msg.tags?.includes('peer_list')) {
        this.handlePeerList(msg.content, pubkeyHex).catch(() => {});
        return;
      }
      this.onEvent?.({
        type: 'data_received',
        from: pubkeyHex,
        content: msg.content,
        tags: msg.tags,
      });
    };

    conn.onF2FSignal = (signal) => {
      this.handleIncomingF2FSignal(conn, signal);
    };

    conn.onDisconnect = () => {
      this.onEvent?.({ type: 'peer_disconnected', pubkey: pubkeyHex });
      this.connections.delete(pubkeyHex);
      this.updatePeerTrust(pubkeyHex, false);
    };

    this.connections.set(pubkeyHex, conn);

    // Set up relay subscription for F2F signaling
    const subId = `f2f_${pubkeyHex.slice(0, 8)}_${Date.now()}`;
    conn.setRelaySubscription(subId);

    try {
      const success = await conn.initiateConnection(addresses);
      if (success) {
        this.onEvent?.({ type: 'peer_connected', pubkey: pubkeyHex, addresses });
        this.updatePeerTrust(pubkeyHex, true);
        // Send PeerList after connection established
        this.sendPeerList(conn).catch(() => {});
      }
      return conn;
    } catch (e) {
      this.onEvent?.({
        type: 'error',
        message: `Failed to connect to peer ${pubkeyHex.slice(0, 12)}...: ${e instanceof Error ? e.message : String(e)}`,
      });
      return null;
    }
  }

  // Send PeerList to a connected peer (WoT cache sync)
  private async sendPeerList(conn: F2FPeerConnection): Promise<void> {
    if (conn.state !== 'connected') return;
    const peerList: PeerList = {
      version: this.peerCache.version,
      peerCount: this.peerCache.peers.length,
      peers: this.peerCache.peers.map((p) => ({
        pubkey: CryptoUtils.hexToBytes(p.pubkey),
        addresses: p.addresses,
        lastSeen: p.lastSeen,
        trustScore: p.trustScore,
      })),
      signature: new Uint8Array(64),
    };
    const signedData = Protocol.encodePeerListSignedData(peerList);
    const sigHex = await CryptoUtils.signMessage(this.privKeyHex, signedData);
    peerList.signature = CryptoUtils.hexToBytes(sigHex);
    const encoded = Protocol.encodePeerList(peerList);
    await conn.sendData(encoded, ['peer_list']);
  }

  // Handle incoming PeerList from peer (merge into cache, dial new peers)
  private async handlePeerList(data: Uint8Array, fromPubkey: string): Promise<void> {
    try {
      const peerList = Protocol.decodePeerList(data);
      const newPeers: F2FPeerInfo[] = peerList.peers.map((p) => ({
        pubkey: CryptoUtils.bytesToHex(p.pubkey),
        addresses: p.addresses,
        lastSeen: p.lastSeen,
        trustScore: p.trustScore,
      }));
      // Update cache with received peers
      this.updatePeerCache(newPeers);
      this.onEvent?.({ type: 'peer_list_received', from: fromPubkey, peers: newPeers });
      // Dial new peers from received list (up to max connections)
      for (const peer of newPeers) {
        if (peer.pubkey === this.pubkeyHex) continue;
        if (this.connections.has(peer.pubkey)) continue;
        if (this.connections.size >= 50) break;
        this.connectToPeer(peer.pubkey, peer.addresses).catch(() => {});
      }
    } catch {
      // Invalid PeerList, ignore
    }
  }

  // Handle incoming F2F signaling (from relay or P2P)
  handleIncomingF2FSignal(conn: F2FPeerConnection, signal: F2FSignal) {
    if (signal.signalType === SignalOffer) {
      const json = JSON.parse(signal.content);
      conn.handleOffer(json.sdp).catch(() => {});
    } else if (signal.signalType === SignalAnswer) {
      const json = JSON.parse(signal.content);
      conn.handleAnswer(json.sdp).catch(() => {});
    } else if (signal.signalType === SignalCandidate) {
      const json = JSON.parse(signal.content);
      conn.handleCandidate({
        candidate: json.candidate,
        sdpMid: json.sdpMid,
        sdpMLineIndex: json.sdpMLineIndex,
      }).catch(() => {});
    }
  }

  // グループ・ピアのリレー購読を開始する(接続確立後に呼ぶ)。
  start() {
    this.subscribeOwnGroups();
    this.subscribeKnownGroups();
  }

  // Handle relay push messages
  handleRelayMessage(msg: { kind: string; [key: string]: any }) {
    if (msg.kind === 'event' && msg.event) {
      this.handleGroupEvent(msg.event as FodprEvent);
    }
    if (msg.kind === 'f2fSignal' && msg.f2fSignal) {
      const sig = msg.f2fSignal;
      const senderHex = CryptoUtils.bytesToHex(sig.sender);
      const conn = this.connections.get(senderHex);
      if (conn) {
        conn.onF2FSignal?.(sig);
      } else if (sig.signalType === SignalOffer) {
        // Incoming connection request from a new peer
        const newConn = new F2FPeerConnection({
          localPrivHex: this.privKeyHex,
          remotePubkeyHex: senderHex,
          relay: this.relays[0],
        });
        newConn.onDataMessage = (dataMsg) => {
          this.onEvent?.({
            type: 'data_received',
            from: senderHex,
            content: dataMsg.content,
            tags: dataMsg.tags,
          });
        };
        newConn.onF2FSignal = (s) => {
          this.handleIncomingF2FSignal(newConn, s);
        };
        newConn.onDisconnect = () => {
          this.connections.delete(senderHex);
          this.updatePeerTrust(senderHex, false);
        };

        this.connections.set(senderHex, newConn);
        const json = JSON.parse(sig.content);
        newConn.handleOffer(json.sdp).catch(() => {});
      }
    }

    if (msg.kind === 'data' && msg.dataMsg) {
      const dataMsg = msg.dataMsg;
      const senderHex = CryptoUtils.bytesToHex(dataMsg.sender);
      const conn = this.connections.get(senderHex);
      if (conn) {
        conn.onDataMessage?.(dataMsg);
      }
    }
  }

  // --- Group management ---

  createGroup(groupId?: string): F2FGroupInfo {
    const now = Math.floor(Date.now() / 1000);
    const gid = groupId || this.pubkeyHex;

    const host: F2FGroupMember = {
      pubkey: this.pubkeyHex,
      addresses: [],
      joinedAt: now,
      isHost: true,
      isConnected: true,
    };

    const group: F2FGroupInfo = {
      groupId: gid,
      hostPubkey: this.pubkeyHex,
      members: [host],
      version: 1,
      createdAt: now,
      state: 'active',
      isHost: true,
      joinedAt: now,
      lastHeartbeat: now,
    };

    this.groups.set(gid, group);
    saveGroups(Array.from(this.groups.values()));
    this.onEvent?.({ type: 'group_updated', group });
    this.publishGroup(group).catch(() => {});
    this.subscribeOwnGroups();
    return group;
  }

  getGroup(groupId: string): F2FGroupInfo | undefined {
    return this.groups.get(groupId);
  }

  updateGroup(group: F2FGroupInfo) {
    this.groups.set(group.groupId, group);
    saveGroups(Array.from(this.groups.values()));
    this.onEvent?.({ type: 'group_updated', group });
    this.publishGroup(group);
  }

  // --- TransTypeGroup による端末間グループ同期 ---

  // 自分がホストのグループ (`group:<自分のfpub>`) をリレーから購読する。
  // これにより別端末で作成したグループを端末を変えても復元できる。
  subscribeOwnGroups() {
    const subId = `f2f_grp_${this.pubkeyHex.slice(0, 8)}_${Date.now()}`;
    const req = {
      subId,
      transType: TransTypeGroup,
      tagKey: 'group',
      tagVal: this.pubkeyHex,
    };
    for (const relay of this.relays) {
      try {
        relay.sendReq(req);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }

  // F2FGroupInfo をワイヤ F2FGroup に変換して TransTypeGroup イベントとして投稿する。
  async publishGroup(group: F2FGroupInfo): Promise<boolean> {
    const wire: F2FGroup = {
      groupId: group.groupId,
      hostPubkey: CryptoUtils.hexToBytes(group.hostPubkey),
      members: group.members.map(
        (m): GroupMember => ({
          pubkey: CryptoUtils.hexToBytes(m.pubkey),
          addresses: m.addresses,
          joinedAt: m.joinedAt,
          isHost: m.isHost,
          isConnected: m.isConnected,
        }),
      ),
      version: group.version,
      createdAt: group.createdAt,
      signature: new Uint8Array(64),
    };
    const signedData = Protocol.encodeGroupSignedData(wire);
    const privBytes = CryptoUtils.hexToBytes(this.privKeyHex);
    const sigHex = await CryptoUtils.signMessage(privBytes, signedData);
    wire.signature = CryptoUtils.hexToBytes(sigHex);
    const content = Protocol.encodeGroup(wire);

    const event: FodprEvent = {
      transType: TransTypeGroup,
      createdAt: Math.floor(Date.now() / 1000),
      pubkey: CryptoUtils.hexToBytes(this.pubkeyHex),
      tags: [`group:${group.groupId}`],
      content,
      signature: new Uint8Array(64),
    };
    const contentSigHex = await CryptoUtils.signMessage(privBytes, content);
    event.signature = CryptoUtils.hexToBytes(contentSigHex);

    let ok = false;
    for (const relay of this.relays) {
      try {
        relay.sendEvent(event);
        ok = true;
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
    return ok;
  }

  // リレーから受信した TransTypeGroup イベントでグループ状態を同期する。
  private handleGroupEvent(event: FodprEvent) {
    if (event.transType !== TransTypeGroup) return;
    try {
      const wire = Protocol.decodeGroup(event.content);
      const wireId = wire.groupId;
      // 既知のグループ、または自分のグループのみ取り込む(他人の未知グループは無視)
      if (!this.groups.has(wireId) && wireId !== this.pubkeyHex) return;

      const existing = this.groups.get(wireId);
      if (existing && wire.version <= existing.version) return;

      const now = Math.floor(Date.now() / 1000);
      const synced: F2FGroupInfo = {
        groupId: wireId,
        hostPubkey: CryptoUtils.bytesToHex(wire.hostPubkey),
        members: wire.members.map((m) => ({
          pubkey: CryptoUtils.bytesToHex(m.pubkey),
          addresses: m.addresses,
          joinedAt: Number(m.joinedAt),
          isHost: m.isHost,
          isConnected: m.isConnected,
        })),
        version: Number(wire.version),
        createdAt: Number(wire.createdAt),
        state: 'active',
        isHost: CryptoUtils.bytesToHex(wire.hostPubkey) === this.pubkeyHex,
        joinedAt: existing?.joinedAt ?? now,
        lastHeartbeat: now,
      };
      this.groups.set(wireId, synced);
      saveGroups(Array.from(this.groups.values()));
      this.onEvent?.({ type: 'group_updated', group: synced });
    } catch {
      /* グループデコード失敗は無視 */
    }
  }

  // 自分がホストのグループ、または参加中のグループを TransTypeGroup で同期する。
  private subscribeKnownGroups() {
    const groupIds = new Set<string>([this.pubkeyHex]);
    for (const g of this.groups.values()) {
      groupIds.add(g.groupId);
      groupIds.add(g.hostPubkey);
    }
    for (const gid of groupIds) {
      const req = {
        subId: `f2f_grp_${gid.slice(0, 8)}_${Date.now()}`,
        transType: TransTypeGroup,
        tagKey: 'group',
        tagVal: gid,
      };
      for (const relay of this.relays) {
        try {
          relay.sendReq(req);
        } catch {
          /* 未接続のリレーは無視 */
        }
      }
    }
  }

  // Handle host change (host disconnected, promote oldest member)
  promoteNewHost(groupId: string): F2FGroupInfo | null {
    const group = this.groups.get(groupId);
    if (!group || !group.isHost) return null;
    if (group.hostPubkey !== this.pubkeyHex) return null;

    // Find connected non-host members sorted by joinedAt (oldest first)
    const candidates = group.members
      .filter((m) => !m.isHost && m.isConnected)
      .sort((a, b) => a.joinedAt - b.joinedAt);

    if (candidates.length === 0) {
      group.state = 'disbanded';
      saveGroups(Array.from(this.groups.values()));
      return group;
    }

    const oldHost = group.hostPubkey;
    const newHost = candidates[0];

    group.members = group.members.map((m) => ({
      ...m,
      isHost: m.pubkey === newHost.pubkey,
    }));
    group.hostPubkey = newHost.pubkey;
    group.version += 1;
    group.state = 'promoting';
    group.isHost = newHost.pubkey === this.pubkeyHex;

    saveGroups(Array.from(this.groups.values()));
    this.onEvent?.({
      type: 'group_host_changed',
      groupId,
      oldHost,
      newHost: newHost.pubkey,
    });
    this.onEvent?.({ type: 'group_updated', group });
    this.publishGroup(group).catch(() => {});
    return group;
  }

  // Check group heartbeats and promote host if needed
  checkGroupHeartbeats() {
    const now = Date.now();
    for (const group of this.groups.values()) {
      if (group.state === 'active' && group.isHost) {
        if (now - group.lastHeartbeat > 30000) {
          // Host is unresponsive, try to promote
          this.promoteNewHost(group.groupId);
        }
      }
    }
  }

  // --- Group member management ---

  getConnectedPeers(): string[] {
    return Array.from(this.connections.entries())
      .filter(([_, conn]) => conn.state === 'connected')
      .map(([pubkey]) => pubkey);
  }

  async connectToMultiplePeers(pubkeys: string[]) {
    for (const pk of pubkeys) {
      if (!this.connections.has(pk)) {
        await this.connectToPeer(pk);
      }
    }
  }

  // Close all connections
  close() {
    for (const conn of this.connections.values()) {
      conn.close();
    }
    this.connections.clear();
  }

  private loadGroups() {
    const saved = loadGroups();
    for (const g of saved) {
      this.groups.set(g.groupId, g);
    }
  }
}

// Re-export for consumers
export type { ConnectionState };
