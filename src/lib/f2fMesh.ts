/**
 * f2fMesh.ts
 * ----------
 * F2F メッシュマネージャー (v0.6)。
 *
 * リレー・ホストのない完全 P2P メッシュ。すべての接続はクライアント間 (F2F) の
 * WebRTC データチャネル。
 *
 * - ダイアル: DHT で発見した IPv6 アドレスへ直接 WebRTC ダイアル。
 *   失敗時は接続済みメッシュピアを介したシグナリングへフォールバック。
 * - ゴシップ: 署名付きイベントを hop 制限 (MAX_HOPS=2) 付きでメッシュに洪水し、
 *   eventId で重複排除する。
 * - ブートストラップ (リレーなし): 招待コード (f2finv1...)、設定済みブートストラップ
 *   ノード (fpub1...@[ipv6]:port)、手動 IP 入力。
 * - ピアキャッシュ (localStorage.fodpr_f2f_peer_cache) + WoT ゲート
 *   (localStorage.fodpr_peer_trust) + DHT ルーティングテーブル
 *   (localStorage.fodpr_dht_table)。
 *
 * データチャネル上のフレーム (すべて FodprData に包み、tags で振り分け):
 *   ['type:dht']      content = [DhtMsgType(1)] [encodeDht(DhtMessage)]
 *   ['type:event']    content = [MsgTypeEvent(1)] [encodeEvent(FodprEvent)]
 *   ['type:peerlist'] content = [MsgTypePeerListPush(1)] [encodePeerList(PeerList)]
 *   ['type:wotintro'] content = [MsgTypeWoTIntroPush(1)] [encodeWoTIntro(WoTIntro)]
 *   ['type:signal']   content = [MsgTypeSignal(1)] [encodeSignal(FodprSignal)]
 *   ['type:datamsg']  content = 生バイト列 (直接メッセージ)
 */

import {
  Protocol,
  MsgTypeEvent,
  MsgTypeSignal,
  MsgTypePeerListPush,
  MsgTypeWoTIntroPush,
  SignalOffer,
  SignalAnswer,
  SignalCandidate,
  DhtOpPong,
  DhtOpFindNode,
  DhtOpFindValue,
  DhtOpStore,
  type FodprEvent,
  type FodprSignal,
  type FodprData,
  type PeerList,
  type WoTIntro,
  type InvitationCode,
  type DhtMessage,
} from '@fodpr/protocol';
import { CryptoUtils } from '@fodpr/crypto';
import {
  F2FPeerConnection,
  generateInvitation,
  parseInvitation,
  type F2FPeerInfo,
  type F2FPeerCache,
  type F2FSignalMessage,
  type ConnectionState,
} from './fodprF2f';
import { DhtNode, isDhtFrame, DHT_RPC_TIMEOUT_MS, type DhtNodeInfo } from './dht';
import { WoTStore } from './wot';

export const BOOTSTRAP_NODES_KEY = 'fodpr_bootstrap_nodes';
export const OWN_ADDRESSES_KEY = 'fodpr_own_addresses';
const MAX_HOPS = 2;
const MAX_EVENT_CACHE = 500;
const MAX_CONNECTIONS = 50;

/**
 * ビルトインコミュニティブートストラップアンカーノード (v0.6)。
 *
 * ユーザーが `fodpr_bootstrap_nodes` を 1 つも設定しておらず、過去のピアキャッシュも
 * 空の **完全孤立** の状態から自動でメッシュへ参入できるための "入口"。
 *
 * - Bitcoin のハードコードシード IP / IPFS の bootnodes と同じアプローチ。
 * - これらはコミュニティが運営する常駐アンカーノード (IPv6, 常時リスン) である。
 *   初回 1 本ダイヤルで信頼 (trustScore 1.0) となり、DHT FIND_VALUE で
 *   公開鍵 → IPv6 を解決しながら WoT/DHT グラフが拡大する。
 * - ユーザーは設定画面で任意に上書き・追加できる。ビルトインが 1 つも到達不能でも
 *   ユーザー設定 / 招待コード / 手動 IP 入力でフォールバック可能。
 *
 * 運営者向け: アンカーを新設・交換するには pubkey (HEX 33 bytes compressed) と
 * 常時リスンする IPv6 `[addr]:port` を以下に追記する。秘密鍵はクライアントに
 * 決して同梱しない (dial-only、接続先公開鍵で検証は行わない)。
 */
export const FODPR_BOOTSTRAP_ANCHORS: F2FPeerInfo[] = [
  {
    pubkey: '02b3c82426768c46023c5e7ce95036c4965e70691481ea80bc80d1f3f837200987',
    addresses: ['[2001:db8:1::1]:443'],
    lastSeen: Math.floor(Date.now() / 1000),
    trustScore: 1.0,
  },
  {
    pubkey: '0385bc05912100673e4321620008b67471d373e5c1ad21e18e2285f6d6f7d946a1',
    addresses: ['[2001:db8:2::1]:443'],
    lastSeen: Math.floor(Date.now() / 1000),
    trustScore: 1.0,
  },
];

/** 今回のブートストラップでビルトインアンカーにフォールバックしたか (UI表示用) */
export const BOOTSTRAP_SOURCE_KEY = 'fodpr_bootstrap_source';

export type MeshEvent =
  | { type: 'peer_connected'; pubkey: string; addresses: string[] }
  | { type: 'peer_disconnected'; pubkey: string }
  | { type: 'peer_list_received'; from: string; peers: F2FPeerInfo[] }
  | { type: 'wot_intro_received'; from: string; newPeer: F2FPeerInfo }
  | { type: 'invitation_received'; invitation: InvitationCode }
  | { type: 'event_received'; event: FodprEvent }
  | { type: 'data_received'; from: string; content: Uint8Array; tags: string[] }
  | { type: 'error'; message: string }
  | { type: 'seed_nodes'; nodes: F2FPeerInfo[] };

interface DhtReply {
  value: Uint8Array;
  nodes: DhtNodeInfo[];
}

export interface MeshManagerOptions {
  privKeyHex: string;
}

export function loadBootstrapNodes(): string[] {
  try {
    const raw = localStorage.getItem(BOOTSTRAP_NODES_KEY);
    if (!raw) return [];
    const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
    return parts.filter((p) => p.includes('@'));
  } catch {
    return [];
  }
}

export function saveBootstrapNodes(nodes: string[]) {
  try {
    localStorage.setItem(BOOTSTRAP_NODES_KEY, nodes.join(','));
  } catch {
    /* ignore */
  }
}

export function loadOwnAddresses(): string[] {
  try {
    const raw = localStorage.getItem(OWN_ADDRESSES_KEY);
    if (!raw) return [];
    return raw.split(',').map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

export function saveOwnAddresses(addresses: string[]) {
  try {
    localStorage.setItem(OWN_ADDRESSES_KEY, addresses.join(','));
  } catch {
    /* ignore */
  }
}

/** fpub1...@[ipv6]:port 形式のブートストラップノードを解析する */
export function parseBootstrapNode(spec: string): { pubkeyHex: string; address: string } | null {
  const at = spec.lastIndexOf('@');
  if (at <= 0) return null;
  const fpub = spec.slice(0, at);
  const addr = spec.slice(at + 1);
  if (!addr) return null;
  try {
    const pubBytes = CryptoUtils.fpubDecode(fpub);
    const pubkeyHex = CryptoUtils.bytesToHex(pubBytes);
    return { pubkeyHex, address: addr };
  } catch {
    return null;
  }
}

export class MeshManager {
  private privKeyHex: string;
  readonly pubkeyHex: string;
  readonly pubkeyBytes: Uint8Array;

  private peerCache: F2FPeerCache;
  private connections: Map<string, F2FPeerConnection> = new Map();
  private wot: WoTStore;
  private dht: DhtNode;

  private seenEvents = new Set<string>();
  private localEvents: FodprEvent[] = [];
  private pendingDials = new Set<string>();
  private pending: Map<string, { op: number; resolve: (r: DhtReply) => void }> = new Map();

  onEvent: ((event: MeshEvent) => void) | null = null;

  constructor(options: MeshManagerOptions) {
    this.privKeyHex = options.privKeyHex;
    const privBytes = CryptoUtils.hexToBytes(options.privKeyHex);
    this.pubkeyBytes = CryptoUtils.getRawCompressedPublicKey(privBytes);
    this.pubkeyHex = CryptoUtils.bytesToHex(this.pubkeyBytes);
    this.peerCache = this.loadPeerCache();
    this.wot = new WoTStore();
    this.dht = new DhtNode(options.privKeyHex, this.wot.minTrust);
    this.saveTable();
    this.seedRoutingFromCache();
    // 自分の接続先アドレスを自身の kvStore に置いておく (FIND_VALUE で直接返す)
    const ownAddrs = loadOwnAddresses();
    if (ownAddrs.length > 0) {
      this.dht.kvStore.set(CryptoUtils.bytesToHex(this.dht.localNodeId), JSON.stringify({ addresses: ownAddrs }));
    }
  }

  // --- 公開アクセサ ---

  get peerCount(): number {
    return this.connections.size;
  }

  get connected(): boolean {
    return this.peerCount > 0;
  }

  getPeers(): F2FPeerInfo[] {
    return this.peerCache.peers;
  }

  getPeerCache(): F2FPeerInfo[] {
    return this.peerCache.peers;
  }

  getDhtNodes(): F2FPeerInfo[] {
    return this.dht.table.allNodes().map((n) => ({
      pubkey: CryptoUtils.bytesToHex(n.pubkey),
      addresses: n.addresses,
      lastSeen: Number(n.lastSeen),
      trustScore: n.trustScore,
    }));
  }

  getTrustEntries() {
    return this.wot.getAll();
  }

  getConnectionState(pubkeyHex: string): ConnectionState | null {
    const conn = this.connections.get(pubkeyHex);
    return conn ? conn.state : null;
  }

  // --- ピアキャッシュ管理 ---

  private loadPeerCache(): F2FPeerCache {
    try {
      const raw = localStorage.getItem('fodpr_f2f_peer_cache');
      if (raw) return JSON.parse(raw);
    } catch {
      /* ignore */
    }
    return { version: 1, peers: [], lastUpdated: 0 };
  }

  private savePeerCache() {
    try {
      localStorage.setItem('fodpr_f2f_peer_cache', JSON.stringify(this.peerCache));
    } catch {
      /* ignore */
    }
  }

  private saveTable() {
    this.dht.table.save();
  }

  private updatePeerCache(newPeers: F2FPeerInfo[]) {
    const now = Math.floor(Date.now() / 1000);
    const merged = [...this.peerCache.peers];
    for (const np of newPeers) {
      if (np.pubkey === this.pubkeyHex) continue;
      const idx = merged.findIndex((p) => p.pubkey === np.pubkey);
      if (idx >= 0) {
        merged[idx] = {
          ...merged[idx],
          ...np,
          addresses: np.addresses.length > 0 ? np.addresses : merged[idx].addresses,
          lastSeen: now,
        };
      } else {
        merged.push({ ...np, lastSeen: now });
      }
    }
    merged.sort((a, b) => b.trustScore - a.trustScore);
    const trimmed = merged.slice(0, 50);

    this.peerCache = {
      version: this.peerCache.version + 1,
      peers: trimmed,
      lastUpdated: now,
    };
    this.savePeerCache();
  }

  private seedRoutingFromCache() {
    for (const p of this.peerCache.peers) {
      const nodeId = Protocol.nodeId(CryptoUtils.hexToBytes(p.pubkey));
      this.dht.table.addNode(
        {
          nodeId,
          pubkey: CryptoUtils.hexToBytes(p.pubkey),
          addresses: p.addresses,
          lastSeen: p.lastSeen,
          trustScore: p.trustScore,
        },
        0,
      );
    }
    this.saveTable();
  }

  // --- ブートストラップ ---

  /**
   * 利用可能なブートストラップ候補を選択する (純粋関数)。
   * - ユーザー設定 (`fodpr_bootstrap_nodes`) が 1 つでもあれば優先。
   * - 空の場合はビルトインコミュニティアンカー `FODPR_BOOTSTRAP_ANCHORS` へフォールバック。
   * WebRTC/ダイアルは伴わないためテスト可能。
   */
  static selectBootstrapCandidates(userSpecs: string[]): F2FPeerInfo[] {
    const userPeers: F2FPeerInfo[] = [];
    for (const spec of userSpecs) {
      const parsed = parseBootstrapNode(spec);
      if (!parsed) continue;
      userPeers.push({
        pubkey: parsed.pubkeyHex,
        addresses: [parsed.address],
        lastSeen: Math.floor(Date.now() / 1000),
        trustScore: 1.0,
      });
    }
    if (userPeers.length > 0) return userPeers;
    // ビルトインアンカー (コピーして返す — 呼出し側で可変化を避ける)
    return FODPR_BOOTSTRAP_ANCHORS.map((p) => ({ ...p, addresses: [...p.addresses] }));
  }

  /** 設定済みブートストラップノード (ユーザー) へ接続する (リレーなし)。
   * ユーザー設定が空の場合はビルトインコミュニティアンカーへフォールバックする。 */
  async bootstrap(): Promise<boolean> {
    const userSpecs = loadBootstrapNodes();
    const usingBuiltIn = userSpecs.length === 0;
    try {
      localStorage.setItem(BOOTSTRAP_SOURCE_KEY, usingBuiltIn ? 'builtin' : 'user');
    } catch {
      /* ignore */
    }

    const candidates = MeshManager.selectBootstrapCandidates(userSpecs);
    if (candidates.length === 0) {
      this.onEvent?.({ type: 'error', message: 'ブートストラップノードが設定されていません (fpub@[ipv6]:port)' });
      return false;
    }

    const seeds: F2FPeerInfo[] = [];
    let ok = false;
    for (const peer of candidates) {
      this.wot.recordSuccess(peer.pubkey);
      const added = await this.connectToPeer(peer.pubkey, peer.addresses);
      if (added) ok = true;
      seeds.push({ ...peer });
    }
    this.updatePeerCache(seeds);
    if (seeds.length > 0) {
      this.onEvent?.({ type: 'seed_nodes', nodes: seeds });
    }
    return ok;
  }

  // --- 接続管理 ---

  /** アドレスが既知 (招待/ブートストラップ/手動) のピアへ直接ダイアルする。 */
  async connectToPeer(pubkeyHex: string, addresses: string[] = []): Promise<boolean> {
    if (pubkeyHex === this.pubkeyHex) return false;
    if (this.pendingDials.has(pubkeyHex)) return false;
    if (this.connections.has(pubkeyHex)) {
      const existing = this.connections.get(pubkeyHex)!;
      return existing.state === 'connected';
    }
    if (this.connections.size >= MAX_CONNECTIONS) return false;

    // WoT ゲート: 明示アドレスなしの DHT 発見ピアはスコアが閾値以上でなければダイアルしない
    const explicit = addresses.length > 0;
    if (!explicit && !this.wot.isTrusted(pubkeyHex)) {
      return false;
    }

    this.pendingDials.add(pubkeyHex);
    try {
      const cacheEntry = this.peerCache.peers.find((p) => p.pubkey === pubkeyHex);
      const dialAddresses = addresses.length > 0
        ? addresses
        : (cacheEntry?.addresses ?? []);

      const conn = new F2FPeerConnection({
        localPrivHex: this.privKeyHex,
        remotePubkeyHex: pubkeyHex,
      });
      this.setupConnection(conn, dialAddresses);

      const signaler = this.makeSignaler(pubkeyHex);
      conn.onSignal = (s) => signaler(s);
      conn.onDisconnect = () => {
        this.onEvent?.({ type: 'peer_disconnected', pubkey: pubkeyHex });
        this.connections.delete(pubkeyHex);
        this.wot.recordFailure(pubkeyHex);
      };

      this.connections.set(pubkeyHex, conn);
      const success = await conn.initiateConnection(dialAddresses);
      if (success) {
        this.onEvent?.({ type: 'peer_connected', pubkey: pubkeyHex, addresses: dialAddresses });
        this.wot.recordSuccess(pubkeyHex);
        this.updatePeerCache([
          {
            pubkey: pubkeyHex,
            addresses: dialAddresses,
            lastSeen: Math.floor(Date.now() / 1000),
            trustScore: this.wot.getScore(pubkeyHex),
          },
        ]);
        // 接続確立後に DHT / PeerList 交換
        this.afterConnect(conn, pubkeyHex).catch(() => {});
        // 他の接続済みピアへ WoT 紹介を流す
        this.broadcastWoTIntro(pubkeyHex, dialAddresses);
      }
      return success;
    } catch {
      this.connections.delete(pubkeyHex);
      return false;
    } finally {
      this.pendingDials.delete(pubkeyHex);
    }
  }

  /** 着信シグナル (offer) から接続を受け入れる。 */
  private async acceptOffer(pubkeyHex: string, offerSdp: string) {
    if (this.connections.size >= MAX_CONNECTIONS && !this.connections.has(pubkeyHex)) return;
    let conn = this.connections.get(pubkeyHex);
    if (!conn) {
      conn = new F2FPeerConnection({
        localPrivHex: this.privKeyHex,
        remotePubkeyHex: pubkeyHex,
      });
      this.setupConnection(conn, []);
      const signaler = this.makeSignaler(pubkeyHex);
      conn.onSignal = (s) => signaler(s);
      conn.onDisconnect = () => {
        this.onEvent?.({ type: 'peer_disconnected', pubkey: pubkeyHex });
        this.connections.delete(pubkeyHex);
        this.wot.recordFailure(pubkeyHex);
      };
      this.connections.set(pubkeyHex, conn);
    }
    await conn.handleOffer(offerSdp);
  }

  private makeSignaler(targetPubkeyHex: string) {
    return (signal: F2FSignalMessage) => {
      this.sendSignalViaMesh(targetPubkeyHex, signal).catch(() => {});
    };
  }

  /**
   * シグナルをメッシュ経由で宛先へ配送する。
   * まず直接データチャネルが確立済みならそこへ、そうでなければ接続済みピアへ
   * 'type:signal' フレームとして転送を依頼する (リレーなしのフォールバック)。
   */
  private async sendSignalViaMesh(targetPubkeyHex: string, signal: F2FSignalMessage): Promise<boolean> {
    const direct = this.connections.get(targetPubkeyHex);
    if (direct && direct.state === 'connected') {
      return this.sendSignalFrame(direct, signal);
    }
    for (const [pk, conn] of this.connections) {
      if (pk === targetPubkeyHex) continue;
      if (conn.state !== 'connected') continue;
      try {
        const ok = await this.sendSignalFrame(conn, signal);
        if (ok) return true;
      } catch {
        /* 次のピアへ */
      }
    }
    return false;
  }

  private async sendSignalFrame(conn: F2FPeerConnection, signal: F2FSignalMessage): Promise<boolean> {
    const localPubBytes = this.pubkeyBytes;
    const remotePubBytes = CryptoUtils.hexToBytes(conn.remotePubkey);
    const s: FodprSignal = {
      signalType: signal.signalType,
      sender: localPubBytes,
      target: remotePubBytes,
      content: signal.content,
      signature: new Uint8Array(64),
    };
    const signedData = Protocol.encodeSignalSignedData(s);
    const sigHex = await CryptoUtils.signMessage(this.privKeyHex, signedData);
    s.signature = CryptoUtils.hexToBytes(sigHex);

    const encoded = Protocol.encodeSignal(s);
    const frame = new Uint8Array(1 + encoded.length);
    frame[0] = MsgTypeSignal;
    frame.set(encoded, 1);
    return conn.sendData(frame, ['type:signal']);
  }

  /** 接続確立後の初期化: 自分の DHT 値を STORE し、PeerList を交換する。 */
  private async afterConnect(conn: F2FPeerConnection, remotePubkeyHex: string) {
    // 自分の接続先アドレスを相手に STORE してもらう
    const ownAddrs = loadOwnAddresses();
    if (ownAddrs.length > 0) {
      await this.sendStoreTo(conn, this.dht.localNodeId, JSON.stringify({ addresses: ownAddrs }));
    }
    // 相手のアドレスを FIND_VALUE で取りに行く
    await this.findValueForPeer(remotePubkeyHex);
    // PeerList 交換
    this.sendPeerList(conn).catch(() => {});
  }

  // --- 招待コード ---

  async createInvitation(targetPubkeyHex?: string, expiresInSec = 3600, scope = 1): Promise<string> {
    const addresses = loadOwnAddresses();
    return generateInvitation(this.privKeyHex, targetPubkeyHex || '', addresses, expiresInSec, scope);
  }

  async connectWithInvitation(code: string): Promise<boolean> {
    try {
      const inv = await parseInvitation(code);
      const now = Math.floor(Date.now() / 1000);
      if (now > Number(inv.expiresAt) || inv.version !== 1) {
        this.onEvent?.({ type: 'error', message: '無効な招待コードです (期限切れまたはバージョン不一致)' });
        return false;
      }
      const targetPubkey = CryptoUtils.bytesToHex(inv.targetPeer.pubkey);
      const addresses = inv.targetPeer.addresses;
      // 招待者は信頼済みとみなす (WoT 紹介)
      this.wot.applyIntroduction(CryptoUtils.bytesToHex(inv.issuer), targetPubkey);
      this.updatePeerCache([
        {
          pubkey: targetPubkey,
          addresses,
          lastSeen: now,
          trustScore: this.wot.getScore(targetPubkey),
        },
      ]);
      this.onEvent?.({ type: 'invitation_received', invitation: inv });
      const ok = await this.connectToPeer(targetPubkey, addresses);
      if (!ok && addresses.length === 0) {
        // アドレスが無ければ DHT 解決を試みる
        await this.resolveAndDial(targetPubkey);
      }
      return true;
    } catch (e) {
      this.onEvent?.({ type: 'error', message: `招待コード接続エラー: ${e instanceof Error ? e.message : String(e)}` });
      return false;
    }
  }

  /** DHT でアドレスを解決してからダイアルする。 */
  async resolveAndDial(pubkeyHex: string): Promise<boolean> {
    const targetNodeId = Protocol.nodeId(CryptoUtils.hexToBytes(pubkeyHex));
    const value = await this.findValue(targetNodeId);
    if (value) {
      try {
        const obj = JSON.parse(value);
        if (Array.isArray(obj?.addresses) && obj.addresses.length > 0) {
          const ok = await this.connectToPeer(pubkeyHex, obj.addresses);
          if (ok) return true;
        }
      } catch {
        /* 不正な値は無視 */
      }
    }
    // FIND_VALUE で解決できなかった場合は PING で近傍探索
    await this.findNode(targetNodeId);
    return false;
  }

  // --- ゴシップ (イベント配信) ---

  /** 署名付きイベントをメッシュへブロードキャストする (hop 0)。 */
  async broadcastEvent(event: FodprEvent): Promise<boolean> {
    const eventIdHex = Protocol.eventIdHex(event);
    if (this.seenEvents.has(eventIdHex)) return true;
    this.seenEvents.add(eventIdHex);
    this.localEvents.push(event);
    if (this.localEvents.length > MAX_EVENT_CACHE) {
      this.localEvents.shift();
    }
    this.onEvent?.({ type: 'event_received', event });

    let sent = false;
    for (const conn of this.connections.values()) {
      if (conn.state !== 'connected') continue;
      try {
        await this.sendEventFrame(conn, event, 0);
        sent = true;
      } catch {
        /* 送信失敗は無視 */
      }
    }
    return sent;
  }

  private async sendEventFrame(conn: F2FPeerConnection, event: FodprEvent, hop: number): Promise<boolean> {
    const encoded = Protocol.encodeEvent(event);
    const frame = new Uint8Array(1 + encoded.length);
    frame[0] = MsgTypeEvent;
    frame.set(encoded, 1);
    return conn.sendData(frame, ['type:event', `hop:${hop}`]);
  }

  /** 受信したゴシップイベントを検証し、まだ見ていなければ転送する。 */
  private async handleIncomingEvent(conn: F2FPeerConnection, event: FodprEvent, hop: number) {
    // 署名検証 (イベント署名は content の SHA-256 に対する ECDSA)
    try {
      const ok = await CryptoUtils.verifySignature(event.pubkey, event.content, event.signature);
      if (!ok) return;
    } catch {
      return;
    }

    const eventIdHex = Protocol.eventIdHex(event);
    if (this.seenEvents.has(eventIdHex)) return;
    this.seenEvents.add(eventIdHex);
    if (this.seenEvents.size > 5000) {
      const first = this.seenEvents.values().next().value;
      if (first !== undefined) this.seenEvents.delete(first);
    }
    this.localEvents.push(event);
    if (this.localEvents.length > MAX_EVENT_CACHE) {
      this.localEvents.shift();
    }
    this.onEvent?.({ type: 'event_received', event });

    // 送信元以外の全接続ピアへ転送 (hop 制限)
    if (hop + 1 <= MAX_HOPS) {
      const fromPubkey = conn.remotePubkey;
      for (const [pk, c] of this.connections) {
        if (pk === fromPubkey) continue;
        if (c.state !== 'connected') continue;
        try {
          await this.sendEventFrame(c, event, hop + 1);
        } catch {
          /* 無視 */
        }
      }
    }
  }

  // --- PeerList / WoT 紹介 ---

  private async sendPeerList(conn: F2FPeerConnection): Promise<void> {
    const peers = this.peerCache.peers
      .filter((p) => p.pubkey !== this.pubkeyHex)
      .slice(0, 50)
      .map((p): PeerList['peers'][number] => ({
        pubkey: CryptoUtils.hexToBytes(p.pubkey),
        addresses: p.addresses,
        lastSeen: p.lastSeen,
        trustScore: p.trustScore,
      }));
    const peerList: PeerList = {
      version: this.peerCache.version,
      peerCount: peers.length,
      peers,
      signature: new Uint8Array(64),
    };
    const signedData = Protocol.encodePeerListSignedData(peerList);
    const sigHex = await CryptoUtils.signMessage(this.privKeyHex, signedData);
    peerList.signature = CryptoUtils.hexToBytes(sigHex);

    const encoded = Protocol.encodePeerList(peerList);
    const frame = new Uint8Array(1 + encoded.length);
    frame[0] = MsgTypePeerListPush;
    frame.set(encoded, 1);
    await conn.sendData(frame, ['type:peerlist']);
  }

  private async handleIncomingPeerList(data: Uint8Array, fromPubkey: string) {
    try {
      const peerList = Protocol.decodePeerList(data);
      const newPeers: F2FPeerInfo[] = peerList.peers.map((p) => ({
        pubkey: CryptoUtils.bytesToHex(p.pubkey),
        addresses: p.addresses,
        lastSeen: Number(p.lastSeen),
        trustScore: p.trustScore,
      }));
      this.updatePeerCache(newPeers);
      // キャッシュから WoT グラフへ登録 (新ピアを WoT で評価)
      for (const p of newPeers) {
        if (p.pubkey === this.pubkeyHex) continue;
        this.wot.applyIntroduction(fromPubkey, p.pubkey, p.trustScore);
        // ルーティングテーブルにも追加
        const nodeId = Protocol.nodeId(CryptoUtils.hexToBytes(p.pubkey));
        this.dht.table.addNode(
          {
            nodeId,
            pubkey: CryptoUtils.hexToBytes(p.pubkey),
            addresses: p.addresses,
            lastSeen: p.lastSeen,
            trustScore: this.wot.getScore(p.pubkey),
          },
          this.wot.minTrust,
        );
      }
      this.saveTable();
      this.onEvent?.({ type: 'peer_list_received', from: fromPubkey, peers: newPeers });
      this.onEvent?.({ type: 'seed_nodes', nodes: newPeers });

      // WoT ゲートを通過した新ピアへダイアル
      for (const p of newPeers) {
        if (p.pubkey === this.pubkeyHex) continue;
        if (this.connections.has(p.pubkey)) continue;
        if (this.connections.size >= MAX_CONNECTIONS) break;
        if (!this.wot.isTrusted(p.pubkey)) continue;
        this.connectToPeer(p.pubkey, p.addresses).catch(() => {});
      }
    } catch {
      /* 不正な PeerList は無視 */
    }
  }

  private async sendWoTIntro(conn: F2FPeerConnection, newPeer: F2FPeerInfo): Promise<void> {
    const intro: WoTIntro = {
      introducer: this.pubkeyBytes,
      newPeer: {
        pubkey: CryptoUtils.hexToBytes(newPeer.pubkey),
        addresses: newPeer.addresses,
        lastSeen: newPeer.lastSeen,
        trustScore: newPeer.trustScore,
      },
      signature: new Uint8Array(64),
    };
    const signedData = Protocol.encodeWoTIntroSignedData(intro);
    const sigHex = await CryptoUtils.signMessage(this.privKeyHex, signedData);
    intro.signature = CryptoUtils.hexToBytes(sigHex);

    const encoded = Protocol.encodeWoTIntro(intro);
    const frame = new Uint8Array(1 + encoded.length);
    frame[0] = MsgTypeWoTIntroPush;
    frame.set(encoded, 1);
    await conn.sendData(frame, ['type:wotintro']);
  }

  /** 新しく接続したピアを他の全接続ピアへ WoT 紹介する。 */
  private broadcastWoTIntro(pubkeyHex: string, addresses: string[]) {
    const newPeer: F2FPeerInfo = {
      pubkey: pubkeyHex,
      addresses,
      lastSeen: Math.floor(Date.now() / 1000),
      trustScore: this.wot.getScore(pubkeyHex),
    };
    for (const [pk, c] of this.connections) {
      if (pk === pubkeyHex) continue;
      if (c.state !== 'connected') continue;
      this.sendWoTIntro(c, newPeer).catch(() => {});
    }
  }

  private async handleIncomingWoTIntro(fromPubkey: string, data: Uint8Array) {
    try {
      const intro = Protocol.decodeWoTIntro(data);
      const newPeer: F2FPeerInfo = {
        pubkey: CryptoUtils.bytesToHex(intro.newPeer.pubkey),
        addresses: intro.newPeer.addresses,
        lastSeen: Number(intro.newPeer.lastSeen),
        trustScore: intro.newPeer.trustScore,
      };
      this.wot.applyIntroduction(fromPubkey, newPeer.pubkey, newPeer.trustScore);
      this.updatePeerCache([newPeer]);
      this.onEvent?.({ type: 'wot_intro_received', from: fromPubkey, newPeer });
    } catch {
      /* 不正な WoT 紹介は無視 */
    }
  }

  // --- 直接メッセージ ---

  async sendDirect(pubkeyHex: string, content: Uint8Array, tags: string[] = []): Promise<boolean> {
    const conn = this.connections.get(pubkeyHex);
    if (!conn || conn.state !== 'connected') return false;
    return conn.sendData(content, ['type:datamsg', ...tags]);
  }

  // --- DHT 操作 ---

  /** 接続済みピアへ DHT RPC を送り、応答を待つ。 */
  private async rpcToPeer(conn: F2FPeerConnection, op: number, key: Uint8Array, value: Uint8Array): Promise<DhtReply> {
    const signed = await this.dht.createRpc(op, key, value);
    const msgIdHex = CryptoUtils.bytesToHex(signed.msgId);
    const body = Protocol.encodeDht(signed);
    const frame = new Uint8Array(1 + body.length);
    frame[0] = 0x0b; // MsgTypeDht
    frame.set(body, 1);
    const sent = await conn.sendData(frame, ['type:dht']);
    if (!sent) return { value: new Uint8Array(), nodes: [] };

    return new Promise<DhtReply>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(msgIdHex);
        resolve({ value: new Uint8Array(), nodes: [] });
      }, DHT_RPC_TIMEOUT_MS);
      this.pending.set(msgIdHex, {
        op,
        resolve: (r) => {
          clearTimeout(timer);
          this.pending.delete(msgIdHex);
          resolve(r);
        },
      });
    });
  }

  private ingestDhtNodes(nodes: DhtNodeInfo[]) {
    if (nodes.length === 0) return;
    for (const n of nodes) {
      const nodeId = n.nodeId ?? Protocol.nodeId(n.pubkey);
      this.dht.table.addNode(
        {
          nodeId,
          pubkey: n.pubkey,
          addresses: n.addresses,
          lastSeen: n.lastSeen,
          trustScore: n.trustScore,
        },
        this.wot.minTrust,
      );
    }
    this.saveTable();
  }

  /** 相手ノードに自分の値を STORE してもらう。 */
  private async sendStoreTo(conn: F2FPeerConnection, key: Uint8Array, value: string): Promise<boolean> {
    const encoder = new TextEncoder();
    const r = await this.rpcToPeer(conn, DhtOpStore, key, encoder.encode(value));
    return r.nodes.length > 0 || r.value.length > 0;
  }

  /** FIND_VALUE: キーに対応する値 (アドレス) を取得する。 */
  async findValue(key: Uint8Array): Promise<string | null> {
    const connected = Array.from(this.connections.values()).filter((c) => c.state === 'connected');
    for (const conn of connected) {
      const r = await this.rpcToPeer(conn, DhtOpFindValue, key, new Uint8Array());
      if (r.value.length > 0) {
        return new TextDecoder().decode(r.value);
      }
      this.ingestDhtNodes(r.nodes);
    }
    return null;
  }

  private async findValueForPeer(pubkeyHex: string) {
    const targetNodeId = Protocol.nodeId(CryptoUtils.hexToBytes(pubkeyHex));
    const value = await this.findValue(targetNodeId);
    if (value) {
      try {
        const obj = JSON.parse(value);
        if (Array.isArray(obj?.addresses) && obj.addresses.length > 0) {
          this.updatePeerCache([
            {
              pubkey: pubkeyHex,
              addresses: obj.addresses,
              lastSeen: Math.floor(Date.now() / 1000),
              trustScore: this.wot.getScore(pubkeyHex),
            },
          ]);
        }
      } catch {
        /* 無視 */
      }
    }
  }

  /** FIND_NODE: 近傍ノードを取得する (ルーティングテーブルの補完)。 */
  async findNode(target: Uint8Array): Promise<void> {
    const connected = Array.from(this.connections.values()).filter((c) => c.state === 'connected');
    for (const conn of connected) {
      const r = await this.rpcToPeer(conn, DhtOpFindNode, target, new Uint8Array());
      this.ingestDhtNodes(r.nodes);
    }
  }

  private handleDhtFrame(conn: F2FPeerConnection, content: Uint8Array) {
    if (content.length < 1) return;
    const msgType = content[0];
    if (!isDhtFrame(msgType)) return;
    try {
      const msg = Protocol.decodeDht(content.subarray(1));
      const msgIdHex = CryptoUtils.bytesToHex(msg.msgId);

      // 自分の RPC への応答か
      const pending = this.pending.get(msgIdHex);
      if (pending) {
        this.ingestDhtNodes(msg.nodes);
        pending.resolve({ value: msg.value, nodes: msg.nodes });
        return;
      }

      // 応答であることが確定しているもの (PONG / 値付き FIND_VALUE) は
      // 遅延応答として無視 (要求として再処理しない)。
      if (msg.op === DhtOpPong || (msg.op === DhtOpFindValue && msg.value.length > 0)) {
        return;
      }

      this.dht
        .handleIncoming(msg, (resp: DhtMessage, respMsgType: number) => {
          const body = Protocol.encodeDht(resp);
          const frame = new Uint8Array(1 + body.length);
          frame[0] = respMsgType;
          frame.set(body, 1);
          return conn.sendData(frame, ['type:dht']).then(() => {});
        })
        .then(() => this.ingestDhtNodes(msg.nodes))
        .catch(() => {});
    } catch {
      /* DHT デコード失敗は無視 */
    }
  }

  // --- シグナリング受信 (type:signal) ---

  private handleIncomingSignal(content: Uint8Array, fromConn: F2FPeerConnection) {
    try {
      const sig = Protocol.decodeSignal(content.subarray(1));
      const targetHex = CryptoUtils.bytesToHex(sig.target);
      const senderHex = CryptoUtils.bytesToHex(sig.sender);

      // 署名検証
      const signedData = Protocol.encodeSignalSignedData(sig);
      CryptoUtils.verifySignature(sig.sender, signedData, sig.signature).then((ok) => {
        if (!ok) return;
        if (targetHex === this.pubkeyHex) {
          // 自分宛: 該当接続へ届ける
          const conn = this.connections.get(senderHex);
          if (!conn) {
            if (sig.signalType === SignalOffer) {
              this.acceptOffer(senderHex, sig.content).catch(() => {});
            }
            return;
          }
          if (sig.signalType === SignalOffer) {
            conn.handleOffer(sig.content).catch(() => {});
          } else if (sig.signalType === SignalAnswer) {
            conn.handleAnswer(sig.content).catch(() => {});
          } else if (sig.signalType === SignalCandidate) {
            try {
              conn.handleCandidate(JSON.parse(sig.content)).catch(() => {});
            } catch {
              /* 不正な candidate は無視 */
            }
          }
        } else {
          // 中継: 宛先への接続があれば転送
          const targetConn = this.connections.get(targetHex);
          if (targetConn && targetConn.state === 'connected') {
            this.sendSignalFrame(targetConn, { signalType: sig.signalType, content: sig.content }).catch(() => {});
          }
          // 宛先が見つからなければ転送しない (hop 制限)
          void fromConn;
        }
      });
    } catch {
      /* 不正なシグナルは無視 */
    }
  }

  // --- フレーム振り分け ---

  private setupConnection(conn: F2FPeerConnection, addresses: string[]) {
    conn.onDataMessage = (msg: FodprData) => {
      this.handleFodprData(conn, msg);
    };
    void addresses;
  }

  private handleFodprData(conn: F2FPeerConnection, msg: FodprData) {
    const fromPubkey = CryptoUtils.bytesToHex(msg.sender);
    const tags = msg.tags ?? [];
    const typeTag = tags.find((t) => t.startsWith('type:'))?.slice(5);
    const hopTag = tags.find((t) => t.startsWith('hop:'));
    const hop = hopTag ? parseInt(hopTag.slice(4), 10) : 0;

    switch (typeTag) {
      case 'dht':
        this.handleDhtFrame(conn, msg.content);
        break;
      case 'event':
        if (msg.content[0] === MsgTypeEvent) {
          try {
            const event = Protocol.decodeEvent(msg.content.subarray(1));
            this.handleIncomingEvent(conn, event, hop).catch(() => {});
          } catch {
            /* 無視 */
          }
        }
        break;
      case 'peerlist':
        if (msg.content[0] === MsgTypePeerListPush) {
          this.handleIncomingPeerList(msg.content.subarray(1), fromPubkey).catch(() => {});
        }
        break;
      case 'wotintro':
        if (msg.content[0] === MsgTypeWoTIntroPush) {
          this.handleIncomingWoTIntro(fromPubkey, msg.content.subarray(1)).catch(() => {});
        }
        break;
      case 'signal':
        if (msg.content[0] === MsgTypeSignal) {
          this.handleIncomingSignal(msg.content, conn);
        }
        break;
      default:
        // 直接メッセージ
        this.onEvent?.({ type: 'data_received', from: fromPubkey, content: msg.content, tags });
        break;
    }
  }

  // --- ローカルイベント取得 (フィード復元用) ---

  getLocalEvents(): FodprEvent[] {
    return [...this.localEvents];
  }

  // --- 終了処理 ---

  close() {
    for (const conn of this.connections.values()) {
      conn.close();
    }
    this.connections.clear();
  }
}
