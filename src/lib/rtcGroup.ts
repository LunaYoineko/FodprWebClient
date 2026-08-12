/**
 * rtcGroup.ts
 * -----------
 * ホスト昇格方式 (RtcGroup) クライアントネットワーキングレイヤー。
 *
 * リレーの WebRTC シグナリンググループ (TransTypeWebRTC + to:<fpub> タグ) を利用する。
 * - グループID = ホストの fpub。最初に P2P を始めた人がホスト。
 * - ゲストは REQ to:<ホストfpub> (TransTypeWebRTC) でグループに参加する。
 * - ホスト切断時、リレーが最古の joinedAt のゲストを昇格し、全メンバーへ
 *   "HOST_CHANGE: <new_fpub>" テキストを送信する。クライアントは受信後
 *   新ホストの fpub で REQ を再送信する。
 * - WebRTC シグナリングは MsgTypeSignal (FodprSignal) でリレーが中継する。
 * - グループ状態は TransTypeGroup (group:<groupId> タグ) でリレーに永続化し、
 *   端末を変えても復元できるようにする。
 */

import {
  Protocol,
  TransTypeGroup,
  TransTypeWebRTC,
  SignalOffer,
  SignalAnswer,
  SignalCandidate,
  type FodprSignal,
  type FodprEvent,
  type F2FGroup,
  type GroupMember,
  type FodprAuth,
} from '@fodpr/protocol';
import { CryptoUtils } from '@fodpr/crypto';
import type { RelayClient, RelayMessage } from './relay';

const RTC_GROUPS_KEY = 'fodpr_rtc_groups';

export interface RtcGroupInfo {
  groupId: string; // ホスト fpub (小文字) = グループID
  hostFpub: string;
  members: string[]; // fpub (小文字) リスト
  isHost: boolean;
  joinedAt: number;
  version: number;
  createdAt: number;
}

export type RtcGroupEvent =
  | { type: 'group_updated'; group: RtcGroupInfo }
  | { type: 'group_joined'; group: RtcGroupInfo }
  | { type: 'group_left'; groupId: string }
  | { type: 'host_changed'; groupId: string; oldHost: string; newHost: string }
  | { type: 'peer_connected'; pubkey: string }
  | { type: 'peer_disconnected'; pubkey: string }
  | { type: 'data_received'; from: string; content: Uint8Array; tags: string[] }
  | { type: 'error'; message: string };

function loadGroups(): RtcGroupInfo[] {
  try {
    const raw = localStorage.getItem(RTC_GROUPS_KEY);
    if (raw) return JSON.parse(raw) as RtcGroupInfo[];
  } catch {
    /* ignore */
  }
  return [];
}

function saveGroups(groups: RtcGroupInfo[]) {
  try {
    localStorage.setItem(RTC_GROUPS_KEY, JSON.stringify(groups));
  } catch {
    /* ignore */
  }
}

export interface RtcGroupManagerOptions {
  privKeyHex: string;
  relays: RelayClient[];
}

export class RtcGroupManager {
  private privKeyHex: string;
  private pubkeyHex: string;
  private pubkeyFpub: string;
  private relays: RelayClient[];
  private groups = new Map<string, RtcGroupInfo>();
  private peers = new Map<string, RtcPeerConnection>();

  onEvent: ((ev: RtcGroupEvent) => void) | null = null;

  constructor(options: RtcGroupManagerOptions) {
    this.privKeyHex = options.privKeyHex;
    this.relays = options.relays;
    const privBytes = CryptoUtils.hexToBytes(options.privKeyHex);
    const pubBytes = CryptoUtils.getRawCompressedPublicKey(privBytes);
    this.pubkeyHex = CryptoUtils.bytesToHex(pubBytes);
    this.pubkeyFpub = CryptoUtils.fpubEncode(pubBytes).toLowerCase();
    this.loadGroups();
    this.initialize();
  }

  // 起動時: 保存済みグループの状態をリレーから購読し、ホストがいれば自動接続
  private initialize() {
    this.subscribeKnownGroups();
    // 既存グループがあればホストへ接続を試みる
    for (const group of this.groups.values()) {
      if (!group.isHost && group.hostFpub) {
        this.connectToPeer(group.hostFpub);
      }
    }
  }

  get pubkey(): string {
    return this.pubkeyHex;
  }

  getGroups(): RtcGroupInfo[] {
    return Array.from(this.groups.values());
  }

  getGroup(groupId: string): RtcGroupInfo | undefined {
    return this.groups.get(groupId.toLowerCase());
  }

  get peerCount(): number {
    return this.peers.size;
  }

  private loadGroups() {
    for (const g of loadGroups()) {
      this.groups.set(g.groupId, g);
    }
  }

  private persist() {
    saveGroups(Array.from(this.groups.values()));
  }

  // ---------------------------------------------------------------------------
  // グループ管理
  // ---------------------------------------------------------------------------

  // 自分の fpub をグループIDとしてグループを作成し、ホストとして参加する。
  createGroup(): RtcGroupInfo {
    const now = Math.floor(Date.now() / 1000);
    const group: RtcGroupInfo = {
      groupId: this.pubkeyFpub,
      hostFpub: this.pubkeyFpub,
      members: [this.pubkeyFpub],
      isHost: true,
      joinedAt: now,
      version: 1,
      createdAt: now,
    };
    this.groups.set(group.groupId, group);
    this.persist();
    this.subscribeGroup(group.groupId);
    this.onEvent?.({ type: 'group_joined', group });
    this.onEvent?.({ type: 'group_updated', group });
    this.publishGroup(group);
    return group;
  }

  // 指定のホスト fpub のグループに参加する。
  joinGroup(hostFpub: string): RtcGroupInfo {
    const gid = hostFpub.toLowerCase().trim();
    const now = Math.floor(Date.now() / 1000);
    let group = this.groups.get(gid);
    if (!group) {
      group = {
        groupId: gid,
        hostFpub: gid,
        members: [gid, this.pubkeyFpub],
        isHost: false,
        joinedAt: now,
        version: 1,
        createdAt: now,
      };
      this.groups.set(gid, group);
    } else {
      if (!group.members.includes(this.pubkeyFpub)) group.members.push(this.pubkeyFpub);
    }
    this.persist();
    this.subscribeGroup(gid);
    this.onEvent?.({ type: 'group_joined', group });
    this.onEvent?.({ type: 'group_updated', group });
    this.publishGroup(group);
    return group;
  }

  leaveGroup(groupId: string) {
    const gid = groupId.toLowerCase();
    this.groups.delete(gid);
    this.persist();
    this.onEvent?.({ type: 'group_left', groupId: gid });
  }

  // TransTypeWebRTC の購読 (REQ to:<hostFpub>) を開始する。
  // リレーはこの REQ をきっかけに RtcGroup へメンバー追加する。
  private subscribeGroup(hostFpub: string) {
    const req = {
      subId: `rtc_${hostFpub.slice(0, 10)}_${Date.now()}`,
      transType: TransTypeWebRTC,
      tagKey: 'to',
      tagVal: hostFpub,
    };
    for (const relay of this.relays) {
      try {
        relay.sendReq(req);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }

  // ---------------------------------------------------------------------------
  // TransTypeGroup によるグループ状態の永続化・同期
  // ---------------------------------------------------------------------------

  // グループ状態を TransTypeGroup イベント (group:<groupId> タグ) として投稿する。
  async publishGroup(group: RtcGroupInfo): Promise<boolean> {
    const pubBytes = CryptoUtils.hexToBytes(this.pubkeyHex);
    const wire: F2FGroup = {
      groupId: group.groupId,
      hostPubkey: CryptoUtils.fpubDecode(group.hostFpub),
      members: group.members.map(
        (fpub): GroupMember => ({
          pubkey: CryptoUtils.fpubDecode(fpub),
          addresses: [],
          joinedAt: group.joinedAt,
          isHost: fpub === group.hostFpub,
          isConnected: true,
        }),
      ),
      version: group.version,
      createdAt: group.createdAt,
      signature: new Uint8Array(64),
    };
    const signedData = Protocol.encodeGroupSignedData(wire);
    const sigHex = await CryptoUtils.signMessage(this.privKeyHex, signedData);
    wire.signature = CryptoUtils.hexToBytes(sigHex);
    const content = Protocol.encodeGroup(wire);

    const event: FodprEvent = {
      transType: TransTypeGroup,
      createdAt: Math.floor(Date.now() / 1000),
      pubkey: pubBytes,
      tags: [`group:${group.groupId}`],
      content,
      signature: new Uint8Array(64),
    };
    const contentSigHex = await CryptoUtils.signMessage(this.privKeyHex, content);
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

  private handleGroupEvent(event: FodprEvent) {
    if (event.transType !== TransTypeGroup) return;
    try {
      const wire = Protocol.decodeGroup(event.content);
      const gid = wire.groupId.toLowerCase();
      const known = this.groups.has(gid) || gid === this.pubkeyFpub;
      if (!known) return;

      const existing = this.groups.get(gid);
      if (existing && Number(wire.version) <= existing.version) return;

      const hostFpub = CryptoUtils.fpubEncode(wire.hostPubkey).toLowerCase();
      const synced: RtcGroupInfo = {
        groupId: gid,
        hostFpub,
        members: wire.members.map((m) => CryptoUtils.fpubEncode(m.pubkey).toLowerCase()),
        isHost: hostFpub === this.pubkeyFpub,
        joinedAt: existing?.joinedAt ?? Math.floor(Date.now() / 1000),
        version: Number(wire.version),
        createdAt: Number(wire.createdAt),
      };
      this.groups.set(gid, synced);
      this.persist();
      this.onEvent?.({ type: 'group_updated', group: synced });
    } catch {
      /* グループデコード失敗は無視 */
    }
  }

  // 参加中のグループの状態を TransTypeGroup で購読する。
  subscribeKnownGroups() {
    const gids = new Set<string>([this.pubkeyFpub]);
    for (const g of this.groups.values()) {
      gids.add(g.groupId);
    }
    for (const gid of gids) {
      const req = {
        subId: `rtc_grp_${gid.slice(0, 10)}_${Date.now()}`,
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

  // ---------------------------------------------------------------------------
  // WebRTC P2P (リレー中継シグナリング)
  // ---------------------------------------------------------------------------

  // グループのピアへ P2P 接続を確立する (最古の参加順で接続)。
  dialPeers() {
    for (const group of this.groups.values()) {
      const targets = group.members.filter((f) => f !== this.pubkeyFpub);
      for (const fpub of targets) {
        this.connectToPeer(fpub);
      }
    }
  }

  connectToPeer(peerFpub: string): RtcPeerConnection {
    const gid = peerFpub.toLowerCase();
    if (this.peers.has(gid)) return this.peers.get(gid)!;
    const conn = new RtcPeerConnection({
      localPrivHex: this.privKeyHex,
      remoteFpub: gid,
      relay: this.relays[0],
    });
    conn.onDisconnect = () => {
      this.peers.delete(gid);
      this.onEvent?.({ type: 'peer_disconnected', pubkey: gid });
    };
    conn.onDataMessage = (content) => {
      this.onEvent?.({ type: 'data_received', from: gid, content, tags: [] });
    };
    this.peers.set(gid, conn);
    conn.initiate().catch(() => {});
    return conn;
  }

  // ---------------------------------------------------------------------------
  // リレーメッセージ処理
  // ---------------------------------------------------------------------------

  handleRelayMessage(msg: RelayMessage | { kind: string; [key: string]: any }) {
    if (msg.kind === 'challenge' && msg.nonce) {
      this.respondAuth(msg.nonce as Uint8Array).catch(() => {});
      return;
    }
    if (msg.kind === 'text' && typeof msg.text === 'string') {
      this.handleText(msg.text);
      return;
    }
    if (msg.kind === 'event' && msg.event) {
      this.handleGroupEvent(msg.event as FodprEvent);
      return;
    }
    if (msg.kind === 'signal' && msg.signal) {
      this.handleSignal(msg.signal as FodprSignal);
    }
  }

  // HOST_CHANGE: <new_fpub> を受けたら新ホストのグループに再参加する。
  private handleText(text: string) {
    const m = /^HOST_CHANGE:\s*(\S+)/i.exec(text.trim());
    if (m) {
      const newHost = m[1].toLowerCase();
      // グループID (旧ホストfpub) を新ホストへ差し替え、REQ を再送信する。
      for (const group of this.groups.values()) {
        if (group.hostFpub === newHost) continue;
        const oldHost = group.hostFpub;
        if (!group.isHost && group.members.includes(oldHost)) {
          const updated: RtcGroupInfo = {
            ...group,
            hostFpub: newHost,
            groupId: newHost,
            version: group.version + 1,
            members: group.members.includes(newHost)
              ? group.members
              : [...group.members, newHost],
          };
          this.groups.delete(group.groupId);
          this.groups.set(newHost, updated);
          this.persist();
          this.subscribeGroup(newHost);
          this.onEvent?.({
            type: 'host_changed',
            groupId: oldHost,
            oldHost,
            newHost,
          });
          this.onEvent?.({ type: 'group_updated', group: updated });
        }
      }
      return;
    }
    // OK: Authenticated 等は無視
  }

  // 認証チャレンジへ AUTH 応答する (to: タグ購読に必須)。
  private async respondAuth(nonce: Uint8Array) {
    if (!this.privKeyHex) return;
    try {
      const pubBytes = CryptoUtils.hexToBytes(this.pubkeyHex);
      const auth: FodprAuth = {
        nonce,
        pubkey: pubBytes,
        signature: new Uint8Array(64),
      };
      const signedData = Protocol.encodeAuthSignedData(auth);
      const sigHex = await CryptoUtils.signMessage(this.privKeyHex, signedData);
      auth.signature = CryptoUtils.hexToBytes(sigHex);
      for (const relay of this.relays) {
        try {
          relay.sendAuth(auth);
        } catch {
          /* 未接続のリレーは無視 */
        }
      }
    } catch {
      /* 署名失敗は無視 */
    }
  }

  private handleSignal(signal: FodprSignal) {
    const senderFpub = CryptoUtils.fpubEncode(signal.sender).toLowerCase();
    const json = this.parseSignalContent(signal.content);
    if (!json) return;

    let conn = this.peers.get(senderFpub);
    if (!conn) {
      conn = this.connectToPeer(senderFpub);
    }
    if (!conn) return;

    if (signal.signalType === SignalOffer) {
      if (json.sdp) conn.handleOffer(json.sdp).catch(() => {});
    } else if (signal.signalType === SignalAnswer) {
      if (json.sdp) conn.handleAnswer(json.sdp).catch(() => {});
    } else if (signal.signalType === SignalCandidate) {
      if (json.candidate) {
        conn.handleCandidate({
          candidate: json.candidate,
          sdpMid: json.sdpMid,
          sdpMLineIndex: json.sdpMLineIndex,
        }).catch(() => {});
      }
    }
  }

  private parseSignalContent(content: string): { sdp?: string; candidate?: string; sdpMid?: string; sdpMLineIndex?: number } | null {
    try {
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  close() {
    for (const conn of this.peers.values()) {
      conn.close();
    }
    this.peers.clear();
  }
}

// ---------------------------------------------------------------------------
// WebRTC P2P 接続 (FodprSignal によるリレー中継シグナリング)
// ---------------------------------------------------------------------------

class RtcPeerConnection {
  readonly remoteFpub: string;
  readonly localPubkeyHex: string;
  private localPrivHex: string;
  private pc: RTCPeerConnection | null = null;
  private dc: RTCDataChannel | null = null;
  private relay: RelayClient | null = null;

  onDisconnect: (() => void) | null = null;
  onDataMessage: ((content: Uint8Array, tags: string[]) => void) | null = null;

  constructor(params: {
    localPrivHex: string;
    remoteFpub: string;
    relay?: RelayClient;
  }) {
    this.localPrivHex = params.localPrivHex;
    this.remoteFpub = params.remoteFpub;
    this.relay = params.relay ?? null;
    const privBytes = CryptoUtils.hexToBytes(params.localPrivHex);
    this.localPubkeyHex = CryptoUtils.bytesToHex(
      CryptoUtils.getRawCompressedPublicKey(privBytes),
    );
  }

  private config(): RTCConfiguration {
    return { iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] };
  }

  async initiate(): Promise<boolean> {
    if (this.pc) return false;
    this.pc = new RTCPeerConnection(this.config());
    this.dc = this.pc.createDataChannel('fodpr-rtc');
    this.setupDataChannel(this.dc);
    this.setupEvents();
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    await this.sendSignal(SignalOffer, JSON.stringify({ sdp: offer.sdp ?? '' }));
    return true;
  }

  async handleOffer(sdp: string): Promise<boolean> {
    if (!this.pc) {
      this.pc = new RTCPeerConnection(this.config());
      this.setupEvents();
    }
    try {
      await this.pc.setRemoteDescription({ type: 'offer', sdp });
      this.pc.ondatachannel = (ev) => {
        this.dc = ev.channel;
        this.setupDataChannel(this.dc);
      };
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      await this.sendSignal(SignalAnswer, JSON.stringify({ sdp: answer.sdp ?? '' }));
      return true;
    } catch {
      this.close();
      return false;
    }
  }

  async handleAnswer(sdp: string): Promise<boolean> {
    try {
      await this.pc?.setRemoteDescription({ type: 'answer', sdp });
      return true;
    } catch {
      this.close();
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

  send(content: Uint8Array, _tags: string[] = []) {
    if (this.dc && this.dc.readyState === 'open') {
      try {
        const buf = new Uint8Array(content.length);
        buf.set(content);
        this.dc.send(buf.buffer);
      } catch {
        /* ignore */
      }
    }
  }

  private setupDataChannel(dc: RTCDataChannel) {
    dc.onopen = () => {};
    dc.onmessage = (ev) => {
      const data = ev.data as ArrayBuffer;
      this.onDataMessage?.(new Uint8Array(data), []);
    };
    dc.onclose = () => this.onDisconnect?.();
  }

  private setupEvents() {
    this.pc?.addEventListener('icecandidate', (ev) => {
      if (ev.candidate) {
        this.sendSignal(
          SignalCandidate,
          JSON.stringify({
            candidate: ev.candidate.candidate,
            sdpMid: ev.candidate.sdpMid,
            sdpMLineIndex: ev.candidate.sdpMLineIndex,
          }),
        ).catch(() => {});
      }
    });
    this.pc?.addEventListener('connectionstatechange', () => {
      if (
        this.pc?.connectionState === 'failed' ||
        this.pc?.connectionState === 'closed'
      ) {
        this.onDisconnect?.();
      }
    });
  }

  private async sendSignal(signalType: number, content: string) {
    if (!this.relay) return;
    const pubBytes = CryptoUtils.hexToBytes(this.localPubkeyHex);
    const remotePubBytes = CryptoUtils.fpubDecode(this.remoteFpub);
    const signal: FodprSignal = {
      signalType,
      sender: pubBytes,
      target: remotePubBytes,
      content,
      signature: new Uint8Array(64),
    };
    const signedData = Protocol.encodeSignalSignedData(signal);
    const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
    signal.signature = CryptoUtils.hexToBytes(sigHex);
    try {
      this.relay.sendSignal(signal);
    } catch {
      /* 未接続のリレーは無視 */
    }
  }

  close() {
    this.dc?.close();
    this.pc?.close();
    this.pc = null;
    this.dc = null;
  }
}
