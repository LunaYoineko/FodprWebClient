/**
 * dht.ts
 * ------
 * Kademlia DHT (WebRTC データチャネル上)。
 *
 * ピアの接続先 (IPv6 一時アドレス) を公開鍵から解決するための分散ハッシュテーブル。
 * ルーティングテーブルは 256-bit ノード ID (nodeId = SHA-256(圧縮公開鍵)) の
 * k-buckets で管理する。
 *
 * すべての RPC は確立済み WebRTC データチャネル (FodprData) 上で行う。
 * DhtMessage は encodeDht でシリアライズし、FodprData.content の先頭に
 * MsgTypeDht (0x0B) / MsgTypeDhtNodes (0x8B) / MsgTypeDhtValue (0x8C) の
 * いずれかを付与して送信する (Nim の dht.nim と同じ)。
 *
 * 永続化: localStorage.fodpr_dht_table
 */

import {
  Protocol,
  DhtOpPing,
  DhtOpPong,
  DhtOpFindNode,
  DhtOpFindValue,
  DhtOpStore,
  type DhtMessage,
  type DhtNodeInfo,
} from '@fodpr/protocol';
import { CryptoUtils } from '@fodpr/crypto';
import { sha256 } from '@noble/hashes/sha2.js';

export type { DhtNodeInfo, DhtMessage } from '@fodpr/protocol';

export const DHT_STORAGE_KEY = 'fodpr_dht_table';
export const K_BUCKET_SIZE = 20;
export const DHT_RPC_TIMEOUT_MS = 5000;
export const DHT_VALUE_MAX = 4096;

export const DHT_MSG_TYPES = new Set<number>([0x0b, 0x8b, 0x8c]);

export function isDhtFrame(firstByte: number): boolean {
  return DHT_MSG_TYPES.has(firstByte);
}

/** nodeId = SHA-256(圧縮公開鍵) */
export function nodeIdFromPubkey(pub: Uint8Array): Uint8Array {
  return sha256(pub);
}

export function bytesToHex(b: Uint8Array): string {
  return CryptoUtils.bytesToHex(b);
}

export interface KBucket {
  nodes: DhtNodeInfo[];
  lastUpdated: number;
}

export class RoutingTable {
  readonly localNodeId: Uint8Array;
  buckets: KBucket[] = [];
  version: number = 1;

  constructor(localNodeId: Uint8Array) {
    this.localNodeId = localNodeId.slice(0, 32);
    for (let i = 0; i < 256; i++) {
      this.buckets.push({ nodes: [], lastUpdated: 0 });
    }
  }

  /** 2つのノードIDの XOR 距離の先頭ビット位置 (0..255)。-1 は完全一致。 */
  bucketIndexFor(nodeId: Uint8Array): number {
    for (let i = 0; i < 32; i++) {
      const diff = this.localNodeId[i] ^ nodeId[i];
      if (diff !== 0) {
        let msb = 0;
        let v = diff;
        while (v > 0) {
          v = v >> 1;
          msb += 1;
        }
        return (31 - i) * 8 + (8 - msb);
      }
    }
    return -1;
  }

  /** target から見て a のほうが b より近いか */
  closerTo(target: Uint8Array, a: Uint8Array, b: Uint8Array): boolean {
    for (let i = 0; i < 32; i++) {
      const da = a[i] ^ target[i];
      const db = b[i] ^ target[i];
      if (da < db) return true;
      if (da > db) return false;
    }
    return false;
  }

  /** ノードを追加する。WoT ゲート: minTrust 未満の新規ノードは拒否 (既知ノードは更新を許可)。 */
  addNode(n: DhtNodeInfo, minTrust: number): boolean {
    if (n.nodeId.length !== 32) return false;
    if (bytesToHex(n.nodeId) === bytesToHex(this.localNodeId)) return false;
    const idx = this.bucketIndexFor(n.nodeId);
    if (idx < 0) return false;

    const now = Math.floor(Date.now() / 1000);
    const bucket = this.buckets[idx];

    const found = bucket.nodes.findIndex((x) => bytesToHex(x.nodeId) === bytesToHex(n.nodeId));
    if (found >= 0) {
      const existing = bucket.nodes[found];
      existing.lastSeen = now;
      existing.addresses = n.addresses.length > 0 ? n.addresses : existing.addresses;
      bucket.nodes.splice(found, 1);
      bucket.nodes.push(existing);
      this.version++;
      return true;
    }

    // 新規ノード: WoT ゲート
    if (n.trustScore < minTrust) return false;

    if (bucket.nodes.length >= K_BUCKET_SIZE) {
      bucket.nodes.shift();
    }
    bucket.nodes.push({ ...n, lastSeen: now });
    bucket.lastUpdated = now;
    this.version++;
    return true;
  }

  /** target から見て近い順に最大 count 個のノードを返す */
  findClosest(target: Uint8Array, count: number = K_BUCKET_SIZE): DhtNodeInfo[] {
    const center = this.bucketIndexFor(target);
    if (center < 0) return [];

    const all: DhtNodeInfo[] = [];
    for (let dist = 0; dist < 256 && all.length < count; dist++) {
      const hi = center + dist;
      if (hi < 256) {
        for (const n of this.buckets[hi].nodes) all.push(n);
      }
      const lo = center - dist;
      if (lo >= 0) {
        for (const n of this.buckets[lo].nodes) all.push(n);
      }
    }

    all.sort((a, b) => (this.closerTo(target, a.nodeId, b.nodeId) ? -1 : this.closerTo(target, b.nodeId, a.nodeId) ? 1 : 0));
    return all.slice(0, count);
  }

  allNodes(): DhtNodeInfo[] {
    const out: DhtNodeInfo[] = [];
    for (const b of this.buckets) {
      for (const n of b.nodes) out.push(n);
    }
    return out;
  }

  count(): number {
    return this.allNodes().length;
  }

  save() {
    try {
      const nodes = this.allNodes().map((n) => ({
        nodeId: CryptoUtils.bytesToHex(n.nodeId),
        pubkey: CryptoUtils.bytesToHex(n.pubkey),
        addresses: n.addresses,
        lastSeen: n.lastSeen,
        trustScore: n.trustScore,
      }));
      localStorage.setItem(
        DHT_STORAGE_KEY,
        JSON.stringify({ version: this.version, localNodeId: bytesToHex(this.localNodeId), nodes }),
      );
    } catch {
      /* 保存失敗は無視 */
    }
  }

  static load(localNodeId: Uint8Array): RoutingTable {
    const table = new RoutingTable(localNodeId);
    try {
      const raw = localStorage.getItem(DHT_STORAGE_KEY);
      if (!raw) return table;
      const data = JSON.parse(raw);
      if (!data || !Array.isArray(data.nodes)) return table;
      for (const n of data.nodes) {
        if (!/^[0-9a-f]{64}$/i.test(n.nodeId) || !/^[0-9a-f]{66}$/i.test(n.pubkey)) continue;
        table.addNode(
          {
            nodeId: CryptoUtils.hexToBytes(n.nodeId),
            pubkey: CryptoUtils.hexToBytes(n.pubkey),
            addresses: Array.isArray(n.addresses) ? n.addresses : [],
            lastSeen: Number(n.lastSeen) || 0,
            trustScore: Number(n.trustScore) || 0,
          },
          0,
        );
      }
    } catch {
      /* 壊れたデータは無視 */
    }
    return table;
  }
}

export class DhtNode {
  readonly localPrivHex: string;
  readonly localPubkey: Uint8Array;
  readonly localNodeId: Uint8Array;
  readonly table: RoutingTable;
  kvStore: Map<string, string> = new Map(); // keyHex -> value
  minTrust: number;

  private pendingMsgId = new Uint8Array(16);

  constructor(localPrivHex: string, minTrust: number = 0.0) {
    this.localPrivHex = localPrivHex;
    const privBytes = CryptoUtils.hexToBytes(localPrivHex);
    this.localPubkey = CryptoUtils.getRawCompressedPublicKey(privBytes);
    this.localNodeId = nodeIdFromPubkey(this.localPubkey);
    this.table = RoutingTable.load(this.localNodeId);
    this.minTrust = minTrust;
  }

  /** 次に使う msgId を返し、内部カウンタを進める */
  nextMsgId(): Uint8Array {
    for (let i = 15; i >= 0; i--) {
      this.pendingMsgId[i] = (this.pendingMsgId[i] + 1) & 0xff;
      if (this.pendingMsgId[i] !== 0) break;
    }
    return this.pendingMsgId.slice();
  }

  private selfInfo(): DhtNodeInfo {
    return {
      nodeId: this.localNodeId.slice(),
      pubkey: this.localPubkey.slice(),
      addresses: [],
      lastSeen: Math.floor(Date.now() / 1000),
      trustScore: 1.0,
    };
  }

  /** DHT RPC を組み立てて署名する (送信はメッシュ側が行う) */
  async createRpc(op: number, key: Uint8Array, value: Uint8Array = new Uint8Array()): Promise<DhtMessage> {
    const msg: DhtMessage = {
      op,
      msgId: this.nextMsgId(),
      key: key.slice(0, 32),
      nodes: [],
      value,
      sender: this.localPubkey.slice(),
      signature: new Uint8Array(64),
    };
    const signedData = Protocol.encodeDhtSignedData(msg);
    const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
    msg.signature = CryptoUtils.hexToBytes(sigHex);
    return msg;
  }

  /**
   * 受信した DhtMessage を処理する。PING / FIND_NODE / FIND_VALUE / STORE に応答し、
   * 応答 (DhtMessage + msgType) があれば reply コールバックで返す。
   */
  async handleIncoming(
    msg: DhtMessage,
    reply: (resp: DhtMessage, msgType: number) => Promise<void>,
  ): Promise<void> {
    // 署名検証 (encodeDhtSignedData は signature を含まないため msg をそのまま使える)
    try {
      const signedData = Protocol.encodeDhtSignedData(msg);
      const ok = await CryptoUtils.verifySignature(msg.sender, signedData, msg.signature);
      if (!ok) return;
    } catch {
      return;
    }

    // 送信元ノードをルーティングテーブルに追加
    const peerNode: DhtNodeInfo = {
      nodeId: nodeIdFromPubkey(msg.sender),
      pubkey: msg.sender,
      addresses: [],
      lastSeen: Math.floor(Date.now() / 1000),
      trustScore: this.minTrust,
    };
    this.table.addNode(peerNode, this.minTrust);

    switch (msg.op) {
      case DhtOpPing: {
        const pong: DhtMessage = {
          op: DhtOpPong,
          msgId: msg.msgId,
          key: msg.key,
          nodes: [this.selfInfo()],
          value: new Uint8Array(),
          sender: this.localPubkey,
          signature: new Uint8Array(64),
        };
        const signedData = Protocol.encodeDhtSignedData(pong);
        const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
        pong.signature = CryptoUtils.hexToBytes(sigHex);
        await reply(pong, 0x8b); // MsgTypeDhtNodes
        break;
      }
      case DhtOpFindNode: {
        const closest = this.table.findClosest(msg.key, K_BUCKET_SIZE);
        const resp: DhtMessage = {
          op: DhtOpFindNode,
          msgId: msg.msgId,
          key: msg.key,
          nodes: closest,
          value: new Uint8Array(),
          sender: this.localPubkey,
          signature: new Uint8Array(64),
        };
        const signedData = Protocol.encodeDhtSignedData(resp);
        const sigHex = await CryptoUtils.signMessage(this.localPrivHex, signedData);
        resp.signature = CryptoUtils.hexToBytes(sigHex);
        await reply(resp, 0x8b); // MsgTypeDhtNodes
        break;
      }
      case DhtOpFindValue: {
        const keyHex = bytesToHex(msg.key);
        if (this.kvStore.has(keyHex)) {
          const resp: DhtMessage = {
            op: DhtOpFindValue,
            msgId: msg.msgId,
            key: msg.key,
            nodes: [],
            value: new TextEncoder().encode(this.kvStore.get(keyHex) ?? ''),
            sender: this.localPubkey,
            signature: new Uint8Array(64),
          };
          const sd = Protocol.encodeDhtSignedData(resp);
          const sig = await CryptoUtils.signMessage(this.localPrivHex, sd);
          resp.signature = CryptoUtils.hexToBytes(sig);
          await reply(resp, 0x8c); // MsgTypeDhtValue
        } else {
          const closest = this.table.findClosest(msg.key, K_BUCKET_SIZE);
          const resp: DhtMessage = {
            op: DhtOpFindNode,
            msgId: msg.msgId,
            key: msg.key,
            nodes: closest,
            value: new Uint8Array(),
            sender: this.localPubkey,
            signature: new Uint8Array(64),
          };
          const sd = Protocol.encodeDhtSignedData(resp);
          const sig = await CryptoUtils.signMessage(this.localPrivHex, sd);
          resp.signature = CryptoUtils.hexToBytes(sig);
          await reply(resp, 0x8b); // MsgTypeDhtNodes
        }
        break;
      }
      case DhtOpStore: {
        if (msg.value.length <= DHT_VALUE_MAX) {
          this.kvStore.set(bytesToHex(msg.key), new TextDecoder().decode(msg.value));
        }
        const resp: DhtMessage = {
          op: DhtOpStore,
          msgId: msg.msgId,
          key: msg.key,
          nodes: [],
          value: new Uint8Array(),
          sender: this.localPubkey,
          signature: new Uint8Array(64),
        };
        const sd = Protocol.encodeDhtSignedData(resp);
        const sig = await CryptoUtils.signMessage(this.localPrivHex, sd);
        resp.signature = CryptoUtils.hexToBytes(sig);
        await reply(resp, 0x8c); // MsgTypeDhtValue
        break;
      }
      default:
        break;
    }
  }
}
