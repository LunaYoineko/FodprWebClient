/**
 * network.ts
 * ----------
 * v0.6 "Mesh": 統合ネットワーク層 (F2F メッシュのみ)。
 *
 * リレーサーバー・ホスト昇グループは存在しない。すべての接続はクライアント間
 * (F2F) の WebRTC データチャネル。MeshManager がブートストラップ(招待コード /
 * 設定済みブートストラップノード / 手動 IP)、WoT ゲート、DHT でのアドレス解決、
 * ピアダイアル、ゴシップ配信を一手に責務する。
 *
 * App は createNetworkManager() で得た NetworkManager を 1 つだけ保持し、
 * mesh イベントを onEvent コールバックで受け取る。モード切替はない (常に mesh)。
 */

import { MeshManager, type MeshEvent, type MeshManagerOptions } from './f2fMesh';
import { CryptoUtils } from '@fodpr/crypto';

export type NetworkMode = 'f2f';

export type NetworkEvent = MeshEvent & { mode: 'f2f' };

export interface NetworkManagerOptions extends MeshManagerOptions {
  // v0.6 では不要だが API 互換性を保つため受け入れる
  seedRelayUrl?: string;
}

export interface NetworkManager {
  onEvent: ((ev: NetworkEvent) => void) | null;
  getPeerCount(): number;
  getMode(): NetworkMode;
  bootstrap(): Promise<boolean>;
  createInvitation(targetPubkeyHex?: string, expiresInSec?: number, scope?: number): Promise<string>;
  connectWithInvitation(code: string): Promise<boolean>;
  broadcastEvent(event: Parameters<MeshManager['broadcastEvent']>[0]): Promise<boolean>;
  getPeerCache(): ReturnType<MeshManager['getPeerCache']>;
  getDhtNodes(): ReturnType<MeshManager['getDhtNodes']>;
  getTrustEntries(): ReturnType<MeshManager['getTrustEntries']>;
  getLocalEvents(): ReturnType<MeshManager['getLocalEvents']>;
  close(): void;
}

class NetworkManagerImpl implements NetworkManager {
  private mesh: MeshManager;
  readonly mode: NetworkMode = 'f2f';

  onEvent: ((ev: NetworkEvent) => void) | null = null;

  constructor(opts: NetworkManagerOptions) {
    this.mesh = new MeshManager(opts);
    this.mesh.onEvent = (ev) => {
      this.onEvent?.({ ...ev, mode: 'f2f' });
    };
  }

  getPeerCount(): number {
    return this.mesh.peerCount;
  }

  getMode(): NetworkMode {
    return this.mode;
  }

  bootstrap(): Promise<boolean> {
    return this.mesh.bootstrap();
  }

  createInvitation(targetPubkeyHex?: string, expiresInSec?: number, scope?: number): Promise<string> {
    return this.mesh.createInvitation(targetPubkeyHex, expiresInSec, scope);
  }

  connectWithInvitation(code: string): Promise<boolean> {
    return this.mesh.connectWithInvitation(code);
  }

  async broadcastEvent(event: Parameters<MeshManager['broadcastEvent']>[0]): Promise<boolean> {
    return this.mesh.broadcastEvent(event);
  }

  getPeerCache() {
    return this.mesh.getPeerCache();
  }

  getDhtNodes() {
    return this.mesh.getDhtNodes();
  }

  getTrustEntries() {
    return this.mesh.getTrustEntries();
  }

  getLocalEvents() {
    return this.mesh.getLocalEvents();
  }

  close() {
    this.mesh.close();
  }
}

export function createNetworkManager(opts: NetworkManagerOptions): NetworkManager {
  return new NetworkManagerImpl(opts);
}

export function pubkeyToFpub(pubkeyHex: string): string {
  const pubBytes = CryptoUtils.hexToBytes(pubkeyHex);
  return CryptoUtils.fpubEncode(pubBytes).toLowerCase();
}

export { MeshManager };
export type { MeshEvent } from './f2fMesh';
export type { F2FPeerInfo } from './fodprF2f';
export type { DhtNodeInfo } from './dht';
export type { TrustEntry } from './wot';
