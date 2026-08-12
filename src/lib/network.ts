/**
 * network.ts
 * ----------
 * 統合ネットワーク層：3モード（F2F / Relay / RtcGroup）をトグルで切り替え。
 *
 * - F2F: Web of Trust 方式。知り合いを介して最大50人まで接続し、P2P をマルチモーダルに確立。
 *   ブートストラップは招待コードまたはリレーのシード取得機能。
 * - Relay: リレー経由のサーバー中継メッセージング（既存の useRelay フックで実装済み）。
 * - RtcGroup: ホスト昇格型 P2P。最初に P2P を始めた人をホストとし、他の人はそのホストに接続。
 *   ホストが抜けた際は最古の joinedAt の人がホストに昇格し、全員が新ホストへ再接続。
 */

import { F2FManager, type F2FGroupInfo } from './fodprF2f';
import { RtcGroupManager, type RtcGroupInfo } from './rtcGroup';
import type { RelayClient } from './relay';
import { CryptoUtils } from '@fodpr/crypto';

export type NetworkMode = 'f2f' | 'relay' | 'rtcgroup';

export type { RtcGroupInfo };

export interface NetworkManagerOptions {
  mode: NetworkMode;
  privKeyHex: string;
  relayClients: RelayClient[];
  seedRelayUrl?: string;
}

export interface NetworkEvent {
  type: string;
  [key: string]: any;
}

export interface NetworkManager {
  onEvent: ((ev: NetworkEvent) => void) | null;
  getPeerCount(): number;
  getGroups(): (F2FGroupInfo | RtcGroupInfo)[];
  getMode(): NetworkMode;
  setMode(mode: NetworkMode): Promise<void>;
  close(): void;
}

class NetworkManagerImpl implements NetworkManager {
  private currentMode: NetworkMode;
  private privKeyHex: string;
  private relayClients: RelayClient[];
  private seedRelayUrl?: string;

  private f2fManager: F2FManager | null = null;
  private rtcGroupManager: RtcGroupManager | null = null;

  onEvent: ((ev: NetworkEvent) => void) | null = null;

  constructor(opts: NetworkManagerOptions) {
    this.currentMode = opts.mode;
    this.privKeyHex = opts.privKeyHex;
    this.relayClients = opts.relayClients;
    this.seedRelayUrl = opts.seedRelayUrl;
    if (this.privKeyHex) {
      this.initCurrentMode();
    }
  }

  private initCurrentMode() {
    if (!this.privKeyHex) return;
    switch (this.currentMode) {
      case 'f2f':
        this.initF2F();
        break;
      case 'rtcgroup':
        this.initRtcGroup();
        break;
      case 'relay':
      default:
        break;
    }
  }

  private initF2F() {
    this.f2fManager = new F2FManager({
      privKeyHex: this.privKeyHex,
      relays: this.relayClients,
      seedRelayUrl: this.seedRelayUrl,
    });
    this.f2fManager.onEvent = (ev) => {
      this.onEvent?.({ ...ev, mode: 'f2f' });
    };
    // F2F モード開始時にシード登録 (自分の情報をリレーに通知)
    this.f2fManager.registerSeed?.().catch(() => {});
  }

  private initRtcGroup() {
    this.rtcGroupManager = new RtcGroupManager({
      privKeyHex: this.privKeyHex,
      relays: this.relayClients,
    });
    this.rtcGroupManager.onEvent = (ev) => {
      this.onEvent?.({ ...ev, mode: 'rtcgroup' });
    };
    this.rtcGroupManager.subscribeKnownGroups();
  }

  private async cleanupCurrentMode() {
    if (this.f2fManager) {
      this.f2fManager.close();
      this.f2fManager = null;
    }
    if (this.rtcGroupManager) {
      this.rtcGroupManager.close();
      this.rtcGroupManager = null;
    }
  }

  getPeerCount(): number {
    if (this.f2fManager) return this.f2fManager.peerCount;
    if (this.rtcGroupManager) return this.rtcGroupManager.peerCount;
    return 0;
  }

  getGroups(): (F2FGroupInfo | RtcGroupInfo)[] {
    if (this.f2fManager) return this.f2fManager.getGroups();
    if (this.rtcGroupManager) return this.rtcGroupManager.getGroups();
    return [];
  }

  getMode(): NetworkMode {
    return this.currentMode;
  }

  async setMode(mode: NetworkMode) {
    if (mode === this.currentMode) return;
    await this.cleanupCurrentMode();
    this.currentMode = mode;
    this.initCurrentMode();
  }

  close() {
    this.cleanupCurrentMode();
  }
}

export function createNetworkManager(opts: NetworkManagerOptions): NetworkManager {
  return new NetworkManagerImpl(opts);
}

export function pubkeyToFpub(pubkeyHex: string): string {
  const pubBytes = CryptoUtils.hexToBytes(pubkeyHex);
  return CryptoUtils.fpubEncode(pubBytes).toLowerCase();
}