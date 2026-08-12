/**
 * wot.ts
 * ------
 * WoT (Web of Trust) スコアリング。
 *
 * DHT で発見された IPv6 ピアは、まず WoT の信頼スコアで評価される。
 * - 新規/未検証ピアは最小スコア (MIN_TRUST_DEFAULT = 0.0) で始まる。
 * - 信頼スコアが接続閾値 (CONNECT_THRESHOLD_DEFAULT) 以上にならない限り
 *   ダイアルしない (WoT ゲート)。
 * - スコアは WoT 紹介 (WoTIntro) と成功した対話で上昇し、時間とともに減衰する。
 *
 * 永続化: localStorage.fodpr_peer_trust
 */

export const TRUST_STORAGE_KEY = 'fodpr_peer_trust';
export const MIN_TRUST_DEFAULT = 0.0;
export const CONNECT_THRESHOLD_DEFAULT = 0.0;
export const MAX_TRUST_SCORE = 1.0;

// 紹介で新規ピアに付与するスコアの基準値
const INTRODUCTION_BASE_SCORE = 0.5;
// 紹介者のスコアがどれだけ新ピアに伝播するか (Nim の * 0.8 に相当)
const INTRODUCTION_DAMPING = 0.8;
// 成功/失敗のスコア増減
const SUCCESS_DELTA = 0.1;
const FAIL_DELTA = 0.15;
// 減衰: 30日で半分 (半分になるごとに score * 0.5)
const DECAY_HALF_LIFE_SEC = 30 * 86400;

export interface TrustEntry {
  score: number; // 0.0 .. 1.0
  lastUpdate: number; // unix 秒
  lastSeen: number; // 最後に接続できた時刻 (unix 秒, 0 = 未接続)
  introducedBy?: string; // 紹介者の pubkey hex (WoT の連鎖)
}

export interface TrustStoreData {
  version: number;
  entries: Record<string, TrustEntry>;
}

export class WoTStore {
  private entries: Map<string, TrustEntry>;
  readonly minTrust: number;
  readonly connectThreshold: number;

  constructor(minTrust: number = MIN_TRUST_DEFAULT, connectThreshold: number = CONNECT_THRESHOLD_DEFAULT) {
    this.minTrust = minTrust;
    this.connectThreshold = connectThreshold;
    this.entries = new Map();
    this.load();
  }

  private load() {
    try {
      const raw = localStorage.getItem(TRUST_STORAGE_KEY);
      if (!raw) return;
      const data = JSON.parse(raw) as TrustStoreData;
      if (data && typeof data === 'object' && data.entries) {
        for (const [k, v] of Object.entries(data.entries)) {
          if (typeof v.score === 'number') this.entries.set(k, v);
        }
      }
    } catch {
      /* 壊れたデータは無視 */
    }
  }

  private save() {
    try {
      const data: TrustStoreData = { version: 1, entries: {} };
      for (const [k, v] of this.entries) data.entries[k] = v;
      localStorage.setItem(TRUST_STORAGE_KEY, JSON.stringify(data));
    } catch {
      /* 保存失敗は無視 */
    }
  }

  /** 現在のスコアを返す (未登録なら最小スコアで登録して返す) */
  getScore(pubkeyHex: string): number {
    const e = this.entries.get(pubkeyHex);
    if (!e) {
      const entry: TrustEntry = { score: this.minTrust, lastUpdate: Math.floor(Date.now() / 1000), lastSeen: 0 };
      this.entries.set(pubkeyHex, entry);
      this.save();
      return entry.score;
    }
    return e.score;
  }

  /** 接続閾値を超えているか (WoT ゲート) */
  isTrusted(pubkeyHex: string): boolean {
    return this.getScore(pubkeyHex) >= this.connectThreshold;
  }

  /** 接続成功を記録してスコアを上げる */
  recordSuccess(pubkeyHex: string) {
    const now = Math.floor(Date.now() / 1000);
    const e = this.entries.get(pubkeyHex) ?? {
      score: this.minTrust,
      lastUpdate: now,
      lastSeen: 0,
    };
    e.score = Math.min(e.score + SUCCESS_DELTA, MAX_TRUST_SCORE);
    e.lastUpdate = now;
    e.lastSeen = now;
    this.entries.set(pubkeyHex, e);
    this.save();
  }

  /** 接続失敗を記録してスコアを下げる */
  recordFailure(pubkeyHex: string) {
    const now = Math.floor(Date.now() / 1000);
    const e = this.entries.get(pubkeyHex) ?? {
      score: this.minTrust,
      lastUpdate: now,
      lastSeen: 0,
    };
    e.score = Math.max(e.score - FAIL_DELTA, this.minTrust);
    e.lastUpdate = now;
    this.entries.set(pubkeyHex, e);
    this.save();
  }

  /**
   * WoT 紹介を適用する。
   * 新ピアのスコア = max(現在のスコア, 紹介者のスコア * INTRODUCTION_DAMPING)。
   * 紹介者もわずかにスコアが上がる (Nim の discovery.processWoTIntroduction 相当)。
   */
  applyIntroduction(introducerHex: string, newPeerHex: string, introducedScore = INTRODUCTION_BASE_SCORE) {
    const now = Math.floor(Date.now() / 1000);
    const introScore = this.getScore(introducerHex);

    const e = this.entries.get(newPeerHex) ?? {
      score: this.minTrust,
      lastUpdate: now,
      lastSeen: 0,
    };
    const propagated = Math.max(introducedScore, introScore * INTRODUCTION_DAMPING);
    e.score = Math.max(e.score, Math.min(propagated, MAX_TRUST_SCORE));
    e.introducedBy = introducerHex;
    e.lastUpdate = now;
    this.entries.set(newPeerHex, e);

    const intro = this.entries.get(introducerHex);
    if (intro) {
      intro.score = Math.min(intro.score + 0.05, MAX_TRUST_SCORE);
      intro.lastUpdate = now;
      this.entries.set(introducerHex, intro);
    }
    this.save();
    return e.score;
  }

  /** 時間経過による減衰 (30日で半分)。定期的に呼ぶこと。 */
  decay(now: number = Math.floor(Date.now() / 1000)) {
    let changed = false;
    for (const e of this.entries.values()) {
      const elapsed = Math.max(0, now - e.lastUpdate);
      const factor = Math.pow(0.5, elapsed / DECAY_HALF_LIFE_SEC);
      const next = Math.max(e.score * factor, this.minTrust);
      if (next !== e.score) {
        e.score = next;
        e.lastUpdate = now;
        changed = true;
      }
    }
    if (changed) this.save();
  }

  /** 全エントリ (UI 表示用) */
  getAll(): { pubkey: string; score: number; lastSeen: number; introducedBy?: string }[] {
    const out: { pubkey: string; score: number; lastSeen: number; introducedBy?: string }[] = [];
    for (const [k, e] of this.entries) {
      out.push({ pubkey: k, score: e.score, lastSeen: e.lastSeen, introducedBy: e.introducedBy });
    }
    out.sort((a, b) => b.score - a.score);
    return out;
  }
}

export function createWoTStore(): WoTStore {
  return new WoTStore();
}
