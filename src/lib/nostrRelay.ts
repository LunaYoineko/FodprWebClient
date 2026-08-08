// nostrRelay.ts
// ----------------
// Nostr リレー向けブラウザクライアント。テキスト JSON フレームで通信する。

export type NostrRelayMessage =
  | { kind: 'open'; url: string }
  | { kind: 'closed'; url: string; code: number }
  | { kind: 'error'; url: string; message: string }
  | { kind: 'notice'; url: string; message: string }
  | { kind: 'event'; url: string; subscriptionId: string; event: any }
  | { kind: 'eose'; url: string; subscriptionId: string };

// eslint-disable-next-line @typescript-eslint/no-explicit-any

export interface NostrRelayClientOptions {
  url: string;
  onMessage?: (msg: NostrRelayMessage) => void;
}

// Browser-native WebSocket wrapper for Nostr relays (text frames)
export class NostrRelayClient {
  private ws: WebSocket | null = null;
  private connectTimer: number | undefined;
  readonly url: string;
  private onMessage?: (msg: NostrRelayMessage) => void;
  private subIdCounter = 0;

  constructor(options: NostrRelayClientOptions) {
    this.url = options.url;
    this.onMessage = options.onMessage;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      ws.binaryType = 'arraybuffer';

      ws.addEventListener('open', () => {
        this.emit({ kind: 'open', url: this.url });
        resolve();
      });

      ws.addEventListener('error', () => {
        this.emit({ kind: 'error', url: this.url, message: 'WebSocket error' });
        reject(new Error('WebSocket error'));
      });

      ws.addEventListener('close', (e: CloseEvent) => {
        this.emit({ kind: 'closed', url: this.url, code: e.code });
      });

      ws.addEventListener('message', (ev: MessageEvent) => {
        this.handleMessage(ev);
      });

      this.ws = ws;
    });
  }

  connectDelay(ms = 0): Promise<void> {
    return new Promise((resolve, reject) => {
      this.connectTimer = window.setTimeout(() => {
        this.connectTimer = undefined;
        this.connect().then(resolve).catch(reject);
      }, ms);
    });
  }

  private emit(msg: NostrRelayMessage) {
    this.onMessage?.(msg);
  }

  private handleMessage(ev: MessageEvent) {
    let data: string;
    if (typeof ev.data === 'string') {
      data = ev.data;
    } else {
      // Treat as UTF-8 text if it's ArrayBuffer
      data = new TextDecoder().decode(ev.data as ArrayBuffer);
    }

    let msg: unknown;
    try {
      msg = JSON.parse(data);
    } catch {
      this.emit({ kind: 'notice', url: this.url, message: 'Invalid JSON from relay' });
      return;
    }

    if (!Array.isArray(msg)) {
      return;
    }

    const type = msg[0];
    if (type === 'EVENT') {
      // Nostr relay sends ["EVENT", subId, event]
      // But some implementations may send ["EVENT", event] — handle both
      const subId = typeof msg[1] === 'string' ? msg[1] : '';
      const event = typeof msg[1] === 'string' ? msg[2] : msg[1];
      this.emit({ kind: 'event', url: this.url, subscriptionId: subId, event });
    } else if (type === 'EOSE') {
      const subId = typeof msg[1] === 'string' ? msg[1] : '';
      this.emit({ kind: 'eose', url: this.url, subscriptionId: subId });
    } else if (type === 'NOTICE') {
      const message = typeof msg[1] === 'string' ? msg[1] : '';
      this.emit({ kind: 'notice', url: this.url, message });
    } else if (type === 'CLOSE') {
      const subId = typeof msg[1] === 'string' ? msg[1] : '';
      this.emit({ kind: 'notice', url: this.url, message: 'Relay closed subscription ' + subId });
    }
  }

  sendText(json: string) {
    this.ensureOpen();
    this.ws!.send(json);
  }

  sendReq(subscriptionId: string, filters: any[]) {
    this.ensureOpen();
    this.ws!.send(JSON.stringify(['REQ', subscriptionId, ...filters]));
  }

  sendEvent(event: any) {
    this.ensureOpen();
    this.ws!.send(JSON.stringify(['EVENT', event]));
  }

  sendClose(subscriptionId: string) {
    this.ensureOpen();
    this.ws!.send(JSON.stringify(['CLOSE', subscriptionId]));
  }

  nextSubscriptionId(): string {
    this.subIdCounter += 1;
    return 'sub_' + Date.now() + '_' + this.subIdCounter;
  }

  private ensureOpen() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not connected');
    }
  }

  close() {
    if (this.connectTimer !== undefined) {
      clearTimeout(this.connectTimer);
      this.connectTimer = undefined;
    }
    this.ws?.close();
    this.ws = null;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// 使い捨てのワンショット取得ヘルパー
// ────────────────────────────────────────────────────────────────────────────

interface FetchResult {
  events: any[];
}

function singleRelayFetch(url: string, filters: any[], timeoutMs = 8000): Promise<FetchResult> {
  return new Promise((resolve, reject) => {
    let ws: WebSocket | null = null;
    let settled = false;
    const timer = window.setTimeout(() => {
      if (settled) return;
      settled = true;
      ws?.close();
      reject(new Error('リレーからの応答がタイムアウトしました'));
    }, timeoutMs);

    const finish = () => {
      clearTimeout(timer);
    };

    try {
      ws = new WebSocket(url);
    } catch (e) {
      finish();
      reject(e instanceof Error ? e : new Error(String(e)));
      return;
    }

    const events: any[] = [];
    ws.onopen = () => {
      ws?.send(JSON.stringify(['REQ', 'fetch_' + Date.now(), ...filters]));
    };
    ws.onmessage = (ev: MessageEvent) => {
      let msg: unknown;
      try {
        msg = JSON.parse(String(ev.data));
      } catch {
        return;
      }
      if (!Array.isArray(msg)) return;
      if (msg[0] === 'EVENT' && msg[2] && typeof msg[2] === 'object') {
        events.push(msg[2]);
      } else if (msg[0] === 'EOSE') {
        if (settled) return;
        settled = true;
        ws?.close();
        finish();
        resolve({ events });
      } else if (msg[0] === 'NOTICE') {
        // リレーからの通知は無視(応答待ちは続行)
      }
    };
    ws.onerror = () => {
      if (settled) return;
      settled = true;
      finish();
      reject(new Error('リレーへの接続に失敗しました: ' + url));
    };
    ws.onclose = () => {
      if (!settled) {
        settled = true;
        finish();
        reject(new Error('リレーが接続を閉じました: ' + url));
      }
    };
  });
}

// 指定 pubkey の kind 0(プロフィール)を複数リレーから取得し、最新のものを返す。
// 見つからなければ null。
export async function fetchNostrKind0(
  urls: string[],
  pubkeyHex: string,
  timeoutMs = 8000,
): Promise<any | null> {
  return fetchLatestEventOfKind(urls, pubkeyHex, 0, timeoutMs);
}

// 指定 pubkey の最新 kind(kind 0 / kind 10002 など)を複数リレーから取得して返す。
// 見つからなければ null。
async function fetchLatestEventOfKind(
  urls: string[],
  pubkeyHex: string,
  kind: number,
  timeoutMs = 8000,
): Promise<any | null> {
  let best: any = null;
  let anyOk = false;
  let lastErr: Error | null = null;
  await Promise.all(
    (urls.length ? urls : []).map(async (url) => {
      try {
        const { events } = await singleRelayFetch(
          url,
          [{ kinds: [kind], authors: [pubkeyHex], limit: 1 }],
          timeoutMs,
        );
        anyOk = true;
        for (const ev of events) {
          if (ev.kind !== kind || ev.pubkey !== pubkeyHex) continue;
          if (!best || (ev.created_at ?? 0) > best.created_at) best = ev;
        }
      } catch (e) {
        lastErr = e instanceof Error ? e : new Error(String(e));
      }
    }),
  );
  if (best) return best;
  if (anyOk) return null;
  throw lastErr ?? new Error('プロフィールを取得できませんでした');
}

// ────────────────────────────────────────────────────────────────────────────
// NIP-65 kind 10002(リレーリスト)
// ────────────────────────────────────────────────────────────────────────────

// kind 10002 のリレーリスト。tags は ["r", "<url>"] または ["r", "<url>", "read"|"write"]。
// マーカーなしは読み書き両用。マーカー付きはその役割のみ。
export interface RelayList {
  read: string[]; // 読み取り専用
  write: string[]; // 書き込み専用
  both: string[]; // 読み書き両用(マーカーなし)
  all: string[]; // 重複のない全 URL
}

// リレーリスト(kind 10002)イベントを解析して read/write に分類する
export function parseRelayListEvent(ev: any): RelayList {
  const read: string[] = [];
  const write: string[] = [];
  const both: string[] = [];
  const push = (arr: string[], url: string) => {
    if (!arr.includes(url)) arr.push(url);
  };
  for (const t of ev?.tags ?? []) {
    if (!Array.isArray(t) || t[0] !== 'r') continue;
    const url = typeof t[1] === 'string' ? t[1] : '';
    if (!url) continue;
    const marker = typeof t[2] === 'string' ? t[2] : '';
    if (marker === 'read') push(read, url);
    else if (marker === 'write') push(write, url);
    else push(both, url);
  }
  return { read, write, both, all: Array.from(new Set([...read, ...write, ...both])) };
}

// 指定 pubkey の kind 10002(リレーリスト)を複数リレーから取得し、
// 見つかれば parseRelayListEvent の結果、なければ null を返す。
export async function fetchNostrRelayList(
  urls: string[],
  pubkeyHex: string,
  timeoutMs = 8000,
): Promise<RelayList | null> {
  const ev = await fetchLatestEventOfKind(urls, pubkeyHex, 10002, timeoutMs);
  return ev ? parseRelayListEvent(ev) : null;
}
