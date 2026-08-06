/**
 * relay.ts
 * --------
 * Fodpr リレーサーバー向けブラウザクライアント。
 *
 * 設計方針:
 *  - サーバー(Nim)とは「バイナリフレーム」で通信する。テキストフレームは UTF-8
 *    エンコードされるため公開鍵/署名のような任意バイト列を壊してしまうため。
 *  - ワイヤプロトコルのエンコード/デコードは SDK(`FodprTSSDK/src/protocol.ts`)の
 *    `Protocol` クラスをそのまま再利用する。ここでは WebSocket 送受信と
 *    PUSHパケットの振り分けのみを担う(Node 用の `ws` に依存しない)。
 */

import {
  Protocol,
  MsgTypePush,
  MsgTypeEvent,
  type FodprEvent,
  type FodprReq,
  type FodprDelReq,
} from '@fodpr/protocol';

// url を含まないメッセージ本文
type RelayMessageBody =
  | { kind: 'open' } // 接続確立
  | { kind: 'closed'; code: number } // 切断
  | { kind: 'error'; message: string } // エラー
  | { kind: 'text'; text: string } // サーバーからのテキスト応答("OK: ..."(ERR:.../EOE:...)
  | { kind: 'event'; subId: string; event: FodprEvent }; // PUSH されたイベント

// クライアントが受け取れるメッセージの種類(送信元リレー url 付き)
export type RelayMessage = RelayMessageBody & { url: string };

export interface RelayClientOptions {
  // 接続先 URL
  url: string;
  // 受信メッセージを通知するコールバック
  onMessage?: (msg: RelayMessage) => void;
}

// ブラウザのネイティブ WebSocket をラップした Fodpr クライアント
export class RelayClient {
  private ws: WebSocket | null = null;
  private connectTimer: number | undefined;
  readonly url: string;
  private onMessage?: (msg: RelayMessage) => void;

  constructor(options: RelayClientOptions) {
    this.url = options.url;
    this.onMessage = options.onMessage;
  }

  // サーバーへ接続する。接続確立で resolve される
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      // バイナリフレームを ArrayBuffer として受け取る(文字化け防止)
      ws.binaryType = 'arraybuffer';

      ws.addEventListener('open', () => {
        this.emit({ kind: 'open' });
        resolve();
      });

      ws.addEventListener('error', () => {
        this.emit({ kind: 'error', message: 'WebSocket error' });
        reject(new Error('WebSocket error'));
      });

      ws.addEventListener('close', (e: CloseEvent) => {
        this.emit({ kind: 'closed', code: e.code });
      });

      ws.addEventListener('message', (ev: MessageEvent) => {
        this.handleMessage(ev);
      });

      this.ws = ws;
    });
  }

  // 接続開始を少し遅延させる。
  // React StrictMode の二重マウントなどで「作ってすぐ閉じる」ことになっても
  // この間に close() されれば WebSocket を生成せず、
  // 「WebSocket is closed before the connection is established」エラーを防ぐ。
  connectDelay(ms = 0): Promise<void> {
    return new Promise((resolve, reject) => {
      this.connectTimer = window.setTimeout(() => {
        this.connectTimer = undefined;
        this.connect().then(resolve).catch(reject);
      }, ms);
    });
  }

  // 内部通知ヘルパー
  private emit(msg: RelayMessageBody) {
    this.onMessage?.({ ...msg, url: this.url });
  }

  // 受信フレームの振り分け: テキスト応答 or バイナリ PUSH パケット
  private handleMessage(ev: MessageEvent) {
    if (typeof ev.data === 'string') {
      this.emit({ kind: 'text', text: ev.data });
      return;
    }

    // バイナリフレーム -> ArrayBuffer -> Uint8Array
    const bytes = new Uint8Array(ev.data as ArrayBuffer);
    if (bytes.length === 0) {
      return;
    }

    // 先頭バイトが PUSH(0x81) ならイベント配信パケット
    if (bytes[0] === MsgTypePush) {
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      // レイアウト: [MsgTypePush(1)] [SubIdLen(2)] [SubId] [encodedEvent]
      const subIdLen = view.getUint16(1, false);
      const subId = new TextDecoder().decode(bytes.subarray(3, 3 + subIdLen));
      const event = Protocol.decodeEvent(bytes.subarray(3 + subIdLen));
      this.emit({ kind: 'event', subId, event });
    } else {
      // 予期せずテキストでない場合は UTF-8 として表示
      this.emit({ kind: 'text', text: new TextDecoder().decode(bytes) });
    }
  }

  // イベント投稿(EVENT)。署名は呼び出し側で事前に生成して渡す。
  sendEvent(event: FodprEvent) {
    this.ensureOpen();
    // イベント本体をエンコードし、先頭に種別バイト(EVENT 0x01)を付与して送信
    const payload = Protocol.encodeEvent(event);
    const frame = new Uint8Array(1 + payload.length);
    frame[0] = MsgTypeEvent;
    frame.set(payload, 1);
    this.ws!.send(this.toArrayBuffer(frame));
  }

  // 購読要求(REQ)を送信。encodeReq は先頭に種別バイト(0x02)を含む。
  sendReq(req: FodprReq) {
    this.ensureOpen();
    const payload = Protocol.encodeReq(req);
    this.ws!.send(this.toArrayBuffer(payload));
  }

  // イベント削除要求(DEL)を送信。encodeDel は先頭に種別バイト(0x03)を含む。
  sendDel(req: FodprDelReq) {
    this.ensureOpen();
    const payload = Protocol.encodeDel(req);
    this.ws!.send(this.toArrayBuffer(payload));
  }

  // 接続が必要なメソッド共通の事前チェック
  private ensureOpen() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket が接続されていません');
    }
  }

  // Uint8Array を所有する ArrayBuffer にコピーする。
  // (ws.send は ArrayBuffer / ArrayBufferView を受け取るが、Uint8Array.buffer は
  //  ArrayBufferLike(共有型も含む)ため、純粋な ArrayBuffer を渡す必要がある)
  private toArrayBuffer(view: Uint8Array): ArrayBuffer {
    const buf = new ArrayBuffer(view.length);
    new Uint8Array(buf).set(view);
    return buf;
  }

  // 接続を閉じる(未開始の遅延接続は取り消す)
  close() {
    if (this.connectTimer !== undefined) {
      clearTimeout(this.connectTimer);
      this.connectTimer = undefined;
    }
    this.ws?.close();
    this.ws = null;
  }
}
