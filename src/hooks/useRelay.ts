import { useEffect, useRef, useState, useCallback } from 'react';
import { RelayClient, type RelayMessage } from '../lib/relay';

// リレーごとの接続状態
export interface RelayStatus {
  url: string;
  connected: boolean;
}

// Fodpr リレーサーバー(複数)への接続・送受信を React に橋渡しするカスタムフック。
// 受信メッセージは `messages` 配列として蓄積され、feed の描画に使える。
// イベントの重複排除は上位(App)側で行う。
export function useRelay(urls: string[]) {
  const [messages, setMessages] = useState<RelayMessage[]>([]);
  const [relayStatus, setRelayStatus] = useState<RelayStatus[]>(() =>
    urls.map((url) => ({ url, connected: false })),
  );
  const clientsRef = useRef<Map<string, RelayClient>>(new Map());
  const urlsKey = urls.join('\n');

  // リレー一覧の内容が変わったときだけ接続を作り直す(配列の同一性には依存しない)
  useEffect(() => {
    const clients = new Map<string, RelayClient>();
    clientsRef.current = clients;

    // リレー一覧の増減をステータスへ反映する(追加/削除時に接続状態はリセット)
    setRelayStatus(urls.map((url) => ({ url, connected: false })));

    const setConn = (url: string, connected: boolean) => {
      setRelayStatus((prev) => prev.map((s) => (s.url === url ? { ...s, connected } : s)));
    };

    for (const url of urls) {
      const client = new RelayClient({
        url,
        onMessage: (msg) => setMessages((prev) => [...prev, msg]),
      });
      clients.set(url, client);
      // 二重マウント(StrictMode)で即 close されても WebSocket を作らないよう遅延接続する
      client
        .connectDelay(0)
        .then(() => {
          if (clients.has(url)) setConn(url, true);
        })
        .catch(() => {
          if (clients.has(url)) setConn(url, false);
        });
    }

    return () => {
      for (const client of clients.values()) {
        client.close();
      }
      clientsRef.current = new Map();
    };
  }, [urlsKey]);

  const connected = relayStatus.some((s) => s.connected);

  const sendEvent = useCallback((event: Parameters<RelayClient['sendEvent']>[0]) => {
    for (const client of clientsRef.current.values()) {
      try {
        client.sendEvent(event);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }, []);

  const sendReq = useCallback((req: Parameters<RelayClient['sendReq']>[0]) => {
    for (const client of clientsRef.current.values()) {
      try {
        client.sendReq(req);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }, []);

  const sendDel = useCallback((req: Parameters<RelayClient['sendDel']>[0]) => {
    for (const client of clientsRef.current.values()) {
      try {
        client.sendDel(req);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }, []);

  return { connected, relayStatus, messages, sendEvent, sendReq, sendDel };
}
