import { useEffect, useRef, useState, useCallback } from 'react';
import { NostrRelayClient } from '../lib/nostrRelay';
import type { NostrRelayMessage } from '../lib/nostrRelay';

// リレーごとの接続状態
export interface NostrRelayStatus {
  url: string;
  connected: boolean;
}

// Nostr リレー(複数)への接続・送受信を React に橋渡しする。
// NostrRelayClient はテキスト JSON フレームで通信するため、useRelay とは異なり
// メッセージは JSON パース済みの形で蓄積される。
export function useNostrRelay(urls: string[]) {
  const [messages, setMessages] = useState<NostrRelayMessage[]>([]);
  const [relayStatus, setRelayStatus] = useState<NostrRelayStatus[]>(() =>
    urls.map((url) => ({ url, connected: false })),
  );
  const clientsRef = useRef<Map<string, NostrRelayClient>>(new Map());
  const urlsKey = urls.join('\n');

  useEffect(() => {
    const clients = new Map<string, NostrRelayClient>();
    clientsRef.current = clients;

    setRelayStatus(urls.map((url) => ({ url, connected: false })));

    const setConn = (url: string, connected: boolean) => {
      setRelayStatus((prev) => prev.map((s) => (s.url === url ? { ...s, connected } : s)));
    };

    for (const url of urls) {
      const client = new NostrRelayClient({
        url,
        onMessage: (msg) => setMessages((prev) => [...prev, msg]),
      });
      clients.set(url, client);
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

  const sendReq = useCallback((subscriptionId: string, filters: any[]) => {
    for (const client of clientsRef.current.values()) {
      try {
        client.sendReq(subscriptionId, filters);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }, []);

  const sendEvent = useCallback((event: any) => {
    for (const client of clientsRef.current.values()) {
      try {
        client.sendEvent(event);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }, []);

  // NIP-65 の write マーカー等、指定したリレーだけへ REQ を送る
  const sendReqTo = useCallback((urls: string[], subscriptionId: string, filters: any[]) => {
    for (const url of urls) {
      const client = clientsRef.current.get(url);
      if (!client) continue;
      try {
        client.sendReq(subscriptionId, filters);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }, []);

  // NIP-65 の read マーカー等、指定したリレーだけへイベントを送る
  const sendEventTo = useCallback((urls: string[], event: any) => {
    for (const url of urls) {
      const client = clientsRef.current.get(url);
      if (!client) continue;
      try {
        client.sendEvent(event);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }, []);

  const sendClose = useCallback((subscriptionId: string) => {
    for (const client of clientsRef.current.values()) {
      try {
        client.sendClose(subscriptionId);
      } catch {
        /* 未接続のリレーは無視 */
      }
    }
  }, []);

  const getSubId = useCallback((url: string): string => {
    const client = clientsRef.current.get(url);
    return client?.nextSubscriptionId() ?? `sub_${Date.now()}`;
  }, []);

  return { connected, relayStatus, messages, sendReq, sendEvent, sendReqTo, sendEventTo, sendClose, getSubId };
}
