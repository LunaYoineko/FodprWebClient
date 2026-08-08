import { Protocol, TransTypeJSON } from '/root/FodprTSSDK/dist/index.js';
import { WebSocket } from 'ws';
const pk = Buffer.from('02d9f3624d92d771f033ab8b1e1c0c995b0e570f8b730c3c542b49819ce175f62c', 'hex');
const ws = new WebSocket('ws://localhost:8000', { binary: true });
ws.binaryType = 'arraybuffer';
ws.on('error', (e) => console.log('WSERR', e.message));
ws.on('open', () => {
  ws.send(Protocol.encodeReq({ subId: 'gq', transType: TransTypeJSON, tagKey: '', tagVal: '' }));
  setTimeout(() => ws.close(), 8000);
});
ws.on('message', (data) => {
  if (typeof data === 'string') return;
  const b = Buffer.from(data);
  if (b[0] !== 0x81) return;
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const sl = view.getUint16(1, false);
  const ev = Protocol.decodeEvent(b.subarray(3 + sl));
  if (Buffer.from(ev.pubkey).equals(pk)) {
    const txt = typeof ev.content === 'string' ? ev.content : '';
    console.log('created=' + ev.createdAt + '  content=' + txt.slice(0, 120));
  }
});
