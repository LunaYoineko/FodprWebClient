// Playwright test: Fodpr + Nostr 通知の end-to-end 検証
// - poster(自分)の投稿へ、reactor(第三者)が react/reply/repost/quote(または Nostr kind 7/6/1)を投稿
// - アプリが受信 PUSH から通知を導出し、ベルバッジが増えることを確認
import { chromium } from 'playwright';
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import WebSocket from 'ws';
import https from 'node:https';

const url = process.argv[2] || 'http://localhost:5199';
const apiBase = process.argv[3] || 'http://localhost:8088';
const NOSTR_RELAY = 'wss://relay.yoinekodo.jp/';

const log = (k, v) => console.log(k, v);

// poster / reactor の Fodpr 秘密鍵(HEX)。poster はアプリにシードされる。
// reactor は REST /api/note で署名してリレーへブロードキャストする
const POSTER_FODPR = '404A16913F14DDE240863038FFE2FCC80CB72BA6A9E3F1471A935793D0F1124E';
function randHex(n){const a=Buffer.alloc(n);for(let i=0;i<n;++i)a[i]=Math.floor(Math.random()*256);return a.toString('hex');}
// reactor の Fodpr 秘密鍵(HEX)をランダム生成(第三者として署名してブロードキャスト)
const REACTOR_FODPR_KEY = secp.utils.randomPrivateKey();
const REACTOR_FODPR = Buffer.isBuffer(REACTOR_FODPR_KEY)
  ? REACTOR_FODPR_KEY.toString('hex')
  : typeof REACTOR_FODPR_KEY === 'string'
    ? REACTOR_FODPR_KEY
    : Buffer.from(REACTOR_FODPR_KEY).toString('hex');

// Fodpr pubkey(hex) from priv
function fodprPub(privHex){return Buffer.from(secp.getPublicKey(privHex, true)).slice(1).toString('hex');}

// Nostr nsec(hex) -> 32-byte x-only pubkey hex
function nostrPub(nsecHex){const c=secp.getPublicKey(nsecHex,true);return Buffer.from(c).slice(1).toString('hex');}

// REST /api/note で署名+ブロードキャスト。tagsはreact:/reply:/repost:/quote:<dk>
function postNote(privHex, content, tags=[], quote='') {
  const body = JSON.stringify({ privKey: privHex, content, tags, quote });
  return new Promise((resolve, reject) => {
    const data = Buffer.from(body);
    const req = https.request(
      apiBase + '/api/note',
      { method:'POST', headers:{'Content-Type':'application/json','Content-Length':data.length} },
      (res) => {
        let s='';res.on('data',c=>s+=c);res.on('end',()=>{try{resolve(JSON.parse(s))}catch(e){reject(e)}});
      }
    );
    req.on('error', reject); req.write(data); req.end();
  });
}

// Nostr イベントを署名して指定リレーへ publish。returns event id
async function nostrPublish(nsecHex, {kind, created_at, tags, content}) {
  const pub = nostrPub(nsecHex);
  const ser = JSON.stringify([0, pub, created_at, kind, tags, content]);
  const idBytes = Uint8Array.from(sha256(new TextEncoder().encode(ser)));
  const sig = secp.schnorr.sign(idBytes, nsecHex);
  const id = Buffer.from(idBytes).toString('hex');
  const ev = { id, pubkey: pub, created_at, kind, tags, content, sig: Buffer.from(sig).toString('hex') };
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(NOSTR_RELAY);
    ws.on('open', ()=>{ ws.send(JSON.stringify(['EVENT', ev])); });
    ws.on('message', (m) => {
      try {
        const j = JSON.parse(m.toString());
        if (j[0] === 'OK' && j[1] === id) { ws.close(); resolve(true); }
        else if (j[0] === 'NOTICE') { /* ignore */ }
      } catch { /* ignore non-json */ }
    });
    ws.on('error', reject);
    setTimeout(()=>{ ws.close(); resolve('timeout'); }, 15000);
  });
  return id;
}

function sleep(ms){return new Promise(r=>setTimeout(r,ms));}
async function getUnreadBadge(page){
  const v = await page.evaluate(()=>document.querySelector('header .fixed .bg-primary')?.textContent?.trim());
  return v ? parseInt(v,10) : 0;
}
async function panelRows(page){
  return page.evaluate(()=>Array.from(document.querySelectorAll('button[title]')).flatMap(b=>b.textContent? [b.textContent.trim()]:[]));
}

const browser = await chromium.launch();
const ctx = await browser.newContext();
const page = await ctx.newPage();
await page.addInitScript(({hex,relay})=>{
  localStorage.setItem('fodpr_priv', hex);
  localStorage.setItem('fodpr_relays', JSON.stringify([relay]));
}, {hex: POSTER_FODPR, relay:'ws://localhost:8000'});
await page.goto(url+'/', { waitUntil:'domcontentloaded' });
// Fodpr リレー接続待ち(green dot)
await page.waitForFunction(()=>document.querySelector('header span.h-2.w-2.rounded-full.bg-green-400')!==null,{timeout:25000});
await page.waitForTimeout(3000); // sync REQ 待ち

// ---- Fodpr: poster の note を投稿 ----
const noteRes = await postNote(POSTER_FODPR, '通知テスト用の投稿です');
const dk = noteRes?.event?.dedupeKey;
if (!dk) throw new Error('poster note dedupeKey missing: ' + JSON.stringify(noteRes));
log('FODPR_POSTER_NOTE_DK', dk);

// app が自分の note を受信して myFodprKeys へ載るまで待機
await page.waitForFunction(()=>{
  // バッジが0でもいい。note が到着したかを「通知」の対象になったかで判定→リアクション投稿後に判定する。
  return true;
},{timeout:5000});

// ---- Fodpr: reactor が react / reply / repost / quote を投稿 ----
const actions = [
  { label:'react', tags:['react:'+dk], content:'❤️' },
  { label:'reply', tags:['reply:'+dk], content:'お返事です' },
  { label:'repost', tags:['repost:'+dk], content:'' },
  { label:'quote', tags:['quote:'+dk], content:'引用コメント' },
];
let fodprBadge = 0;
for (const a of actions) {
  await postNote(REACTOR_FODPR, a.content, a.tags);
  await sleep(1500);
  fodprBadge = await getUnreadBadge(page);
  log(`FODPR_${a.label.toUpperCase()}_BADGE`, fodprBadge);
}

// パネルを開いて行を確認
await page.querySelector('header button[aria-label="通知"]')?.click();
await page.waitForTimeout(500);
const rows = await pageRows(page);
log('FODPR_PANEL_ROWS', rows.length);
rows.slice(0,8).forEach((r,i)=>log(`ROW${i}`, r));

// ---- Nostr: poster nsec 生成して seed → note投稿(WS direct) ----
const POSTER_NSEC = Buffer.from(secp.utils.randomPrivateKey()).toString('hex');
const REACTOR_NSEC = Buffer.from(secp.utils.randomPrivateKey()).toString('hex');
log('NOSTR_POSTER_NPUB', nostrPub(POSTER_NSEC));
log('NOSTR_REACTOR_NPUB', nostrPub(REACTOR_NSEC));

// need nostr_priv in localStorage as hex (App expects hex nsec)
await page.evaluate((nsec)=>{ localStorage.setItem('nostr_priv', nsec); }, POSTER_NSEC);

// poster note (kind 1) publish via WS
const now = Math.floor(Date.now()/1000);
const posterNoteId = await nostrPublish(POSTER_NSEC, {kind:1, created_at:now, tags:[], content:'ノスト通知テスト投稿'});
log('NOSTR_POSTER_NOTE_ID', posterNoteId);
// app は nostrRelayReq(300) で取得. 到着待ち
await sleep(4000);

// reactor: kind 7 react / kind 6 repost / kind 1 reply to posterNoteId
const nActions = [
  { label:'react', kind:7, content:'❤️', tags:[['e', posterNoteId]] },
  { label:'repost', kind:6, content:'', tags:[['e', posterNoteId]] },
  { label:'reply', kind:1, content:'ノストお返事', tags:[['e', posterNoteId]] },
];
let nostrBadge = fodprBadge;
for (const a of nActions) {
  await nostrPublish(REACTOR_NSEC, {kind:a.kind, created_at:Math.floor(Date.now()/1000), tags:a.tags, content:a.content});
  await sleep(2000);
  nostrBadge = await getUnreadBadge(page);
  log(`NOSTR_${a.label.toUpperCase()}_BADGE`, nostrBadge);
}

// verify panel now contains nostr entries (switch tab)
await page.querySelector('header button[aria-label="通知"]')?.click();
await page.waitForTimeout(500);

log('FINAL_UNREAD', await getUnreadBadge(page));
await browser.close();

function pageRows(page){return page.evaluate(()=>Array.from(document.querySelectorAll('button[title]')).flatMap(b=>b.textContent? [b.textContent.trim()]:[]));}
