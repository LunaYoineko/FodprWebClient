// keystore.ts
// -----------
// 秘密鍵を「暗号化して」ブラウザへ保存するユーティリティ。
//
// 方針(パスワード不要で暗号化を実現する):
//  - 秘密鍵は AES-256-GCM で暗号化して localStorage に保存する。
//  - 復号用の AES 鍵は WebCrypto で生成した「非エクスポート可能」(extractable:
//    false) な CryptoKey として IndexedDB に保存する。
//  - これにより localStorage の中身が持ち出されても暗号文しか読めず、
//    非エクスポート鍵は JS から生バイトとして取り出せない。
//  - パスワードは不要で、次回アクセス時も自動で復号してログインできる。
//    (同一オリジンのスクリプトからは復号自体は可能だが、localStorage の
//     平文露出や開発者ツールでの一覧表示による流出リスクを下げられる)

// Fodpr(fsec)用と Nostr(nsec)用で別々の保管場所を使う。
const STORAGE_KEY = 'fodpr_vault'; // Fodpr fsec
const LEGACY_STORAGE_KEY = 'fodpr_priv'; // 旧仕様: 平文で秘密鍵を保存していたキー
const NOSTR_STORAGE_KEY = 'nostr_vault'; // Nostr nsec
const DB_NAME = 'fodpr';
const DB_STORE = 'keys';
const DB_KEY = 'aes'; // Fodpr の復号鍵
const NOSTR_DB_KEY = 'aes_nostr'; // Nostr の復号鍵

interface Vault {
  v: 2;
  iv: string; // base64 (12 bytes)
  data: string; // base64 (AES-GCM ciphertext)
}

function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// IndexedDB のストアキーは DB_KEY / NOSTR_DB_KEY を別々に使い、
// localStorage の保管場所も分離することで fsec と nsec を独立して扱う。
function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(DB_STORE)) {
        req.result.createObjectStore(DB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed'));
  });
}

function dbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

async function getAesKey(db: IDBDatabase, key: string): Promise<CryptoKey | null> {
  const tx = db.transaction(DB_STORE, 'readonly');
  const value = await dbRequest(tx.objectStore(DB_STORE).get(key));
  return (value as CryptoKey | undefined) ?? null;
}

async function putAesKey(db: IDBDatabase, key: string, aes: CryptoKey): Promise<void> {
  const tx = db.transaction(DB_STORE, 'readwrite');
  tx.objectStore(DB_STORE).put(aes, key);
  await dbRequest(tx.objectStore(DB_STORE).get(key)).catch(() => undefined);
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB write failed'));
  });
}

async function deleteAesKey(db: IDBDatabase, key: string): Promise<void> {
  const tx = db.transaction(DB_STORE, 'readwrite');
  tx.objectStore(DB_STORE).delete(key);
  await new Promise<void>((resolve) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => resolve(); // 削除失敗は無視
  });
}

// 秘密鍵(HEX)を暗号化して保存する。呼び出し時点で IndexedDB / localStorage を初期化する
async function saveSecretFor(
  storageKey: string,
  dbKey: string,
  secretHex: string,
): Promise<void> {
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false, // extractable: false 非エクスポート可能
    ['encrypt', 'decrypt'],
  );
  const db = await openDb();
  await putAesKey(db, dbKey, aesKey);
  db.close();

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(secretHex),
  );
  const vault: Vault = {
    v: 2,
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(ciphertext)),
  };
  localStorage.setItem(storageKey, JSON.stringify(vault));
}

// 保存された秘密鍵を復号して返す。失敗時や未保存時は null
async function loadSecretFor(storageKey: string, dbKey: string): Promise<string | null> {
  const raw = localStorage.getItem(storageKey);
  if (!raw) return null;
  let vault: Vault;
  try {
    vault = JSON.parse(raw) as Vault;
  } catch {
    localStorage.removeItem(storageKey);
    return null;
  }
  let db: IDBDatabase | null = null;
  try {
    db = await openDb();
    const aesKey = await getAesKey(db, dbKey);
    if (!aesKey) {
      localStorage.removeItem(storageKey);
      return null;
    }
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(vault.iv) },
      aesKey,
      fromBase64(vault.data),
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    localStorage.removeItem(storageKey);
    return null;
  } finally {
    db?.close();
  }
}

// 保存済みの鍵を削除する(ログアウト)
async function clearSecretFor(storageKey: string, dbKey: string): Promise<void> {
  localStorage.removeItem(storageKey);
  try {
    const db = await openDb();
    await deleteAesKey(db, dbKey);
    db.close();
  } catch {
    /* IndexedDB が使えない環境では localStorage の削除のみ行う */
  }
}

// ── Fodpr (fsec) ──
export async function saveSecret(secretHex: string): Promise<void> {
  await saveSecretFor(STORAGE_KEY, DB_KEY, secretHex);
}

export async function loadSecret(): Promise<string | null> {
  return loadSecretFor(STORAGE_KEY, DB_KEY);
}

export async function clearSecret(): Promise<void> {
  await clearSecretFor(STORAGE_KEY, DB_KEY);
}

// ── Nostr (nsec) ──
export async function saveNostrSecret(secretHex: string): Promise<void> {
  await saveSecretFor(NOSTR_STORAGE_KEY, NOSTR_DB_KEY, secretHex);
}

export async function loadNostrSecret(): Promise<string | null> {
  return loadSecretFor(NOSTR_STORAGE_KEY, NOSTR_DB_KEY);
}

export async function clearNostrSecret(): Promise<void> {
  await clearSecretFor(NOSTR_STORAGE_KEY, NOSTR_DB_KEY);
}

// 旧仕様(平文保存)のキーを掃除して暗号化保存へ移行する。
// 移行後は平文をローカルストレージに残さない。
export async function migrateLegacySecret(): Promise<string | null> {
  const legacy = localStorage.getItem(LEGACY_STORAGE_KEY);
  if (!legacy) return null;
  const hex = legacy.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    localStorage.removeItem(LEGACY_STORAGE_KEY);
    return null;
  }
  await saveSecret(hex);
  localStorage.removeItem(LEGACY_STORAGE_KEY);
  return hex;
}
