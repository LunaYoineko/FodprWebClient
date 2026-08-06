// bech32.ts
// --------
// BIP-173 (Bech32) のデコード。サーバー側(Nim の crypto.nim)と同一の
// アルゴリズムで "fsec1..." 形式の秘密鍵を 32 バイトの生鍵へ復元する。

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if (((top >> i) & 1) !== 0) {
        chk ^= GENERATOR[i];
      }
    }
  }
  return chk;
}

function expandHrp(hrp: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const maxv = (1 << toBits) - 1;
  const out: number[] = [];
  for (const b of data) {
    acc = (acc << fromBits) | b;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >>> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error('Invalid padding in convertBits');
  }
  return out;
}

export function bech32Decode(bechStr: string, expectedHrp: string): Uint8Array {
  if (bechStr.length < 8) throw new Error('Bech32 string too short');

  const pos = bechStr.lastIndexOf('1');
  if (pos === -1 || pos < 1 || pos + 7 > bechStr.length) throw new Error('Invalid Bech32 format');

  const hrp = bechStr.slice(0, pos).toLowerCase();
  if (hrp !== expectedHrp.toLowerCase()) throw new Error('HRP mismatch: expected ' + expectedHrp);

  const data: number[] = [];
  for (let i = pos + 1; i < bechStr.length; i++) {
    const idx = CHARSET.indexOf(bechStr[i]);
    if (idx === -1) throw new Error('Invalid character in Bech32 string');
    data.push(idx);
  }

  const pm = polymod([...expandHrp(hrp), ...data]);
  if (pm !== 1) throw new Error('Invalid checksum');

  const decoded5bit = data.slice(0, data.length - 6);
  return Uint8Array.from(convertBits(decoded5bit, 5, 8, false));
}

// "fsec1..." の Bech32 秘密鍵を 32 バイトの HEX 文字列へ変換する。
export function fsecToHex(fsec: string): string {
  const bytes = bech32Decode(fsec.trim(), 'fsec');
  if (bytes.length !== 32) throw new Error('Invalid private key length');
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// 32 バイトの秘密鍵 HEX を "fsec1..." の Bech32 文字列へ変換する。
// (サーバー側 crypto.nim の bech32Encode と同一アルゴリズム)
export function hexToFsec(secretHex: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < secretHex.length; i += 2) {
    bytes.push(parseInt(secretHex.slice(i, i + 2), 16));
  }
  const converted = convertBits(bytes, 8, 5, true);
  const pm = polymod([...expandHrp('fsec'), ...converted, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum: number[] = new Array(6);
  for (let i = 0; i < 6; i++) {
    checksum[5 - i] = (pm >>> (i * 5)) & 31;
  }
  return (
    'fsec1' + [...converted, ...checksum].map((v) => CHARSET[v]).join('')
  );
}
