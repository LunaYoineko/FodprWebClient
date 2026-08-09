import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import { bech32 } from '@scure/base';
const priv = secp.utils.randomSecretKey();
const pub = secp.getPublicKey(priv, true);
const hex = (u) => Buffer.from(u).toString('hex');
const nsec = bech32.encode('nsec', bech32.toWords(priv));
const npub = bech32.encode('npub', bech32.toWords(pub));
console.log(JSON.stringify({ hex: hex(priv), nsec, npub: npub }));
