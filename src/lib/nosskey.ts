// NIP-79 "Passkey-Wrapped Keys a.k.a. Nosskey" — nosskey-sdk wrapper.
// This module provides a high-level interface for Nosskey using the nosskey-sdk package.

import { NosskeyManager, bytesToHex, hexToBytes } from 'nosskey-sdk';

export interface NosskeyCred {
  credId: string; // hex
  pubkey: string; // HEX
}

// Initialize the NosskeyManager with options for our domain
function getNosskeyManager(): NosskeyManager {
  // Determine rpId based on hostname
  let rpId = location.hostname;
  if (location.hostname.includes('nosskey-sdk.pages.dev')) {
    rpId = 'nosskey-sdk.pages.dev';
  } else if (location.hostname.includes('nosskey.app')) {
    rpId = 'nosskey.app';
  }

  return new NosskeyManager({
    prfOptions: {
      rpId,
      userVerification: 'required',
    },
    storageOptions: {
      enabled: true,
      storageKey: 'nosskey_pwk',
    },
    cacheOptions: {
      enabled: true,
      timeoutMs: 60 * 1000,
    },
  });
}

// Check if Nosskey (WebAuthn PRF) is supported
export function nosskeySupported(): boolean {
  if (typeof window === 'undefined') return false;
  const c = (window as unknown as { PublicKeyCredential?: unknown }).PublicKeyCredential;
  const n = window.navigator?.credentials;
  return typeof c === 'function' && typeof n?.get === 'function' && typeof n?.create === 'function';
}

// Create a new Nosskey passkey and generate a new Nostr key (PRF direct mode)
export async function registerNosskeyPasskey(): Promise<{
  privKey: string;
  pubkey: string;
  credId: string;
}> {
  const manager = getNosskeyManager();
  
  // Create a new passkey (this will show the device's passkey UI)
  const credentialId = await manager.createPasskey();
  
  // Create Nostr key from PRF (direct mode - PRF output becomes the private key)
  const keyInfo = await manager.createNostrKey(credentialId);
  manager.setCurrentKeyInfo(keyInfo);
  
  const pubkey = await manager.getPublicKey();
  // Get the private key by exporting
  const privKey = await manager.exportNostrKey(keyInfo, credentialId);
  
  return { privKey, pubkey, credId: bytesToHex(credentialId) };
}

// Login with existing Nosskey passkey (PRF direct mode)
export async function loginNosskeyPasskey(): Promise<{
  privKey: string;
  pubkey: string;
}> {
  const manager = getNosskeyManager();
  
  // Get the stored key info to find the credential
  const keyInfo = manager.getCurrentKeyInfo();
  if (!keyInfo) {
    throw new Error('Nosskey credential not found. Please register first.');
  }
  
  // Set the current key info (loads from storage if needed)
  manager.setCurrentKeyInfo(keyInfo);
  
  // Get public key
  const pubkey = await manager.getPublicKey();
  
  // Export private key (will trigger WebAuthn authentication)
  const credentialId = hexToBytes(keyInfo.credentialId);
  const privKey = await manager.exportNostrKey(keyInfo, credentialId);
  
  return { privKey, pubkey };
}

// Save existing nsec to Nosskey (wrap mode - encrypts nsec with PRF-derived KEK)
export async function saveNsecToNosskey(nsecHex: string): Promise<{
  pubkey: string;
  credId: string;
}> {
  const manager = getNosskeyManager();
  
  // Create a new passkey
  const credentialId = await manager.createPasskey();
  
  // Import existing nsec (wrap mode - encrypts nsec with PRF-derived KEK)
  const seckey = hexToBytes(nsecHex);
  const keyInfo = await manager.importNostrKey(seckey, credentialId);
  manager.setCurrentKeyInfo(keyInfo);
  
  const pubkey = await manager.getPublicKey();
  
  return { pubkey, credId: bytesToHex(credentialId) };
}

// Sign an event using Nosskey
export async function signNostrEventWithNosskey(event: {
  kind: number;
  tags: string[][];
  content: string;
  created_at: number;
}): Promise<{
  id: string;
  pubkey: string;
  sig: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}> {
  const manager = getNosskeyManager();
  const keyInfo = manager.getCurrentKeyInfo();
  if (!keyInfo) {
    throw new Error('Nosskey not initialized. Please login first.');
  }
  
  const signed = await manager.signEvent(event);
  // The SDK's NostrEvent may have optional id, but after signing it should be present
  return signed as {
    id: string;
    pubkey: string;
    sig: string;
    created_at: number;
    kind: number;
    tags: string[][];
    content: string;
  };
}

// Get public key from Nosskey
export async function getNosskeyPublicKey(): Promise<string> {
  const manager = getNosskeyManager();
  const keyInfo = manager.getCurrentKeyInfo();
  if (!keyInfo) {
    throw new Error('Nosskey not initialized');
  }
  return manager.getPublicKey();
}

// Check if Nosskey credential is stored
export function hasNosskeyCredential(): boolean {
  const manager = getNosskeyManager();
  return manager.hasKeyInfo();
}

// Get stored Nosskey credential info
export function getStoredNosskeyCred(): NosskeyCred | null {
  const manager = getNosskeyManager();
  const keyInfo = manager.getCurrentKeyInfo();
  if (!keyInfo) return null;
  
  return {
    credId: keyInfo.credentialId,
    pubkey: keyInfo.pubkey,
  };
}

// Clear Nosskey credential (for switching accounts)
export function clearNosskeyCredential(): void {
  const manager = getNosskeyManager();
  manager.clearStoredKeyInfo();
}

// Clear current Nosskey session (logout but keep credential for re-login)
export function clearNosskeySession(): void {
  const manager = getNosskeyManager();
  manager.clearCurrentKeyInfo();
}