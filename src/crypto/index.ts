import { bytes, equal, lp, sha256, utf8 } from './bytes';

export type Role = 'sender' | 'receiver';

export interface SessionKeys {
  enc: CryptoKey;
  macS2R: CryptoKey;
  macR2S: CryptoKey;
  audit: CryptoKey;
}

export interface SessionContext {
  senderDev: Uint8Array;
  receiverDev: Uint8Array;
  sessionId: Uint8Array;
  senderPublic: Uint8Array;
  receiverPublic: Uint8Array;
  commitment: Uint8Array;
  senderNonce: Uint8Array;
  receiverNonce: Uint8Array;
}

function requireLength(value: Uint8Array, length: number): void {
  if (!(value instanceof Uint8Array) || value.byteLength !== length) throw new Error('INVALID_CRYPTO_INPUT');
}

/** A fresh nonextractable P-256 private key; the public point is SEC1 uncompressed. */
export async function generateEphemeral(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  return {
    privateKey: pair.privateKey,
    publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)),
  };
}

export async function importPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  requireLength(raw, 65);
  if (raw[0] !== 4) throw new Error('INVALID_PUBLIC_KEY');
  // Web Crypto validates that the point belongs to P-256 (including rejecting infinity).
  try {
    return await crypto.subtle.importKey('raw', new Uint8Array(raw).buffer, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  } catch {
    throw new Error('INVALID_PUBLIC_KEY');
  }
}

export async function sessionId(senderDev: Uint8Array, receiverDev: Uint8Array): Promise<Uint8Array> {
  requireLength(senderDev, 16);
  requireLength(receiverDev, 16);
  return (await sha256(lp(utf8('qrbeam-v1 sid'), senderDev, receiverDev))).slice(0, 16);
}

export async function commitment(nonceR: Uint8Array, pkR: Uint8Array, pkS: Uint8Array, sid: Uint8Array): Promise<Uint8Array> {
  requireLength(nonceR, 16);
  requireLength(pkR, 65);
  requireLength(pkS, 65);
  requireLength(sid, 16);
  const key = await crypto.subtle.importKey('raw', new Uint8Array(nonceR).buffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hmac(key, lp(utf8('qrbeam-v1 commit'), pkR, pkS, sid));
}

export async function hmac(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array(data).buffer));
}

export async function verifyMac(key: CryptoKey, data: Uint8Array, tag: Uint8Array, truncate = 16): Promise<boolean> {
  if (!Number.isInteger(truncate) || truncate < 16 || truncate > 32 || tag.byteLength !== truncate) return false;
  return equal((await hmac(key, data)).subarray(0, truncate), tag);
}

export async function deriveSession(
  privateKey: CryptoKey,
  peerPublic: Uint8Array | CryptoKey,
  context: SessionContext,
): Promise<{ keys: SessionKeys; transcriptHash: Uint8Array; sas: string }> {
  for (const field of ['senderDev', 'receiverDev', 'sessionId', 'senderNonce', 'receiverNonce'] as const) requireLength(context[field], 16);
  requireLength(context.senderPublic, 65);
  requireLength(context.receiverPublic, 65);
  requireLength(context.commitment, 32);
  const computedCommitment = await commitment(context.receiverNonce, context.receiverPublic, context.senderPublic, context.sessionId);
  if (!equal(computedCommitment, context.commitment)) throw new Error('COMMITMENT_MISMATCH');

  const transcriptHash = await sha256(lp(
    utf8('qrbeam-v1 transcript'), new Uint8Array([1]), utf8('sender'), utf8('receiver'),
    context.senderDev, context.receiverDev, context.sessionId, context.senderPublic,
    context.receiverPublic, context.commitment, context.senderNonce, context.receiverNonce,
  ));

  const publicKey = peerPublic instanceof Uint8Array ? await importPublicKey(peerPublic) : peerPublic;
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256));
  let hkdfKey: CryptoKey;
  try {
    hkdfKey = await crypto.subtle.importKey('raw', secret.buffer, 'HKDF', false, ['deriveKey']);
  } finally {
    secret.fill(0);
  }
  const salt = bytes(context.senderNonce, context.receiverNonce);
  const derive = (label: string, algorithm: AesDerivedKeyParams | HmacImportParams, usages: KeyUsage[]) => crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(salt).buffer, info: new Uint8Array(lp(utf8(`qrbeam-v1 ${label}`), transcriptHash)).buffer },
    hkdfKey, algorithm, false, usages,
  );
  const [enc, macS2R, macR2S, audit] = await Promise.all([
    derive('enc', { name: 'AES-GCM', length: 256 }, ['encrypt', 'decrypt']),
    derive('mac s2r', { name: 'HMAC', hash: 'SHA-256', length: 256 }, ['sign', 'verify']),
    derive('mac r2s', { name: 'HMAC', hash: 'SHA-256', length: 256 }, ['sign', 'verify']),
    derive('audit', { name: 'HMAC', hash: 'SHA-256', length: 256 }, ['sign', 'verify']),
  ]);

  const sasHash = await sha256(lp(utf8('qrbeam-v1 sas'), context.senderPublic, context.receiverPublic, context.senderNonce, context.receiverNonce, context.sessionId));
  const sasValue = new DataView(sasHash.buffer, sasHash.byteOffset, sasHash.byteLength).getBigUint64(0, false) % 1_000_000n;
  const digits = sasValue.toString().padStart(6, '0');
  return { keys: { enc, macS2R, macR2S, audit }, transcriptHash, sas: `${digits.slice(0, 3)} ${digits.slice(3)}` };
}
