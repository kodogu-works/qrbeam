import { createHash, createHmac, hkdfSync, webcrypto } from 'node:crypto';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { commitment, deriveSession, generateEphemeral, hmac, importPublicKey, sessionId, verifyMac, type SessionContext } from '../crypto';
import { bytes, equal, hex, lp, randomBytes, sha256, unhex, utf8 } from '../crypto/bytes';

beforeAll(() => {
  if (!globalThis.crypto?.subtle) vi.stubGlobal('crypto', webcrypto);
});

async function pair() {
  const sender = await generateEphemeral();
  const receiver = await generateEphemeral();
  const senderDev = randomBytes(16);
  const receiverDev = randomBytes(16);
  const sid = await sessionId(senderDev, receiverDev);
  const receiverNonce = randomBytes(16);
  const context: SessionContext = {
    senderDev, receiverDev, sessionId: sid,
    senderPublic: sender.publicKey, receiverPublic: receiver.publicKey,
    senderNonce: randomBytes(16), receiverNonce,
    commitment: await commitment(receiverNonce, receiver.publicKey, sender.publicKey, sid),
  };
  return { sender, receiver, context };
}

describe('byte encoding', () => {
  it('prefixes every transcript element with a big-endian 32-bit length', () => {
    expect(hex(lp(utf8('a'), new Uint8Array(), utf8('bc')))).toBe('000000016100000000000000026263');
    expect(equal(lp(utf8('ab'), utf8('c')), lp(utf8('a'), utf8('bc')))).toBe(false);
    expect(hex(bytes(unhex('1234'), unhex('ABCD')))).toBe('1234abcd');
  });

  it('round-trips hex and rejects malformed input', () => {
    const value = randomBytes(256);
    expect(equal(unhex(hex(value)), value)).toBe(true);
    expect(() => unhex('abc')).toThrow('INVALID_HEX');
    expect(() => unhex('ag')).toThrow('INVALID_HEX');
    expect(() => unhex('0x12')).toThrow('INVALID_HEX');
    expect(() => randomBytes(-1)).toThrow('INVALID_LENGTH');
    expect(() => randomBytes(1.5)).toThrow('INVALID_LENGTH');
  });

  it('hashes SHA-256 correctly and handles getRandomValues chunk boundaries', async () => {
    expect(hex(await sha256(utf8('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(randomBytes(65537)).toHaveLength(65537);
    expect(randomBytes(16)).not.toEqual(randomBytes(16));
  });
});

describe('P-256 and commitment', () => {
  it('exports only the public point and rejects private key extraction', async () => {
    const key = await generateEphemeral();
    expect(key.publicKey.length).toBe(65);
    expect(key.publicKey[0]).toBe(4);
    expect(key.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', key.privateKey)).rejects.toThrow();
    const imported = await importPublicKey(key.publicKey);
    expect(imported.type).toBe('public');
    expect(imported.extractable).toBe(false);
  });

  it('rejects an off-curve point, infinity, compressed points and invalid lengths', async () => {
    const offCurve = new Uint8Array(65);
    offCurve[0] = 4;
    await expect(importPublicKey(offCurve)).rejects.toThrow();
    await expect(importPublicKey(new Uint8Array([0]))).rejects.toThrow();
    const compressed = new Uint8Array(33);
    compressed[0] = 2;
    await expect(importPublicKey(compressed)).rejects.toThrow();
    const invalidFormat = new Uint8Array(65);
    invalidFormat[0] = 3;
    await expect(importPublicKey(invalidFormat)).rejects.toThrow();
  });

  it('matches independent SHA-256 and HMAC references with length-prefixed inputs', async () => {
    const { context } = await pair();
    const expectedSid = createHash('sha256').update(lp(utf8('qrbeam-v1 sid'), context.senderDev, context.receiverDev)).digest().subarray(0, 16);
    expect(hex(context.sessionId)).toBe(expectedSid.toString('hex'));
    const expectedCommit = createHmac('sha256', context.receiverNonce).update(lp(utf8('qrbeam-v1 commit'), context.receiverPublic, context.senderPublic, context.sessionId)).digest();
    expect(hex(context.commitment)).toBe(expectedCommit.toString('hex'));
    const changedSid = context.sessionId.slice();
    changedSid[0] ^= 1;
    expect(await commitment(context.receiverNonce, context.receiverPublic, context.senderPublic, changedSid)).not.toEqual(context.commitment);
  });

  it('rejects malformed nonces and session IDs', async () => {
    await expect(sessionId(new Uint8Array(15), randomBytes(16))).rejects.toThrow('INVALID_CRYPTO_INPUT');
    const { context } = await pair();
    await expect(commitment(new Uint8Array(15), context.receiverPublic, context.senderPublic, context.sessionId)).rejects.toThrow('INVALID_CRYPTO_INPUT');
  });
});

describe('session derivation', () => {
  it('gives both peers identical keys, transcript and six-digit SAS', async () => {
    const { sender, receiver, context } = await pair();
    const left = await deriveSession(sender.privateKey, receiver.publicKey, context);
    const right = await deriveSession(receiver.privateKey, await importPublicKey(sender.publicKey), context);
    expect(left.transcriptHash).toEqual(right.transcriptHash);
    expect(left.sas).toMatch(/^\d{3} \d{3}$/);
    expect(left.sas).toBe(right.sas);
    const testData = utf8('key confirmation');
    expect(await hmac(left.keys.macS2R, testData)).toEqual(await hmac(right.keys.macS2R, testData));
    expect(await hmac(left.keys.macR2S, testData)).toEqual(await hmac(right.keys.macR2S, testData));
    expect(await hmac(left.keys.audit, testData)).toEqual(await hmac(right.keys.audit, testData));
    const nonce = randomBytes(12);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(nonce).buffer }, left.keys.enc, new Uint8Array(testData).buffer);
    expect(new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(nonce).buffer }, right.keys.enc, encrypted))).toEqual(testData);
    for (const key of Object.values(left.keys)) {
      expect(key.extractable).toBe(false);
      await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
    }
  });

  it('uses the specified big-endian first eight hash bytes for SAS', async () => {
    const { sender, receiver, context } = await pair();
    const result = await deriveSession(sender.privateKey, receiver.publicKey, context);
    const hash = createHash('sha256').update(lp(utf8('qrbeam-v1 sas'), context.senderPublic, context.receiverPublic, context.senderNonce, context.receiverNonce, context.sessionId)).digest();
    const digits = (hash.readBigUInt64BE(0) % 1_000_000n).toString().padStart(6, '0');
    expect(result.sas).toBe(`${digits.slice(0, 3)} ${digits.slice(3)}`);
    const transcript = createHash('sha256').update(lp(utf8('qrbeam-v1 transcript'), new Uint8Array([1]), utf8('sender'), utf8('receiver'), context.senderDev, context.receiverDev, context.sessionId, context.senderPublic, context.receiverPublic, context.commitment, context.senderNonce, context.receiverNonce)).digest();
    expect(hex(result.transcriptHash)).toBe(transcript.toString('hex'));
  });

  it('separates direction, audit and transcript contexts', async () => {
    const { sender, receiver, context } = await pair();
    const result = await deriveSession(sender.privateKey, receiver.publicKey, context);
    const data = utf8('READY');
    const senderTag = await hmac(result.keys.macS2R, data);
    expect(senderTag).not.toEqual(await hmac(result.keys.macR2S, data));
    expect(senderTag).not.toEqual(await hmac(result.keys.audit, data));
    const changed = await deriveSession(sender.privateKey, receiver.publicKey, { ...context, senderNonce: randomBytes(16) });
    expect(changed.transcriptHash).not.toEqual(result.transcriptHash);
    expect(await hmac(changed.keys.macS2R, data)).not.toEqual(senderTag);
  });

  it('matches independent HKDF output using raw nonce salt and prefixed info', async () => {
    const { sender, receiver, context } = await pair();
    const result = await deriveSession(sender.privateKey, receiver.publicKey, context);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: await importPublicKey(receiver.publicKey) }, sender.privateKey, 256));
    const testData = utf8('HKDF known context');
    for (const [label, key] of [
      ['mac s2r', result.keys.macS2R],
      ['mac r2s', result.keys.macR2S],
      ['audit', result.keys.audit],
    ] as const) {
      const raw = hkdfSync('sha256', shared, bytes(context.senderNonce, context.receiverNonce), lp(utf8(`qrbeam-v1 ${label}`), result.transcriptHash), 32);
      expect(hex(await hmac(key, testData))).toBe(createHmac('sha256', Buffer.from(raw)).update(testData).digest('hex'));
    }
    const rawEnc = hkdfSync('sha256', shared, bytes(context.senderNonce, context.receiverNonce), lp(utf8('qrbeam-v1 enc'), result.transcriptHash), 32);
    const expectedEnc = await crypto.subtle.importKey('raw', rawEnc, 'AES-GCM', false, ['encrypt']);
    const iv = randomBytes(12);
    const encrypt = (key: CryptoKey) => crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(iv).buffer }, key, new Uint8Array(testData).buffer);
    expect(new Uint8Array(await encrypt(result.keys.enc))).toEqual(new Uint8Array(await encrypt(expectedEnc)));
    shared.fill(0);
  });

  it('refuses derivation when the revealed receiver nonce violates its commitment', async () => {
    const { sender, receiver, context } = await pair();
    await expect(deriveSession(sender.privateKey, receiver.publicKey, { ...context, receiverNonce: randomBytes(16) })).rejects.toThrow('COMMITMENT_MISMATCH');
    const alteredCommit = context.commitment.slice();
    alteredCommit[0] ^= 1;
    await expect(deriveSession(sender.privateKey, receiver.publicKey, { ...context, commitment: alteredCommit })).rejects.toThrow('COMMITMENT_MISMATCH');
  });

  it('checks 128-bit frame MACs and refuses truncated, altered and reflected tags', async () => {
    const { sender, receiver, context } = await pair();
    const { keys } = await deriveSession(sender.privateKey, receiver.publicKey, context);
    const data = utf8('authenticated frame header and payload');
    const tag = (await hmac(keys.macS2R, data)).slice(0, 16);
    expect(await verifyMac(keys.macS2R, data, tag)).toBe(true);
    expect(await verifyMac(keys.macR2S, data, tag)).toBe(false);
    expect(await verifyMac(keys.macS2R, bytes(data, new Uint8Array([0])), tag)).toBe(false);
    expect(await verifyMac(keys.macS2R, data, tag.slice(1))).toBe(false);
    expect(await verifyMac(keys.macS2R, data, tag.slice(0, 8), 8)).toBe(false);
    const full = await hmac(keys.macS2R, data);
    expect(await verifyMac(keys.macS2R, data, full, 32)).toBe(true);
  });
});
