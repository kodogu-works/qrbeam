import { describe, expect, it } from 'vitest';
import { encodeBase45, decodeBase45 } from '../qr/base45';
import { authenticateFrame, crc32, decodeFrame, encodeFrame, MessageType, ZERO_SESSION } from '../protocol/frame';
import { utf8 } from '../crypto/bytes';

describe('Base45 and binary optical frames', () => {
  it('matches RFC 9285 vectors and preserves significant spaces', () => {
    expect(encodeBase45(utf8('AB'))).toBe('BB8');
    expect(encodeBase45(utf8('Hello!!'))).toBe('%69 VD92EX0');
    expect(new TextDecoder().decode(decodeBase45('UJCLQE7W581'))).toBe('base-45');
    for (let length = 0; length < 257; length++) {
      const value = Uint8Array.from({ length }, (_, i) => (i * 37 + length) & 255);
      expect(decodeBase45(encodeBase45(value))).toEqual(value);
    }
  });
  it('rejects invalid alphabet, noncanonical overflow, remainder and oversize', () => {
    for (const value of ['A', 'a0', ':::','::','00\n','0'.repeat(8193)]) expect(() => decodeBase45(value)).toThrow();
  });
  it('uses the standard CRC-32 vector', () => {
    expect(crc32(utf8('123456789'))).toBe(0xcbf43926);
  });
  it('authenticates the entire header and payload with a direction-specific key', async () => {
    const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    const other = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    const text = await encodeFrame({ type: MessageType.READY, sessionId: ZERO_SESSION, sequence: 0xffffffff, payload: utf8('test') }, key);
    const frame = decodeFrame(text);
    expect(frame.sequence).toBe(0xffffffff);
    expect(await authenticateFrame(frame, key)).toBe(true);
    expect(await authenticateFrame(frame, other)).toBe(false);
    frame.signedBytes[23] ^= 1;
    expect(await authenticateFrame(frame, key)).toBe(false);
  });
  it('rejects corruption, trailing bytes, unsupported flags and unsigned impersonation', async () => {
    const text = await encodeFrame({ type: MessageType.HELLO, sessionId: ZERO_SESSION, sequence: 4, payload: utf8('hello') });
    const raw = decodeBase45(text);
    const damaged = raw.slice(); damaged[30] ^= 1;
    expect(() => decodeFrame(encodeBase45(damaged))).toThrow();
    expect(() => decodeFrame(text + '00')).toThrow();
    const key = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    expect(await authenticateFrame(decodeFrame(text), key)).toBe(false);
  });
});
