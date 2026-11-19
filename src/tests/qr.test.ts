import jsQR from 'jsqr';
import { describe, expect, it } from 'vitest';
import { qrImage } from '../../scripts/qr-image';
import { decodeBase45, encodeBase45 } from '../qr/base45';
import { authenticateFrame, decodeFrame, encodeFrame, MessageType } from '../protocol/frame';
import { utf8 } from '../crypto/bytes';

describe('Base45 text encoding', () => {
  it('matches RFC 9285 examples and byte boundary cases', () => {
    for (const [plain, encoded] of [
      ['AB', 'BB8'], ['Hello!!', '%69 VD92EX0'], ['base-45', 'UJCLQE7W581'],
    ]) {
      expect(encodeBase45(utf8(plain))).toBe(encoded);
      expect(decodeBase45(encoded)).toEqual(utf8(plain));
    }
    expect(encodeBase45(new Uint8Array([0]))).toBe('00');
    expect(encodeBase45(new Uint8Array([255]))).toBe('U5');
    expect(encodeBase45(new Uint8Array([255, 255]))).toBe('FGW');
    expect(encodeBase45(new Uint8Array([0, 36]))).toBe(' 00');
    expect(decodeBase45(' 00')).toEqual(new Uint8Array([0, 36]));
    expect(decodeBase45('')).toEqual(new Uint8Array());
  });

  it('preserves every binary byte across odd and even lengths', () => {
    for (const length of [1, 2, 255, 256, 511, 512, 768]) {
      const input = Uint8Array.from({ length }, (_, index) => index & 255);
      expect(decodeBase45(encodeBase45(input))).toEqual(input);
    }
  });

  it('rejects invalid alphabet, impossible lengths, overflow and oversized input', () => {
    for (const input of ['A', '0000', 'abc', '__', ':::', 'ZZ', '\n00', '0'.repeat(8193)]) {
      expect(() => decodeBase45(input)).toThrow('INVALID_BASE45');
    }
  });
});

describe('bundled QR encoder/decoder interoperability', () => {
  for (const payloadBytes of [128, 256, 512, 768]) {
    it(`round-trips an authenticated ${payloadBytes}-byte binary DATA payload`, async () => {
      const key = await crypto.subtle.importKey('raw', new Uint8Array(32).fill(9), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
      const payload = Uint8Array.from({ length: payloadBytes }, (_, index) => index & 255);
      const text = await encodeFrame({ type: MessageType.DATA, sessionId: new Uint8Array(16).fill(7), sequence: 42, payload }, key);
      const image = qrImage(text);
      const detected = jsQR(image.pixels, image.width, image.height, { inversionAttempts: 'dontInvert' });
      expect(detected?.data).toBe(text);
      // Both raw text (BarcodeDetector) and the bundled decoder feed the same parser.
      const frame = decodeFrame(detected!.data);
      expect(frame.payload).toEqual(payload);
      expect(frame.sequence).toBe(42);
      expect(await authenticateFrame(frame, key)).toBe(true);
    });
  }

  it('preserves significant Base45 whitespace through QR decoding', () => {
    const text = encodeBase45(new Uint8Array([0, 36, 0, 36, 255]));
    const image = qrImage(text);
    const detected = jsQR(image.pixels, image.width, image.height);
    expect(detected?.data).toBe(text);
    expect(decodeBase45(detected!.data)).toEqual(new Uint8Array([0, 36, 0, 36, 255]));
  });
});
