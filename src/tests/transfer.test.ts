import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SessionKeys } from '../crypto';
import { equal, hex, lp, randomBytes, sha256, utf8 } from '../crypto/bytes';
import {
  decryptFile, encryptFile, MAX_FILE_SIZE, saveVerifiedFile, type EncryptedFile, type WritableFile,
} from '../transfer';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function keys(): Promise<SessionKeys> {
  const enc = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const mac = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return { enc, macS2R: mac, macR2S: mac, audit: mac };
}

async function fixture(data = utf8('private sample')) {
  const sessionKeys = await keys();
  const sid = randomBytes(16);
  const encrypted = await encryptFile({ name: 'private-name.txt', data }, sessionKeys, sid);
  return { sessionKeys, sid, encrypted, verified: await decryptFile(encrypted, sessionKeys, sid) };
}

afterEach(() => vi.unstubAllGlobals());

describe('authenticated file envelopes', () => {
  it.each([0, 257, MAX_FILE_SIZE])('round trips %i bytes with encrypted metadata and 4 KiB padding', async (length) => {
    const data = new Uint8Array(length);
    for (let i = 0; i < data.length; i++) data[i] = (i * 73 + 19) % 256;
    const { encrypted, verified } = await fixture(data);
    expect(verified.data).toEqual(data);
    expect(verified.name).toBe('private-name.txt');
    expect(encrypted.nonce.length).toBe(12);
    expect(encrypted.transferId.length).toBe(16);
    expect((encrypted.ciphertext.length - 16) % 4096).toBe(0);
    expect(encrypted.digest).toEqual(verified.digest);
    expect(equal(encrypted.digest, await sha256(data))).toBe(false);
    const visible = new TextDecoder().decode(encrypted.ciphertext);
    expect(visible).not.toContain('private-name.txt');
    expect(visible).not.toContain(hex(await sha256(data)));
  });

  it('enforces the size and UTF-8 filename limits before encrypting', async () => {
    const sessionKeys = await keys();
    const sid = randomBytes(16);
    await expect(encryptFile({ name: 'large', data: new Uint8Array(MAX_FILE_SIZE + 1) }, sessionKeys, sid)).rejects.toThrow('file-too-large');
    await expect(encryptFile({ name: '界'.repeat(86), data: new Uint8Array() }, sessionKeys, sid)).rejects.toThrow('invalid-filename');
    await expect(encryptFile({ name: '\ud800', data: new Uint8Array() }, sessionKeys, sid)).rejects.toThrow('invalid-filename');
    const encrypted = await encryptFile({ name: '界'.repeat(85), data: new Uint8Array() }, sessionKeys, sid);
    expect((await decryptFile(encrypted, sessionKeys, sid)).name).toBe('界'.repeat(85));
  });

  it('permits only one encryption attempt per session encryption key', async () => {
    const { sessionKeys, sid } = await fixture();
    await expect(encryptFile({ name: 'another', data: new Uint8Array() }, sessionKeys, sid)).rejects.toThrow('encryption-key-already-used');
    const fresh = await fixture();
    expect(equal(fresh.encrypted.nonce, (await fixture()).encrypted.nonce)).toBe(false);
  });

  it('rejects ciphertext changes, nonce changes, and mixed session/transfer contexts', async () => {
    const { sessionKeys, sid, encrypted } = await fixture();
    const ciphertext = encrypted.ciphertext.slice();
    ciphertext[10] ^= 1;
    await expect(decryptFile({ ...encrypted, ciphertext }, sessionKeys, sid)).rejects.toThrow('authentication-failed');
    await expect(decryptFile({ ...encrypted, nonce: randomBytes(12) }, sessionKeys, sid)).rejects.toThrow('authentication-failed');
    await expect(decryptFile({ ...encrypted, transferId: randomBytes(16) }, sessionKeys, sid)).rejects.toThrow('authentication-failed');
    await expect(decryptFile(encrypted, sessionKeys, randomBytes(16))).rejects.toThrow('authentication-failed');
    await expect(decryptFile({ ...encrypted, ciphertext: new Uint8Array(2_000_000) }, sessionKeys, sid)).rejects.toThrow('invalid-ciphertext');
  });

  it('rejects authenticated metadata with a wrong plaintext hash', async () => {
    const sessionKeys = await keys();
    const sid = randomBytes(16);
    const transferId = randomBytes(16);
    const nonce = randomBytes(12);
    const body = utf8('authentic ciphertext, incorrect metadata');
    const metadata = utf8(JSON.stringify({ v: 1, name: 'test', size: body.length, sha256: '00'.repeat(32) }));
    const plaintext = new Uint8Array(4096);
    new DataView(plaintext.buffer).setUint32(0, metadata.length);
    plaintext.set(metadata, 4);
    plaintext.set(body, 4 + metadata.length);
    const aad = lp(utf8('qrbeam-v1 file'), new Uint8Array([1]), sid, transferId);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, sessionKeys.enc, plaintext,
    ));
    await expect(decryptFile({ transferId, nonce, ciphertext }, sessionKeys, sid)).rejects.toThrow('hash-mismatch');
  });

  it('normalizes an unsafe authenticated filename before suggesting it for saving', async () => {
    const sessionKeys = await keys();
    const sid = randomBytes(16);
    const encrypted = await encryptFile({ name: 'con.txt. ', data: new Uint8Array() }, sessionKeys, sid);
    expect((await decryptFile(encrypted, sessionKeys, sid)).name).toBe('_con.txt');
  });
});

describe('observable File System Access saving', () => {
  it('resolves only after close successfully commits the bytes', async () => {
    const { verified } = await fixture();
    let closeResolve: (() => void) | undefined;
    const writable: WritableFile = {
      write: vi.fn(async () => {}),
      close: vi.fn(() => new Promise<void>((resolve) => { closeResolve = resolve; })),
    };
    const picker = vi.fn(async () => ({ createWritable: async () => writable }));
    vi.stubGlobal('showSaveFilePicker', picker);
    let completed = false;
    const saving = saveVerifiedFile(verified).then(() => { completed = true; });
    await vi.waitFor(() => expect(writable.close).toHaveBeenCalledOnce());
    expect(completed).toBe(false);
    expect(writable.write).toHaveBeenCalledWith(verified.data);
    closeResolve!();
    await saving;
    expect(completed).toBe(true);
    expect(picker).toHaveBeenCalledWith({ suggestedName: verified.name });
  });

  it('rejects cancellation and write/close failures, then permits an explicit retry', async () => {
    const { verified } = await fixture();
    vi.stubGlobal('showSaveFilePicker', vi.fn(async () => { throw new DOMException('sensitive filename', 'AbortError'); }));
    await expect(saveVerifiedFile(verified)).rejects.toThrow('save-cancelled');
    const abort = vi.fn(async () => {});
    const writable: WritableFile = {
      write: vi.fn(async () => {}),
      close: vi.fn(async () => { throw new Error('sensitive disk path'); }), abort,
    };
    vi.stubGlobal('showSaveFilePicker', vi.fn(async () => ({ createWritable: async () => writable })));
    await expect(saveVerifiedFile(verified)).rejects.toThrow('save-failed');
    expect(abort).toHaveBeenCalledOnce();
    writable.close = vi.fn(async () => {});
    writable.write = vi.fn(async () => { throw new Error('sensitive write destination'); });
    await expect(saveVerifiedFile(verified)).rejects.toThrow('save-failed');
    expect(writable.close).not.toHaveBeenCalled();
    writable.write = vi.fn(async () => {});
    await expect(saveVerifiedFile(verified)).resolves.toBeUndefined();
  });

  it('requires both verified contents and a supported save API', async () => {
    await expect(saveVerifiedFile({ name: 'x', data: new Uint8Array(), digest: new Uint8Array(32) })).rejects.toThrow('file-not-verified');
    const { verified } = await fixture();
    vi.stubGlobal('showSaveFilePicker', undefined);
    await expect(saveVerifiedFile(verified)).rejects.toThrow('unsupported-save');
  });

  it('does not open a picker for an already ended session', async () => {
    const { verified } = await fixture();
    const picker = vi.fn();
    vi.stubGlobal('showSaveFilePicker', picker);
    const controller = new AbortController();
    controller.abort('sensitive abort reason');
    await expect(saveVerifiedFile(verified, controller.signal)).rejects.toThrow('save-session-ended');
    expect(picker).not.toHaveBeenCalled();
  });

  it('never writes a zeroed file when the session ends while the picker is open', async () => {
    const { verified } = await fixture();
    const controller = new AbortController();
    const writable: WritableFile = {
      write: vi.fn(async () => {}), close: vi.fn(async () => {}), abort: vi.fn(async () => {}),
    };
    const handle = { createWritable: vi.fn(async () => writable) };
    const chosen = deferred<typeof handle>();
    vi.stubGlobal('showSaveFilePicker', vi.fn(() => chosen.promise));
    const saving = saveVerifiedFile(verified, controller.signal);
    const result = expect(saving).rejects.toThrow('save-session-ended');
    controller.abort();
    verified.data.fill(0);
    chosen.resolve(handle);
    await result;
    expect(handle.createWritable).not.toHaveBeenCalled();
    expect(writable.write).not.toHaveBeenCalled();
    expect(writable.close).not.toHaveBeenCalled();
  });

  it('aborts a late writable without writing when the session ended during its creation', async () => {
    const { verified } = await fixture();
    const controller = new AbortController();
    const writable: WritableFile = {
      write: vi.fn(async () => {}), close: vi.fn(async () => {}), abort: vi.fn(async () => {}),
    };
    const created = deferred<WritableFile>();
    const createWritable = vi.fn(() => created.promise);
    vi.stubGlobal('showSaveFilePicker', vi.fn(async () => ({ createWritable })));
    const saving = saveVerifiedFile(verified, controller.signal);
    const result = expect(saving).rejects.toThrow('save-session-ended');
    await vi.waitFor(() => expect(createWritable).toHaveBeenCalledOnce());
    controller.abort();
    verified.data.fill(0);
    created.resolve(writable);
    await result;
    expect(writable.abort).toHaveBeenCalledOnce();
    expect(writable.write).not.toHaveBeenCalled();
    expect(writable.close).not.toHaveBeenCalled();
  });

  it('aborts pending writes and never closes after session cancellation', async () => {
    const { verified } = await fixture();
    const controller = new AbortController();
    const written = deferred<void>();
    const writable: WritableFile = {
      write: vi.fn(() => written.promise), close: vi.fn(async () => {}), abort: vi.fn(async () => {}),
    };
    vi.stubGlobal('showSaveFilePicker', vi.fn(async () => ({ createWritable: async () => writable })));
    const saving = saveVerifiedFile(verified, controller.signal);
    const result = expect(saving).rejects.toThrow('save-session-ended');
    await vi.waitFor(() => expect(writable.write).toHaveBeenCalledOnce());
    controller.abort();
    expect(writable.abort).toHaveBeenCalledOnce();
    verified.data.fill(0);
    written.resolve();
    await result;
    expect(writable.close).not.toHaveBeenCalled();
    expect(writable.abort).toHaveBeenCalledOnce();
  });

  it('does not report success if the session ends during an already started close', async () => {
    const { verified } = await fixture();
    const controller = new AbortController();
    const closed = deferred<void>();
    const writable: WritableFile = {
      write: vi.fn(async () => {}), close: vi.fn(() => closed.promise), abort: vi.fn(async () => {}),
    };
    vi.stubGlobal('showSaveFilePicker', vi.fn(async () => ({ createWritable: async () => writable })));
    const saving = saveVerifiedFile(verified, controller.signal);
    const result = expect(saving).rejects.toThrow('save-session-ended');
    await vi.waitFor(() => expect(writable.close).toHaveBeenCalledOnce());
    controller.abort();
    closed.resolve();
    await result;
    expect(writable.abort).toHaveBeenCalledOnce();
  });
});
