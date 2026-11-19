import { equal, hex, lp, randomBytes, sha256, utf8 } from '../crypto/bytes';
import { hmac, type SessionKeys } from '../crypto';
import { safeFilename } from '../security/filename';

export const MAX_FILE_SIZE = 1_048_576;
export const MAX_FILENAME_BYTES = 255;
export const MAX_METADATA_BYTES = 2048;
// Maximum ciphertext with the initial 4 KiB padding policy, including GCM's tag.
export const MAX_CIPHERTEXT_SIZE = 1_052_688;
const usedEncryptionKeys = new WeakSet<CryptoKey>();
const verifiedFiles = new WeakSet<VerifiedFile>();
const decoder = new TextDecoder('utf-8', { fatal: true });

export type FileInput = { name: string; data: Uint8Array };
export type EncryptedFile = {
  transferId: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  digest: Uint8Array;
};
export type VerifiedFile = { name: string; data: Uint8Array; digest: Uint8Array };

export class TransferError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = 'TransferError';
  }
}

function paddedLength(length: number, block: number): number {
  if (!Number.isSafeInteger(block) || block < 0 || block > 65_536) {
    throw new TransferError('invalid-padding');
  }
  return block ? Math.ceil(length / block) * block : length;
}

function associatedData(sid: Uint8Array, transferId: Uint8Array): Uint8Array {
  if (sid.length !== 16 || transferId.length !== 16) throw new TransferError('invalid-context');
  return lp(utf8('qrbeam-v1 file'), new Uint8Array([1]), sid, transferId);
}

function validateName(name: unknown): asserts name is string {
  if (typeof name !== 'string' || !name || utf8(name).length > MAX_FILENAME_BYTES) {
    throw new TransferError('invalid-filename');
  }
  if (decoder.decode(utf8(name)) !== name) throw new TransferError('invalid-filename');
}

export async function encryptFile(
  file: FileInput,
  keys: SessionKeys,
  sid: Uint8Array,
  paddingBlock = 4096,
): Promise<EncryptedFile> {
  validateName(file.name);
  const name = file.name;
  if (!(file.data instanceof Uint8Array) || file.data.length > MAX_FILE_SIZE) {
    throw new TransferError('file-too-large');
  }
  if (usedEncryptionKeys.has(keys.enc)) throw new TransferError('encryption-key-already-used');
  const transferId = randomBytes(16);
  const aad = associatedData(sid, transferId);
  // Copy once so that a caller cannot change bytes during asynchronous hashing/encryption.
  const body = file.data.slice();
  let plaintext: Uint8Array | undefined;
  try {
    const hash = await sha256(body);
    const metadata = utf8(JSON.stringify({ v: 1, name, size: body.length, sha256: hex(hash) }));
    if (metadata.length > MAX_METADATA_BYTES) throw new TransferError('invalid-metadata');
    const length = paddedLength(4 + metadata.length + body.length, paddingBlock);
    // Mark before the encrypt call: even a failed attempt must not reuse this session key.
    if (usedEncryptionKeys.has(keys.enc)) throw new TransferError('encryption-key-already-used');
    usedEncryptionKeys.add(keys.enc);
    plaintext = new Uint8Array(length);
    new DataView(plaintext.buffer).setUint32(0, metadata.length, false);
    plaintext.set(metadata, 4);
    plaintext.set(body, 4 + metadata.length);
    const nonce = randomBytes(12);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, keys.enc, plaintext,
    ));
    return { transferId, nonce, ciphertext, digest: await hmac(keys.audit, body) };
  } finally {
    body.fill(0);
    plaintext?.fill(0);
  }
}

export async function decryptFile(
  encrypted: Pick<EncryptedFile, 'transferId' | 'nonce' | 'ciphertext'>,
  keys: SessionKeys,
  sid: Uint8Array,
  paddingBlock = 4096,
): Promise<VerifiedFile> {
  const aad = associatedData(sid, encrypted.transferId);
  const maximum = paddedLength(4 + MAX_METADATA_BYTES + MAX_FILE_SIZE, paddingBlock) + 16;
  if (encrypted.nonce.length !== 12 || encrypted.ciphertext.length < 20 || encrypted.ciphertext.length > maximum) {
    throw new TransferError('invalid-ciphertext');
  }
  let plaintext: Uint8Array | undefined;
  try {
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: encrypted.nonce, additionalData: aad, tagLength: 128 },
        keys.enc, encrypted.ciphertext,
      ));
    } catch {
      throw new TransferError('authentication-failed');
    }
    if (plaintext.length < 4) throw new TransferError('invalid-envelope');
    const metadataLength = new DataView(plaintext.buffer).getUint32(0, false);
    if (metadataLength < 1 || metadataLength > MAX_METADATA_BYTES || 4 + metadataLength > plaintext.length) {
      throw new TransferError('invalid-envelope');
    }
    let metadata: Record<string, unknown>;
    try {
      metadata = JSON.parse(decoder.decode(plaintext.subarray(4, 4 + metadataLength))) as Record<string, unknown>;
    } catch {
      throw new TransferError('invalid-metadata');
    }
    if (!metadata || typeof metadata !== 'object' || metadata.v !== 1 ||
        !Number.isSafeInteger(metadata.size) || (metadata.size as number) < 0 || (metadata.size as number) > MAX_FILE_SIZE ||
        typeof metadata.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(metadata.sha256)) {
      throw new TransferError('invalid-metadata');
    }
    validateName(metadata.name);
    const bodyEnd = 4 + metadataLength + (metadata.size as number);
    if (bodyEnd > plaintext.length || paddedLength(bodyEnd, paddingBlock) !== plaintext.length ||
        plaintext.subarray(bodyEnd).some((value) => value !== 0)) {
      throw new TransferError('invalid-envelope');
    }
    const body = plaintext.subarray(4 + metadataLength, bodyEnd);
    const hash = await sha256(body);
    if (!equal(utf8(hex(hash)), utf8(metadata.sha256))) throw new TransferError('hash-mismatch');
    const file: VerifiedFile = {
      name: safeFilename(metadata.name), data: body.slice(), digest: await hmac(keys.audit, body),
    };
    verifiedFiles.add(file);
    return file;
  } finally {
    plaintext?.fill(0);
  }
}

export type WritableFile = {
  write(data: Uint8Array | string): Promise<void>;
  close(): Promise<void>;
  abort?(): Promise<void>;
};
export type SaveFileHandle = { createWritable(): Promise<WritableFile> };
export type SavePicker = (options: {
  suggestedName: string;
  types?: { description: string; accept: Record<string, string[]> }[];
}) => Promise<SaveFileHandle>;

/** Resolves only after close commits the file. Never substitutes an unobservable download. */
export async function saveVerifiedFile(file: VerifiedFile, signal?: AbortSignal): Promise<void> {
  if (!verifiedFiles.has(file)) throw new TransferError('file-not-verified');
  const picker = (globalThis as unknown as { showSaveFilePicker?: SavePicker }).showSaveFilePicker;
  if (!picker) throw new TransferError('unsupported-save');
  let writable: WritableFile | undefined;
  let committed = false;
  let aborting: Promise<void> | undefined;
  const checkActive = (): void => {
    if (signal?.aborted) throw new TransferError('save-session-ended');
  };
  const abortWritable = (): Promise<void> => {
    if (!writable || committed) return Promise.resolve();
    if (!aborting) {
      const target = writable;
      aborting = (async () => {
        try { await target.abort?.(); } catch { /* Best-effort cleanup cannot change the result. */ }
      })();
    }
    return aborting;
  };
  const onAbort = (): void => { void abortWritable(); };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    checkActive();
    // Keep the picker before any await so the click's transient activation is preserved.
    const handle = await picker.call(globalThis, { suggestedName: file.name });
    checkActive();
    writable = await handle.createWritable();
    checkActive();
    await writable.write(file.data);
    checkActive();
    await writable.close();
    committed = true;
    // A close already in progress may commit despite an abort. The caller must also
    // confirm that this is still the active session before creating COMPLETE.
    checkActive();
  } catch (error) {
    await abortWritable();
    if (signal?.aborted) throw new TransferError('save-session-ended');
    const code = error && typeof error === 'object' && 'name' in error && error.name === 'AbortError'
      ? 'save-cancelled' : 'save-failed';
    throw new TransferError(code);
  } finally {
    signal?.removeEventListener('abort', onAbort);
  }
}
