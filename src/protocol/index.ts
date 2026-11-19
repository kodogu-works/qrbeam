import {
  commitment, deriveSession, generateEphemeral, importPublicKey, sessionId,
  type Role, type SessionKeys,
} from '../crypto';
import { bytes, equal, hex, randomBytes, sha256, utf8 } from '../crypto/bytes';
import { decryptFile, encryptFile, type EncryptedFile, type FileInput, type VerifiedFile } from '../transfer';
import { authenticateFrame, decodeFrame, encodeFrame, MessageType, ZERO_SESSION, type Frame } from './frame';

export interface ProtocolConfig {
  payloadBytes: number;
  windowSize: number;
  minFrameIntervalMs: number;
  handshakeTimeoutMs: number;
  approvalWaitTimeoutMs: number;
  saveWaitTimeoutMs: number;
  sessionMaxLifetimeMs: number;
  maxRetries: number;
  sasEnterGuardMs: number;
  paddingBlock: number;
}
export const DEFAULT_PROTOCOL_CONFIG: ProtocolConfig = {
  payloadBytes: 512, windowSize: 1, minFrameIntervalMs: 350,
  handshakeTimeoutMs: 120_000, approvalWaitTimeoutMs: 180_000,
  saveWaitTimeoutMs: 300_000, sessionMaxLifetimeMs: 3_600_000,
  maxRetries: 100, sasEnterGuardMs: 1500, paddingBlock: 4096,
};
export type ProtocolState = 'aligning' | 'key-exchange' | 'authentication' | 'approval-wait' |
  'transferring' | 'save-wait' | 'save' | 'complete' | 'error' | 'cancelled';
export interface ProtocolSnapshot {
  state: ProtocolState;
  role: Role;
  phase: string;
  sas?: string;
  localApproved: boolean;
  peerApproved: boolean;
  progress: number;
  transferredBytes: number;
  elapsedMs: number;
  retries: number;
  remainingMs?: number;
  error?: string;
  sessionId?: string;
  digest?: string;
  receivedFile?: VerifiedFile;
}

const roleByte = (role: Role) => role === 'sender' ? 1 : 2;
const uint32 = (value: number) => {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value);
  return result;
};
const uint16 = (value: number) => {
  const result = new Uint8Array(2);
  new DataView(result.buffer).setUint16(0, value);
  return result;
};
const read32 = (data: Uint8Array, offset = 0) => new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(offset);
const read16 = (data: Uint8Array, offset = 0) => new DataView(data.buffer, data.byteOffset, data.byteLength).getUint16(offset);
const terminal = (state: ProtocolState) => state === 'error' || state === 'cancelled' || state === 'complete';
const MAX_CIPHERTEXT = 1_048_576 + 65_536 + 16;
const CANCEL_CODES = new Set(['USER_CANCELLED', 'SAS_MISMATCH', 'SAVE_INCOMPLETE', 'CAMERA_STOPPED', 'PAGE_HIDDEN']);

/** A session has one serial mutation queue. Camera callbacks cannot race key derivation or saving. */
export class ProtocolSession {
  readonly role: Role;
  readonly config: ProtocolConfig;
  onEvent?: (event: string) => void;
  private state: ProtocolState = 'aligning';
  private phase = 'hello';
  private file?: FileInput;
  private privateKey?: CryptoKey;
  private publicKey?: Uint8Array;
  private peerPublic?: Uint8Array;
  private dev = randomBytes(16);
  private peerDev?: Uint8Array;
  private sid?: Uint8Array;
  private nr?: Uint8Array;
  private ns?: Uint8Array;
  private commit?: Uint8Array;
  private keys?: SessionKeys;
  private th?: Uint8Array;
  private sas?: string;
  private localApproved = false;
  private peerApproved = false;
  private startedAt = Date.now();
  private now = this.startedAt;
  private approvalAt?: number;
  private saveAt?: number;
  private lastShownAt = -Infinity;
  private seq = 0;
  private carousel = 0;
  private cached = new Map<MessageType, string>();
  private shown = new Map<string, number>();
  private seen = new Map<number, string>();
  private retryCount = 0;
  private encrypted?: EncryptedFile;
  private verified?: VerifiedFile;
  private digest?: Uint8Array;
  private transferId?: Uint8Array;
  private nonce?: Uint8Array;
  private cipherLength = 0;
  private chunkSize = 0;
  private totalChunks = 0;
  private chunks = new Map<number, Uint8Array>();
  private acknowledged = new Set<number>();
  private dataFrames = new Map<number, string>();
  private startAcknowledged = false;
  private acknowledgementSequence = -1;
  private dataCursor = 0;
  private error?: string;
  private terminalFrame?: string;
  private disposed = false;
  private initialized = false;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(role: Role, config: Partial<ProtocolConfig> = {}, file?: FileInput) {
    this.role = role;
    this.config = { ...DEFAULT_PROTOCOL_CONFIG, ...config };
    if (!['sender', 'receiver'].includes(role) ||
        ![1, 2, 4, 8].includes(this.config.windowSize) ||
        !Number.isInteger(this.config.payloadBytes) || this.config.payloadBytes < 128 || this.config.payloadBytes > 1024 ||
        ![0, 4096].includes(this.config.paddingBlock) ||
        Object.entries(this.config).some(([key, value]) => !Number.isFinite(value) || value < 0 ||
          (key !== 'paddingBlock' && key !== 'minFrameIntervalMs' && key !== 'sasEnterGuardMs' && value === 0))) {
      throw new Error('INVALID_CONFIG');
    }
    if (role === 'sender' && (!file || file.data.length > 1_048_576)) throw new Error('INVALID_FILE');
    this.file = file;
  }

  private serial<T>(action: () => Promise<T>): Promise<T> {
    const next = this.queue.then(async () => {
      try { return await action(); }
      finally { if (this.disposed) this.clearSecrets(); }
    });
    this.queue = next.catch(() => undefined);
    return next;
  }

  init(): Promise<void> {
    return this.serial(async () => {
      if (this.initialized || this.disposed) return;
      const key = await generateEphemeral();
      if (this.disposed) return;
      this.privateKey = key.privateKey;
      this.publicKey = key.publicKey;
      await this.cache(MessageType.HELLO, bytes(new Uint8Array([roleByte(this.role)]), this.dev, new Uint8Array([1])), true);
      this.initialized = true;
      this.onEvent?.('session-start');
    });
  }

  get snapshot(): ProtocolSnapshot {
    const received = this.role === 'sender' ? this.acknowledged.size : this.chunks.size;
    const progress = this.totalChunks ? received / this.totalChunks : 0;
    const deadline = this.saveAt !== undefined ? this.saveAt + this.config.saveWaitTimeoutMs :
      this.approvalAt !== undefined ? this.approvalAt + this.config.approvalWaitTimeoutMs :
      ['aligning', 'key-exchange'].includes(this.state) ? this.startedAt + this.config.handshakeTimeoutMs : undefined;
    return {
      state: this.state, role: this.role, phase: this.phase, sas: this.sas,
      localApproved: this.localApproved, peerApproved: this.peerApproved,
      progress: this.state === 'complete' ? 1 : progress,
      transferredBytes: this.state === 'complete' ? this.cipherLength : Math.min(this.cipherLength, received * this.chunkSize),
      elapsedMs: Math.max(0, this.now - this.startedAt), retries: this.retryCount,
      remainingMs: deadline === undefined || terminal(this.state) ? undefined : Math.max(0, deadline - this.now),
      error: this.error, sessionId: this.sid && hex(this.sid), digest: this.digest && hex(this.digest),
      receivedFile: this.verified,
    };
  }

  private async cache(type: MessageType, payload: Uint8Array, unkeyed = false): Promise<string> {
    const value = await encodeFrame({
      type, sequence: this.seq++, sessionId: type <= MessageType.HELLO_ACK ? ZERO_SESSION : this.sid ?? ZERO_SESSION, payload,
    }, unkeyed ? undefined : this.outboundKey());
    if (this.disposed) return '';
    this.cached.set(type, value);
    return value;
  }
  private outboundKey(): CryptoKey | undefined {
    return this.role === 'sender' ? this.keys?.macS2R : this.keys?.macR2S;
  }
  private inboundKey(): CryptoKey | undefined {
    return this.role === 'sender' ? this.keys?.macR2S : this.keys?.macS2R;
  }

  receive(text: string): Promise<void> {
    return this.serial(async () => {
      if (this.disposed || !this.initialized || terminal(this.state)) return;
      this.now = Math.max(this.now, Date.now());
      await this.checkTimeouts();
      if (terminal(this.state) || this.disposed) return;
      let frame: Frame;
      try { frame = decodeFrame(text); } catch { return; }
      if (frame.type === MessageType.HELLO && equal(frame.payload.subarray(1, 17), this.dev)) return;
      const isHello = frame.type === MessageType.HELLO || frame.type === MessageType.HELLO_ACK;
      if (isHello ? !equal(frame.sessionId, ZERO_SESSION) : !this.sid || !equal(frame.sessionId, this.sid)) return;
      if (this.keys) {
        // Immutable handshake frames must remain available until the peer derives its keys.
        // They are never processed again after local derivation.
        if (frame.type <= MessageType.NONCE) return;
        const key = this.inboundKey()!;
        if (!await authenticateFrame(frame, key)) {
          if (frame.type === MessageType.READY) await this.fail('READY_MAC_INVALID');
          return;
        }
        if (this.disposed) return;
      } else if (frame.mac || frame.type >= MessageType.READY && frame.type < MessageType.CANCEL) {
        return;
      }
      const previous = this.seen.get(frame.sequence);
      const fingerprint = hex(frame.signedBytes);
      if (previous && previous !== fingerprint) {
        await this.fail('SEQUENCE_CONFLICT');
        return;
      }
      if (this.seen.size > 20_000) { await this.fail('FRAME_LIMIT'); return; }
      // Handlers remain idempotent so a repeated DATA can elicit the current ACK.
      this.seen.set(frame.sequence, fingerprint);
      try { await this.handle(frame); }
      catch { await this.fail('PROTOCOL_INVALID'); }
    });
  }

  private async handle(frame: Frame): Promise<void> {
    const p = frame.payload;
    switch (frame.type) {
      case MessageType.HELLO: {
        if (p.length !== 18 || ![1, 2].includes(p[0]) || p[17] !== 1) return;
        if (p[0] === roleByte(this.role)) { await this.fail('ROLE_CONFLICT'); return; }
        const peer = p.slice(1, 17);
        if (this.peerDev && !equal(this.peerDev, peer)) return;
        this.peerDev = peer;
        if (!this.cached.has(MessageType.HELLO_ACK)) {
          await this.cache(MessageType.HELLO_ACK, bytes(new Uint8Array([roleByte(this.role)]), this.dev, peer), true);
        }
        break;
      }
      case MessageType.HELLO_ACK: {
        if (p.length !== 33 || p[0] === roleByte(this.role) || !this.peerDev ||
            !equal(p.subarray(1, 17), this.peerDev) || !equal(p.subarray(17), this.dev) || this.sid) return;
        this.sid = await sessionId(this.role === 'sender' ? this.dev : this.peerDev, this.role === 'receiver' ? this.dev : this.peerDev);
        this.state = 'key-exchange'; this.phase = 'key';
        await this.cache(MessageType.KEY, this.publicKey!, true);
        break;
      }
      case MessageType.KEY: {
        if (this.peerPublic) {
          if (!equal(this.peerPublic, p)) await this.fail('PUBLIC_KEY_CHANGED');
          return;
        }
        try { await importPublicKey(p); }
        catch { await this.fail('PUBLIC_KEY_INVALID'); return; }
        if (equal(p, this.publicKey!)) return;
        this.peerPublic = p.slice();
        await this.cache(MessageType.KEY_ACK, await sha256(p), true);
        if (this.role === 'receiver') {
          this.nr = randomBytes(16);
          this.commit = await commitment(this.nr, this.publicKey!, this.peerPublic, this.sid!);
          await this.cache(MessageType.COMMIT, this.commit, true);
          this.phase = 'commit';
        }
        break;
      }
      case MessageType.KEY_ACK:
        if (p.length !== 32 || !equal(p, await sha256(this.publicKey!))) return;
        break;
      case MessageType.COMMIT: {
        if (this.role !== 'sender' || !this.peerPublic || p.length !== 32) return;
        if (this.commit) {
          if (!equal(this.commit, p)) await this.fail('COMMITMENT_CHANGED');
          return;
        }
        this.commit = p.slice();
        this.ns = randomBytes(16);
        await this.cache(MessageType.NONCE, this.ns, true);
        this.phase = 'nonce';
        break;
      }
      case MessageType.NONCE: {
        if (p.length !== 16 || !this.peerPublic || !this.commit) return;
        if (this.role === 'receiver') {
          if (!this.nr) return;
          if (this.ns && !equal(this.ns, p)) { await this.fail('NONCE_CHANGED'); return; }
          this.ns = p.slice();
          await this.cache(MessageType.NONCE, this.nr, true);
        } else {
          if (!this.ns) return;
          this.nr = p.slice();
          const expected = await commitment(this.nr, this.peerPublic, this.publicKey!, this.sid!);
          if (!equal(expected, this.commit)) {
            this.onEvent?.('commitment-failed'); await this.fail('COMMITMENT_INVALID'); return;
          }
        }
        await this.derive();
        break;
      }
      case MessageType.READY: {
        // Delayed READY frames must not restart an approval timer after START.
        if (!['authentication', 'approval-wait'].includes(this.state)) return;
        const peerRole = this.role === 'sender' ? 2 : 1;
        if (p.length !== 33 || p[0] !== peerRole || !equal(p.subarray(1), this.th!)) {
          await this.fail('READY_TRANSCRIPT_INVALID'); return;
        }
        this.peerApproved = true;
        this.approvalAt ??= this.now;
        if (this.localApproved) await this.beginTransfer();
        break;
      }
      case MessageType.START:
        await this.acceptStart(p);
        break;
      case MessageType.DATA:
        await this.acceptData(p);
        break;
      case MessageType.ACK:
      case MessageType.NACK:
        await this.acceptAcknowledgement(p, frame.type === MessageType.NACK, frame.sequence);
        break;
      case MessageType.FIN:
        if (this.role !== 'receiver' || !this.transferId || p.length !== 20 ||
            !equal(p.subarray(0, 16), this.transferId) || read32(p, 16) !== this.totalChunks) return;
        if (this.chunks.size !== this.totalChunks) await this.updateAck(true);
        else await this.finishReceiving();
        break;
      case MessageType.COMPLETE:
        if (this.role !== 'sender' || this.state !== 'save-wait' || p.length !== 48 ||
            !this.transferId || !equal(p.subarray(0, 16), this.transferId)) return;
        if (!this.digest || !equal(p.subarray(16), this.digest)) {
          await this.fail('COMPLETE_DIGEST_INVALID'); return;
        }
        this.state = 'complete'; this.phase = 'complete';
        this.onEvent?.('complete'); this.clearSecrets();
        break;
      case MessageType.CANCEL:
      case MessageType.ERROR: {
        const code = new TextDecoder().decode(p);
        this.error = code === 'SAVE_INCOMPLETE' ? 'PEER_NOT_SAVED' : 'PEER_CANCELLED';
        this.state = 'cancelled'; this.onEvent?.('cancel'); this.clearSecrets();
        break;
      }
    }
  }

  private async derive(): Promise<void> {
    if (this.keys || !this.privateKey || !this.peerPublic || !this.peerDev || !this.nr || !this.ns || !this.commit) return;
    const result = await deriveSession(this.privateKey, this.peerPublic, {
      senderDev: this.role === 'sender' ? this.dev : this.peerDev,
      receiverDev: this.role === 'receiver' ? this.dev : this.peerDev,
      sessionId: this.sid!, senderPublic: this.role === 'sender' ? this.publicKey! : this.peerPublic,
      receiverPublic: this.role === 'receiver' ? this.publicKey! : this.peerPublic,
      commitment: this.commit, senderNonce: this.ns, receiverNonce: this.nr,
    });
    if (this.disposed) return;
    this.keys = result.keys; this.th = result.transcriptHash; this.sas = result.sas;
    this.privateKey = undefined;
    this.state = 'authentication'; this.phase = 'ready';
    this.onEvent?.('key-agreement');
  }

  approve(): Promise<void> {
    return this.serial(async () => {
      if (this.disposed || this.state !== 'authentication' || !this.keys || this.localApproved) return;
      this.now = Math.max(this.now, Date.now());
      await this.checkTimeouts();
      if (terminal(this.state) || this.disposed) return;
      this.localApproved = true; this.approvalAt ??= this.now;
      await this.cache(MessageType.READY, bytes(new Uint8Array([roleByte(this.role)]), this.th!));
      this.onEvent?.('sas-approved');
      this.state = 'approval-wait';
      if (this.peerApproved) await this.beginTransfer();
    });
  }

  private async beginTransfer(): Promise<void> {
    if (!this.localApproved || !this.peerApproved || !this.keys) return;
    if (this.role === 'receiver' || this.encrypted) return;
    const encrypted = await encryptFile(this.file!, this.keys, this.sid!, this.config.paddingBlock);
    if (this.disposed) { encrypted.ciphertext.fill(0); return; }
    this.encrypted = encrypted;
    this.file = undefined;
    this.transferId = this.encrypted.transferId;
    this.nonce = this.encrypted.nonce;
    this.digest = this.encrypted.digest;
    this.cipherLength = this.encrypted.ciphertext.length;
    this.chunkSize = this.config.payloadBytes;
    this.totalChunks = Math.ceil(this.cipherLength / this.chunkSize);
    await this.cache(MessageType.START, bytes(this.transferId, this.nonce, uint32(this.cipherLength),
      uint16(this.chunkSize), uint32(this.totalChunks), uint32(this.config.paddingBlock)));
    if (this.disposed) return;
    this.state = 'transferring'; this.phase = 'start'; this.approvalAt = undefined;
    this.onEvent?.('transfer-start');
  }

  private async acceptStart(p: Uint8Array): Promise<void> {
    if (this.role !== 'receiver' || !this.localApproved || !this.peerApproved || p.length !== 42 ||
        !['approval-wait', 'transferring', 'save'].includes(this.state)) return;
    if (this.transferId) {
      if (!equal(p.subarray(0, 16), this.transferId)) await this.fail('TRANSFER_CHANGED');
      return;
    }
    const length = read32(p, 28), size = read16(p, 32), count = read32(p, 34), padding = read32(p, 38);
    if (length < 16 || length > MAX_CIPHERTEXT || size < 128 || size > 1024 ||
        count !== Math.ceil(length / size) || padding !== this.config.paddingBlock) {
      await this.fail('TRANSFER_BOUNDS'); return;
    }
    this.transferId = p.slice(0, 16); this.nonce = p.slice(16, 28);
    this.cipherLength = length; this.chunkSize = size; this.totalChunks = count;
    this.state = 'transferring'; this.phase = 'data'; this.approvalAt = undefined;
    await this.updateAck(); this.onEvent?.('transfer-start');
  }

  private async acceptData(p: Uint8Array): Promise<void> {
    if (this.role !== 'receiver' || !this.transferId || this.state !== 'transferring' || p.length < 21 ||
        !equal(p.subarray(0, 16), this.transferId)) return;
    const index = read32(p, 16);
    const expected = index === this.totalChunks - 1 ? this.cipherLength - index * this.chunkSize : this.chunkSize;
    if (index >= this.totalChunks || p.length !== 20 + expected) return;
    const old = this.chunks.get(index);
    if (old && !equal(old, p.subarray(20))) { await this.fail('DATA_CHANGED'); return; }
    if (!old) { this.chunks.set(index, p.slice(20)); await this.updateAck(); }
  }

  private async updateAck(nack = false): Promise<void> {
    if (!this.transferId) return;
    let base = 0;
    while (this.chunks.has(base)) base++;
    const count = Math.min(256, this.totalChunks - base);
    const bitmap = new Uint8Array(Math.ceil(count / 8));
    for (let i = 0; i < count; i++) {
      if (nack ? !this.chunks.has(base + i) : this.chunks.has(base + i)) bitmap[i >>> 3] |= 1 << (i & 7);
    }
    await this.cache(nack ? MessageType.NACK : MessageType.ACK,
      bytes(this.transferId, uint32(base), uint16(count), bitmap));
    if (nack) this.cached.delete(MessageType.ACK);
    else this.cached.delete(MessageType.NACK);
  }

  private async acceptAcknowledgement(p: Uint8Array, nack: boolean, sequence: number): Promise<void> {
    if (this.role !== 'sender' || !this.transferId || !['transferring', 'save-wait'].includes(this.state) ||
        sequence <= this.acknowledgementSequence || p.length < 22 || !equal(p.subarray(0, 16), this.transferId)) return;
    const base = read32(p, 16), count = read16(p, 20);
    if (base > this.totalChunks || count > 256 || base + count > this.totalChunks || p.length !== 22 + Math.ceil(count / 8)) return;
    this.acknowledgementSequence = sequence;
    this.startAcknowledged = true;
    for (let i = 0; i < base; i++) this.acknowledged.add(i);
    for (let i = 0; i < count; i++) {
      const bit = (p[22 + (i >>> 3)] & (1 << (i & 7))) !== 0;
      if (nack ? !bit : bit) this.acknowledged.add(base + i);
      else if (nack && bit) this.acknowledged.delete(base + i);
    }
    if (this.acknowledged.size === this.totalChunks && this.state !== 'save-wait') {
      this.state = 'save-wait'; this.phase = 'save'; this.saveAt = this.now;
      await this.cache(MessageType.FIN, bytes(this.transferId, uint32(this.totalChunks)));
    } else if (this.acknowledged.size < this.totalChunks && this.state === 'save-wait') {
      this.state = 'transferring'; this.phase = 'data'; this.saveAt = undefined;
    }
  }

  private async finishReceiving(): Promise<void> {
    if (this.verified || this.state !== 'transferring' || !this.keys) return;
    const ciphertext = new Uint8Array(this.cipherLength);
    for (let i = 0; i < this.totalChunks; i++) ciphertext.set(this.chunks.get(i)!, i * this.chunkSize);
    try {
      const verified = await decryptFile({ transferId: this.transferId!, nonce: this.nonce!, ciphertext }, this.keys, this.sid!, this.config.paddingBlock);
      if (this.disposed) { verified.data.fill(0); return; }
      this.verified = verified;
    } catch { await this.fail('FILE_VERIFICATION_FAILED'); return; }
    finally { ciphertext.fill(0); }
    this.digest = this.verified.digest;
    this.state = 'save'; this.phase = 'save'; this.saveAt = this.now;
  }

  /** Must be called only after the File System Access writable.close() promise resolves. */
  confirmSaved(): Promise<void> {
    return this.serial(async () => {
      if (this.disposed || this.role !== 'receiver' || this.state !== 'save' || !this.verified || !this.digest) return;
      this.now = Math.max(this.now, Date.now());
      await this.checkTimeouts();
      if (this.state !== 'save' || this.disposed) return;
      this.terminalFrame = await this.cache(MessageType.COMPLETE, bytes(this.transferId!, this.digest));
      if (this.disposed) { this.terminalFrame = undefined; return; }
      this.verified.data.fill(0); this.verified = undefined;
      this.state = 'complete'; this.phase = 'complete';
      this.onEvent?.('save-complete'); this.onEvent?.('complete');
      this.clearSecrets();
    });
  }

  nextFrame(now = Date.now()): Promise<string | null> {
    return this.serial(async () => {
      this.now = now;
      if (this.disposed || !this.initialized) return null;
      if (!terminal(this.state)) await this.checkTimeouts();
      if (now - this.lastShownAt < this.config.minFrameIntervalMs) return null;
      if (terminal(this.state)) {
        if (!this.terminalFrame) return null;
        this.lastShownAt = now;
        return this.terminalFrame;
      }
      let choices: MessageType[] = [];
      let value: string | undefined;
      let limited = false;
      if (this.role === 'sender' && this.state === 'transferring') {
        limited = true;
        if (!this.startAcknowledged) {
          // START can overtake or outlive the final READY. Retain both until an
          // authenticated ACK proves that the receiver accepted both approvals.
          value = this.cached.get(this.carousel++ % 2 ? MessageType.START : MessageType.READY);
        }
        else {
          let base = 0;
          while (this.acknowledged.has(base)) base++;
          const candidates: number[] = [];
          for (let i = base; i < Math.min(base + this.config.windowSize, this.totalChunks); i++) {
            if (!this.acknowledged.has(i)) candidates.push(i);
          }
          const index = candidates[this.dataCursor++ % candidates.length];
          if (index !== undefined) {
            value = this.dataFrames.get(index);
            if (!value) {
              value = await this.cache(MessageType.DATA, bytes(this.transferId!, uint32(index),
                this.encrypted!.ciphertext.subarray(index * this.chunkSize, Math.min((index + 1) * this.chunkSize, this.cipherLength))));
              this.dataFrames.set(index, value);
            }
          }
          this.phase = 'data';
        }
      } else if (this.role === 'receiver' && ['transferring', 'save'].includes(this.state)) {
        choices = [MessageType.NACK, MessageType.ACK];
      } else if (this.state === 'save-wait') {
        choices = [MessageType.FIN];
      } else if (this.keys) {
        choices = [MessageType.NONCE, MessageType.READY];
      } else {
        choices = this.peerPublic ? [MessageType.KEY, MessageType.KEY_ACK, MessageType.COMMIT, MessageType.NONCE, MessageType.HELLO_ACK] :
          [MessageType.HELLO, MessageType.HELLO_ACK, MessageType.KEY];
        limited = true;
      }
      if (!value) {
        const existing = choices.map(type => this.cached.get(type)).filter((item): item is string => !!item);
        value = existing[this.carousel++ % existing.length];
      }
      if (!value) return null;
      if (this.disposed) return null;
      const attempts = this.shown.get(value) ?? 0;
      if (limited && attempts >= this.config.maxRetries) {
        await this.fail('RETRY_LIMIT'); return this.terminalFrame ?? null;
      }
      this.shown.set(value, attempts + 1);
      if (attempts > 0) this.retryCount++;
      this.lastShownAt = now;
      return value;
    });
  }

  private async checkTimeouts(): Promise<void> {
    let code: string | undefined;
    if (this.now - this.startedAt >= this.config.sessionMaxLifetimeMs) code = 'SESSION_EXPIRED';
    else if (['aligning', 'key-exchange'].includes(this.state) && this.now - this.startedAt >= this.config.handshakeTimeoutMs) code = 'HANDSHAKE_TIMEOUT';
    else if (this.approvalAt !== undefined && this.now - this.approvalAt >= this.config.approvalWaitTimeoutMs) code = 'APPROVAL_TIMEOUT';
    else if (this.saveAt !== undefined && this.now - this.saveAt >= this.config.saveWaitTimeoutMs) code = 'SAVE_TIMEOUT_UNCONFIRMED';
    if (code) { this.onEvent?.(code === 'SAVE_TIMEOUT_UNCONFIRMED' ? 'incomplete' : 'timeout'); await this.fail(code); }
  }

  cancel(reason = 'USER_CANCELLED'): Promise<void> {
    return this.serial(async () => {
      if (this.disposed || terminal(this.state)) return;
      const code = CANCEL_CODES.has(reason) ? reason : 'USER_CANCELLED';
      if (code === 'SAS_MISMATCH') this.onEvent?.('sas-mismatch');
      await this.stop(code, 'cancelled');
    });
  }
  private async fail(reason: string): Promise<void> { await this.stop(reason, 'error'); }
  private async stop(reason: string, state: 'error' | 'cancelled'): Promise<void> {
    if (terminal(this.state)) return;
    this.terminalFrame = await this.cache(state === 'error' ? MessageType.ERROR : MessageType.CANCEL, utf8(reason));
    if (this.disposed) { this.terminalFrame = undefined; return; }
    this.error = reason; this.state = state;
    this.onEvent?.(state === 'error' ? 'error' : 'cancel');
    this.clearSecrets();
  }
  private clearSecrets(): void {
    this.privateKey = undefined; this.keys = undefined; this.file = undefined;
    this.ns?.fill(0); this.nr?.fill(0); this.ns = undefined; this.nr = undefined;
    this.verified?.data.fill(0); this.verified = undefined;
    this.encrypted?.ciphertext.fill(0); this.encrypted = undefined;
    for (const chunk of this.chunks.values()) chunk.fill(0);
    this.chunks.clear(); this.dataFrames.clear(); this.cached.clear(); this.seen.clear(); this.shown.clear();
    this.sas = undefined; this.th = undefined;
  }
  dispose(): void {
    this.disposed = true; this.clearSecrets(); this.terminalFrame = undefined;
    this.onEvent?.('session-end');
  }
}
