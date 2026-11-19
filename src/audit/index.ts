import { hex, randomBytes } from '../crypto/bytes';
import type { Role } from '../crypto';
import { TransferError, type SavePicker, type WritableFile } from '../transfer';

type AuditEvent = { time: string; event: string; result?: string; fileDigest?: string };

const EVENTS = new Set([
  'session-start', 'key-agreement', 'commitment-failed', 'sas-approved', 'sas-mismatch',
  'sas-warning', 'transfer-start', 'save-complete', 'complete', 'cancel', 'error',
  'timeout', 'session-end', 'incomplete',
]);
const RESULTS = new Set(['success', 'failure', 'cancelled', 'unconfirmed']);

/** Explicit export only. No file names, content, plaintext hashes, or real sizes are accepted. */
export class AuditLog {
  readonly id = hex(randomBytes(16));
  private readonly startedAt = new Date().toISOString();
  private session?: string;
  private readonly events: AuditEvent[] = [];

  constructor(private readonly buildId: string, private readonly role: Role) {
    if (!/^[A-Za-z0-9._-]{1,100}$/.test(buildId)) throw new Error('invalid-build-id');
    this.record('session-start');
  }

  setSession(id: Uint8Array): void {
    if (id.length !== 16) throw new Error('invalid-session-id');
    const next = hex(id);
    if (this.session && this.session !== next) throw new Error('audit-session-already-set');
    this.session = next;
  }

  record(event: string, result?: string, digest?: Uint8Array): void {
    // Fail closed if callers try to put arbitrary details into the log.
    if (!EVENTS.has(event) || (result !== undefined && !RESULTS.has(result)) ||
        (digest !== undefined && digest.length !== 32)) throw new Error('invalid-audit-event');
    if (this.events.length >= 1000) return;
    this.events.push({
      time: new Date().toISOString(), event,
      ...(result === undefined ? {} : { result }),
      ...(digest === undefined ? {} : { fileDigest: hex(digest) }),
    });
  }

  exportJson(): string {
    return JSON.stringify({
      format: 'qrbeam-audit-v1', id: this.id, buildId: this.buildId,
      sessionId: this.session ?? null, role: this.role, startedAt: this.startedAt,
      sizePolicy: 'omitted', digestAlgorithm: 'HMAC-SHA-256-session-audit-key',
      events: this.events,
    }, null, 2) + '\n';
  }

  async save(): Promise<void> {
    const picker = (globalThis as unknown as { showSaveFilePicker?: SavePicker }).showSaveFilePicker;
    if (!picker) throw new TransferError('unsupported-save');
    let writable: WritableFile | undefined;
    try {
      const handle = await picker.call(globalThis, {
        suggestedName: `qrbeam-audit-${this.id}.json`,
        types: [{ description: 'qrbeam audit log', accept: { 'application/json': ['.json'] } }],
      });
      writable = await handle.createWritable();
      await writable.write(this.exportJson());
      await writable.close();
    } catch (error) {
      try { await writable?.abort?.(); } catch { /* Best-effort cleanup. */ }
      throw new TransferError(error && typeof error === 'object' && 'name' in error && error.name === 'AbortError'
        ? 'save-cancelled' : 'save-failed');
    }
  }
}
