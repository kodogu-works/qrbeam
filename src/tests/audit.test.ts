import { describe, expect, it } from 'vitest';
import { AuditLog } from '../audit';

describe('minimal explicit audit logs', () => {
  it('records only identifiers, allowlisted events and a keyed digest', () => {
    const log = new AuditLog('test-build', 'sender');
    log.setSession(new Uint8Array(16).fill(3));
    log.record('key-agreement');
    log.record('complete', 'success', new Uint8Array(32).fill(7));
    const value = JSON.parse(log.exportJson());
    expect(value.id).toBe(log.id);
    expect(value.sessionId).toBe('03'.repeat(16));
    expect(value.sizePolicy).toBe('omitted');
    expect(value.events[2].fileDigest).toBe('07'.repeat(32));
    expect(log.exportJson()).not.toContain('fileSize');
    expect(log.exportJson()).not.toContain('filename');
    expect(() => log.record('secret-filename')).toThrow('invalid-audit-event');
    expect(() => log.record('error', 'secret-details')).toThrow('invalid-audit-event');
    expect(() => log.setSession(new Uint8Array(16).fill(4))).toThrow('audit-session-already-set');
  });
});
