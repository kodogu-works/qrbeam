import { describe, expect, it } from 'vitest';
import { safeFilename } from '../security/filename';

describe('safe filenames', () => {
  it('normalizes Unicode and removes traversal, path separators, controls and unsafe Windows characters', () => {
    expect(safeFilename('Cafe\u0301.txt')).toBe('Café.txt');
    const name = safeFilename('../secret\\thing\u0000<>:"|?*.txt');
    expect(name).not.toMatch(/[\/\\\u0000<>:"|?*]/);
    expect(name).not.toContain('..');
    expect(safeFilename('example.txt.  ')).toBe('example.txt');
  });

  it.each(['CON', 'con.txt', 'PrN.tar.gz', 'AUX', 'NUL.bin', 'COM1', 'com9.txt', 'LPT1', 'Lpt9.pdf'])(
    'avoids reserved name %s including extensions', (name) => expect(safeFilename(name)).toBe(`_${name}`),
  );

  it('does not mistake ordinary names for reserved devices', () => {
    expect(safeFilename('CONTEXT.txt')).toBe('CONTEXT.txt');
    expect(safeFilename('COM10.txt')).toBe('COM10.txt');
  });

  it('falls back for empty names', () => {
    expect(safeFilename('')).toBe('received-file');
    expect(safeFilename(' . ')).toBe('received-file');
  });

  it('keeps UTF-8 boundaries within 255 bytes after all changes', () => {
    for (const input of ['あ'.repeat(100), '😀'.repeat(100), 'a'.repeat(254) + '界.txt', 'CON.' + 'x'.repeat(300)]) {
      const result = safeFilename(input);
      expect(new TextEncoder().encode(result).length).toBeLessThanOrEqual(255);
      expect(result).not.toContain('\ufffd');
      expect(result).not.toMatch(/[. ]$/);
    }
    expect(safeFilename('あ'.repeat(85))).toBe('あ'.repeat(85));
    expect(safeFilename('😀'.repeat(64))).toBe('😀'.repeat(63));
  });
});
