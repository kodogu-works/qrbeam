const encoder = new TextEncoder();
const RESERVED = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i;

/** A suggested basename only; the user chooses the actual destination. */
export function safeFilename(input: string): string {
  let name = input.normalize('NFC')
    .replace(/[\u0000-\u001f\u007f-\u009f/\\<>:"|?*\u202a-\u202e\u2066-\u2069]/gu, '_')
    .replace(/\.{2,}/g, '_')
    .replace(/[. ]+$/g, '');
  if (RESERVED.test(name)) name = `_${name}`;
  if (!name || name === '.') name = 'received-file';

  let result = '';
  let length = 0;
  for (const char of name) {
    const width = encoder.encode(char).length;
    if (length + width > 255) break;
    result += char;
    length += width;
  }
  result = result.replace(/[. ]+$/g, '');
  return result || 'received-file';
}
