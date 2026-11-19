/** RFC 9285 Base45. Spaces are significant and must never be trimmed. */
const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const VALUES = new Map(Array.from(ALPHABET, (c, i) => [c, i]));

export function encodeBase45(input: Uint8Array): string {
  let output = '';
  for (let i = 0; i < input.length; i += 2) {
    let value = input[i];
    if (i + 1 < input.length) {
      value = value * 256 + input[i + 1];
      output += ALPHABET[value % 45] + ALPHABET[Math.floor(value / 45) % 45] + ALPHABET[Math.floor(value / 2025)];
    } else {
      output += ALPHABET[value % 45] + ALPHABET[Math.floor(value / 45)];
    }
  }
  return output;
}

export function decodeBase45(input: string): Uint8Array {
  if (input.length % 3 === 1 || input.length > 8192) throw new Error('INVALID_BASE45');
  const output = new Uint8Array(Math.floor(input.length * 2 / 3));
  let offset = 0;
  for (let i = 0; i < input.length; i += 3) {
    const a = VALUES.get(input[i]);
    const b = VALUES.get(input[i + 1]);
    const c = i + 2 < input.length ? VALUES.get(input[i + 2]) : 0;
    if (a === undefined || b === undefined || c === undefined) throw new Error('INVALID_BASE45');
    const value = a + b * 45 + c * 2025;
    if (i + 2 < input.length) {
      if (value > 65535) throw new Error('INVALID_BASE45');
      output[offset++] = Math.floor(value / 256);
      output[offset++] = value % 256;
    } else {
      if (value > 255) throw new Error('INVALID_BASE45');
      output[offset++] = value;
    }
  }
  return output;
}
