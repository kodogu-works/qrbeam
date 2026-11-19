/** Raw concatenation. Protocol transcript concatenation uses lp() instead. */
export function bytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  if (!Number.isSafeInteger(length)) throw new Error('INVALID_LENGTH');
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** Unambiguous concatenation: each element has a 32-bit big-endian length. */
export function lp(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((total, part) => total + 4 + part.byteLength, 0));
  const view = new DataView(result.buffer);
  let offset = 0;
  for (const part of parts) {
    if (part.byteLength > 0xffffffff) throw new Error('INVALID_LENGTH');
    view.setUint32(offset, part.byteLength, false);
    offset += 4;
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

/** Compare all bytes; JavaScript engines do not guarantee constant-time execution. */
export function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

export function hex(value: Uint8Array): string {
  return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('');
}

export function unhex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[a-fA-F0-9]*$/.test(value)) throw new Error('INVALID_HEX');
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < result.length; index++) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) throw new Error('INVALID_LENGTH');
  const result = new Uint8Array(length);
  for (let offset = 0; offset < length; offset += 65536) {
    crypto.getRandomValues(result.subarray(offset, Math.min(offset + 65536, length)));
  }
  return result;
}

export async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(value).buffer));
}
