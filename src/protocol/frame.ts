import { bytes, equal } from '../crypto/bytes';
import { hmac, verifyMac } from '../crypto';
import { decodeBase45, encodeBase45 } from '../qr/base45';

export enum MessageType {
  HELLO = 1, HELLO_ACK, KEY, KEY_ACK, COMMIT, NONCE, READY, START,
  DATA, ACK, NACK, FIN, COMPLETE, CANCEL, ERROR,
}

export interface FrameInput {
  type: MessageType;
  sessionId: Uint8Array;
  sequence: number;
  payload: Uint8Array;
}
export interface Frame extends FrameInput {
  signedBytes: Uint8Array;
  mac?: Uint8Array;
}

const MAGIC = new Uint8Array([0x51, 0x52, 0x42, 0x4d]);
const HEADER_SIZE = 29;
export const MAX_FRAME_PAYLOAD = 2048;
export const ZERO_SESSION = new Uint8Array(16);

/** CRC-32/ISO-HDLC, used only for early corruption detection. */
export function crc32(input: Uint8Array): number {
  let crc = 0xffffffff;
  for (const value of input) {
    crc ^= value;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export async function encodeFrame(frame: FrameInput, key?: CryptoKey): Promise<string> {
  if (frame.sessionId.length !== 16 || frame.payload.length > MAX_FRAME_PAYLOAD ||
      !Number.isInteger(frame.sequence) || frame.sequence < 0 || frame.sequence > 0xffffffff ||
      frame.type < MessageType.HELLO || frame.type > MessageType.ERROR) throw new Error('INVALID_FRAME');
  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC);
  header[4] = 1;
  header[5] = frame.type;
  header[6] = key ? 1 : 0;
  header.set(frame.sessionId, 7);
  const view = new DataView(header.buffer);
  view.setUint32(23, frame.sequence);
  view.setUint16(27, frame.payload.length);
  const signed = bytes(header, frame.payload);
  const body = key ? bytes(signed, (await hmac(key, signed)).slice(0, 16)) : signed;
  const checksum = new Uint8Array(4);
  new DataView(checksum.buffer).setUint32(0, crc32(body));
  return encodeBase45(bytes(body, checksum));
}

export function decodeFrame(text: string): Frame {
  const data = decodeBase45(text);
  if (data.length < HEADER_SIZE + 4) throw new Error('INVALID_FRAME');
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (!equal(data.subarray(0, 4), MAGIC) || data[4] !== 1 || data[6] > 1 ||
      data[5] < MessageType.HELLO || data[5] > MessageType.ERROR) throw new Error('INVALID_FRAME');
  const length = view.getUint16(27);
  const hasMac = data[6] === 1;
  if (length > MAX_FRAME_PAYLOAD || data.length !== HEADER_SIZE + length + (hasMac ? 16 : 0) + 4 ||
      view.getUint32(data.length - 4) !== crc32(data.subarray(0, -4))) throw new Error('INVALID_FRAME');
  const signedEnd = HEADER_SIZE + length;
  return {
    type: data[5], sessionId: data.slice(7, 23), sequence: view.getUint32(23),
    payload: data.slice(HEADER_SIZE, signedEnd), signedBytes: data.slice(0, signedEnd),
    mac: hasMac ? data.slice(signedEnd, signedEnd + 16) : undefined,
  };
}

export async function authenticateFrame(frame: Frame, key: CryptoKey): Promise<boolean> {
  return !!frame.mac && await verifyMac(key, frame.signedBytes, frame.mac, 16);
}
