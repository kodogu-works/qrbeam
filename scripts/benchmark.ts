import { performance } from 'node:perf_hooks';
import { webcrypto } from 'node:crypto';
import { cpus } from 'node:os';
import jsQR from 'jsqr';
import { createQR, qrImage } from './qr-image';
import { decodeBase45, encodeBase45 } from '../src/qr/base45';
import { ProtocolSession } from '../src/protocol';
import { decodeFrame, MessageType } from '../src/protocol/frame';
import { equal } from '../src/crypto/bytes';

if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });

// Fixed high-entropy-looking bytes make the benchmark reproducible without using file data.
function fixture(length: number): Uint8Array {
  let state = 0x6d2b79f5;
  return Uint8Array.from({ length }, () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state & 255;
  });
}

const iterations = Number(process.env.QRBEAM_BENCH_ITERATIONS ?? 5);
if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100) throw new Error('Invalid benchmark iteration count');
const rows: Array<Record<string, string | number>> = [];
for (const payloadBytes of [128, 256, 512, 768]) {
  // DATA: 16-byte transfer ID + 4-byte chunk index + 29-byte header + 16-byte MAC + 4-byte CRC.
  const frame = fixture(payloadBytes + 69);
  for (const encoding of ['Base45', 'Base64'] as const) {
    const encode = () => encoding === 'Base45' ? encodeBase45(frame) : Buffer.from(frame).toString('base64');
    const text = encode();
    const mode = encoding === 'Base45' ? 'alphanumeric' : 'byte';
    const template = qrImage(text, mode);
    // Warm up JIT and encoder/decoder paths before collecting the mean.
    jsQR(template.pixels, template.width, template.height, { inversionAttempts: 'dontInvert' });
    let textTime = 0;
    let qrTime = 0;
    let decodeTime = 0;
    for (let round = 0; round < iterations; round++) {
      let start = performance.now();
      const encoded = encode();
      const binary = encoding === 'Base45' ? decodeBase45(encoded) : new Uint8Array(Buffer.from(encoded, 'base64'));
      textTime += performance.now() - start;
      if (!Buffer.from(binary).equals(Buffer.from(frame))) throw new Error('Text encoding round-trip failed');
      start = performance.now();
      createQR(encoded, mode);
      qrTime += performance.now() - start;
      // Decode the same synthetic image each iteration; excludes image rasterization.
      start = performance.now();
      const decoded = jsQR(template.pixels, template.width, template.height, { inversionAttempts: 'dontInvert' });
      decodeTime += performance.now() - start;
      if (decoded?.data !== encoded) throw new Error('QR round-trip failed');
    }
    rows.push({
      payloadBytes, encoding, textChars: text.length, version: template.version,
      modules: template.modules, pixels: template.width,
      textRoundTripMs: +(textTime / iterations).toFixed(3),
      qrEncodeMs: +(qrTime / iterations).toFixed(3),
      qrDecodeMs: +(decodeTime / iterations).toFixed(3),
    });
  }
}
console.log(`Node ${process.version}; ${cpus()[0]?.model ?? 'unknown CPU'}; ECC M; scale 4; quiet zone 4; iterations ${iterations}`);
console.table(rows);
console.log('Software-only synthetic QR results. Camera/optical transfer rates, OS/browser support, and BarcodeDetector are not measured.');

async function simulateTransfer(fileBytes: number, windowSize: number) {
  const data = fixture(fileBytes);
  const sender = new ProtocolSession('sender', { windowSize }, { name: 'benchmark.bin', data });
  const receiver = new ProtocolSession('receiver', { windowSize });
  const start = Date.now();
  let time = start;
  let approved = false;
  let saved = false;
  let senderFrames = 0;
  let receiverFrames = 0;
  let dataFrames = 0;
  let dropped = 0;
  const pending: Array<{ at: number; target: ProtocolSession; text: string }> = [];
  const cpuStart = performance.now();
  try {
    await Promise.all([sender.init(), receiver.init()]);
    // Logical time only: 350ms display interval, 175ms per-direction read/delivery delay.
    for (let tick = 0; tick < 30_000; tick++) {
      time = start + tick * 175;
      while (pending[0]?.at <= time) {
        const message = pending.shift()!;
        await message.target.receive(message.text);
      }
      if (!approved && sender.snapshot.state === 'authentication' && receiver.snapshot.state === 'authentication') {
        if (sender.snapshot.sas !== receiver.snapshot.sas) throw new Error('SAS mismatch in simulation');
        // Model the two operators' explicit comparison and approvals; no UI code is exercised.
        await Promise.all([sender.approve(), receiver.approve()]);
        approved = true;
      }
      if (!saved && receiver.snapshot.state === 'save') {
        if (!equal(receiver.snapshot.receivedFile!.data, data)) throw new Error('File mismatch in simulation');
        // Model successful writable.close(); this benchmark does not write a real received file.
        await receiver.confirmSaved();
        saved = true;
      }
      if (sender.snapshot.state === 'complete') {
        return {
          fileKiB: fileBytes / 1024, windowSize, simulatedSeconds: +((time - start) / 1000).toFixed(3),
          dataFrames, droppedFrames: dropped,
          retries: sender.snapshot.retries + receiver.snapshot.retries,
          cpuSeconds: +((performance.now() - cpuStart) / 1000).toFixed(3),
        };
      }
      for (const [source, target, direction] of [[sender, receiver, 'sender'], [receiver, sender, 'receiver']] as const) {
        const text = await source.nextFrame(time);
        if (!text) continue;
        if (direction === 'sender') senderFrames++;
        else receiverFrames++;
        if (decodeFrame(text).type === MessageType.DATA) dataFrames++;
        // Deterministic ~5% independent omissions in each direction, including ACK loss.
        if ((direction === 'sender' ? senderFrames % 19 : receiverFrames % 23) === 0) {
          dropped++;
          continue;
        }
        pending.push({ at: time + 175, target, text });
      }
      for (const session of [sender, receiver]) {
        if (session.snapshot.state === 'error' || session.snapshot.state === 'cancelled') {
          throw new Error(`Protocol simulation failed: ${session.role} ${session.snapshot.error}`);
        }
      }
    }
    throw new Error('Protocol simulation exhausted its time bound');
  } finally {
    sender.dispose(); receiver.dispose(); data.fill(0);
  }
}

if (process.env.QRBEAM_BENCH_PROTOCOL !== '0') {
  const transfers: Array<Awaited<ReturnType<typeof simulateTransfer>>> = [];
  for (const fileBytes of [10 * 1024, 100 * 1024, 1024 * 1024]) {
    for (const windowSize of [1, 2, 4, 8]) transfers.push(await simulateTransfer(fileBytes, windowSize));
  }
  console.log('Protocol simulation: 512-byte chunks; 4 KiB padding; 350ms display; 175ms one-way delay; deterministic ~5% loss each direction; synthetic approvals/save.');
  console.table(transfers);
  console.log('Simulated seconds are model output, not measured optical throughput. CPU seconds measure software execution only.');
}
