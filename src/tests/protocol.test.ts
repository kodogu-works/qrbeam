import { describe, expect, it, vi } from 'vitest';
import { ProtocolSession, type ProtocolConfig } from '../protocol';
import { decodeFrame, encodeFrame, MessageType, ZERO_SESSION } from '../protocol/frame';
import { equal, utf8 } from '../crypto/bytes';

const config: Partial<ProtocolConfig> = { minFrameIntervalMs: 0, maxRetries: 10_000 };
async function pair(size = 1000, overrides: Partial<ProtocolConfig> = {}) {
  const data = Uint8Array.from({ length: size }, (_, index) => index % 251);
  const sender = new ProtocolSession('sender', { ...config, ...overrides }, { name: 'private-秘密.bin', data });
  const receiver = new ProtocolSession('receiver', { ...config, ...overrides });
  await Promise.all([sender.init(), receiver.init()]);
  return { sender, receiver, data, time: Date.now(), count: 0, frames: [] as Array<{ from: 'sender' | 'receiver'; text: string; type: MessageType }> };
}
type Pair = Awaited<ReturnType<typeof pair>>;
async function step(p: Pair, deliver: (type: MessageType, from: 'sender' | 'receiver', count: number) => boolean = () => true) {
  p.time += 10; p.count++;
  for (const from of ['sender', 'receiver'] as const) {
    const text = await p[from].nextFrame(p.time);
    if (!text) continue;
    const type = decodeFrame(text).type;
    p.frames.push({ from, text, type });
    if (deliver(type, from, p.count)) await p[from === 'sender' ? 'receiver' : 'sender'].receive(text);
  }
}
async function until(p: Pair, done: () => boolean, limit = 2000, deliver?: Parameters<typeof step>[1]) {
  for (let i = 0; i < limit && !done(); i++) {
    await step(p, deliver);
    if (p.sender.snapshot.state === 'error' || p.receiver.snapshot.state === 'error') {
      throw new Error(JSON.stringify([p.sender.snapshot, p.receiver.snapshot]));
    }
  }
  expect(done(), JSON.stringify([p.sender.snapshot, p.receiver.snapshot])).toBe(true);
}
async function authenticate(p: Pair) {
  await until(p, () => p.sender.snapshot.state === 'authentication' && p.receiver.snapshot.state === 'authentication');
  expect(p.sender.snapshot.sas).toMatch(/^\d{3} \d{3}$/);
  expect(p.sender.snapshot.sas).toBe(p.receiver.snapshot.sas);
  await Promise.all([p.sender.approve(), p.receiver.approve()]);
}

describe('optical session state machine', () => {
  it('requires both explicit approvals and only completes after save confirmation reaches sender', async () => {
    const p = await pair();
    await until(p, () => p.sender.snapshot.state === 'authentication' && p.receiver.snapshot.state === 'authentication');
    for (let i = 0; i < 10; i++) await step(p);
    expect(p.frames.some(frame => [MessageType.START, MessageType.DATA].includes(frame.type))).toBe(false);
    await p.sender.approve();
    for (let i = 0; i < 10; i++) await step(p);
    expect(p.receiver.snapshot.peerApproved).toBe(true);
    expect(p.frames.some(frame => [MessageType.START, MessageType.DATA].includes(frame.type))).toBe(false);
    await p.receiver.approve();
    await until(p, () => p.receiver.snapshot.state === 'save');
    expect(p.receiver.snapshot.receivedFile?.data).toEqual(p.data);
    expect(p.sender.snapshot.state).toBe('save-wait');
    expect(p.frames.some(frame => frame.type === MessageType.COMPLETE)).toBe(false);
    await p.receiver.confirmSaved();
    expect(p.receiver.snapshot.state).toBe('complete');
    expect(p.receiver.snapshot.receivedFile).toBeUndefined();
    expect(p.sender.snapshot.state).toBe('save-wait');
    await step(p);
    expect(p.sender.snapshot.state).toBe('complete');
    expect(p.sender.snapshot.digest).toBe(p.receiver.snapshot.digest);
    const first = await p.receiver.nextFrame(p.time + 100);
    const second = await p.receiver.nextFrame(p.time + 200);
    expect(first).toBe(second);
    expect(decodeFrame(first!).type).toBe(MessageType.COMPLETE);
  });

  it.each([1, 2, 4, 8])('recovers handshake and ACK loss, duplicates and reordered DATA, window %i', async (windowSize) => {
    const p = await pair(10 * 1024, { windowSize });
    const droppedTypes = new Set<MessageType>();
    await until(p, () => p.sender.snapshot.state === 'authentication' && p.receiver.snapshot.state === 'authentication', 4000,
      (type) => { if (!droppedTypes.has(type)) { droppedTypes.add(type); return false; } return true; });
    await Promise.all([p.sender.approve(), p.receiver.approve()]);
    const pending: string[] = [];
    for (let i = 0; i < 6000 && p.receiver.snapshot.state !== 'save'; i++) {
      await step(p, (type, from, count) => {
        if (count % (from === 'sender' ? 5 : 7) === 0) return false;
        if (type === MessageType.DATA && from === 'sender') {
          pending.push(p.frames[p.frames.length - 1].text);
          return false;
        }
        return true;
      });
      if (i % 3 === 0) {
        for (const text of pending.splice(0).reverse()) {
          await p.receiver.receive(text);
          await p.receiver.receive(text);
        }
      }
    }
    expect(p.receiver.snapshot.state).toBe('save');
    expect(p.receiver.snapshot.receivedFile?.data).toEqual(p.data);
    await p.receiver.confirmSaved(); await until(p, () => p.sender.snapshot.state === 'complete');
  });

  it('transfers the complete 1 MiB binary limit', async () => {
    const p = await pair(1_048_576, { windowSize: 8, payloadBytes: 1024 });
    await authenticate(p);
    await until(p, () => p.receiver.snapshot.state === 'save', 6000);
    expect(equal(p.receiver.snapshot.receivedFile!.data, p.data)).toBe(true);
    await p.receiver.confirmSaved(); await until(p, () => p.sender.snapshot.state === 'complete');
  }, 30_000);

  it('ignores self HELLO and rejects same-role peers', async () => {
    const p = await pair();
    const own = await p.sender.nextFrame(p.time);
    await p.sender.receive(own!);
    expect(p.sender.snapshot.state).toBe('aligning');
    const other = new ProtocolSession('sender', config, { name: 'file', data: utf8('x') });
    await other.init();
    await p.sender.receive((await other.nextFrame(p.time))!);
    expect(p.sender.snapshot.error).toBe('ROLE_CONFLICT');
  });

  it('does not disclose sender nonce before COMMIT and rejects a changed commitment', async () => {
    const p = await pair();
    let changed = false;
    for (let i = 0; i < 1000 && p.sender.snapshot.state !== 'error'; i++) {
      p.time += 10;
      for (const from of ['sender', 'receiver'] as const) {
        let text = await p[from].nextFrame(p.time);
        if (!text) continue;
        const frame = decodeFrame(text);
        if (from === 'sender' && frame.type === MessageType.NONCE) expect(changed).toBe(true);
        if (from === 'receiver' && frame.type === MessageType.COMMIT) {
          frame.payload[0] ^= 1;
          text = await encodeFrame(frame);
          changed = true;
        }
        await p[from === 'sender' ? 'receiver' : 'sender'].receive(text);
      }
    }
    expect(p.sender.snapshot.error).toBe('COMMITMENT_INVALID');
    expect(p.sender.snapshot.sas).toBeUndefined();
  });

  it('uses identical KEY, COMMIT and NONCE values on retransmission', async () => {
    const p = await pair();
    await authenticate(p);
    const immutable = new Map<string, string>();
    for (const frame of p.frames) if ([MessageType.KEY, MessageType.COMMIT, MessageType.NONCE].includes(frame.type)) {
      const id = `${frame.from}/${frame.type}`;
      if (immutable.has(id)) expect(frame.text).toBe(immutable.get(id));
      immutable.set(id, frame.text);
    }
    expect(immutable.size).toBe(5);
  });

  it('rejects reflected READY instead of accepting peer approval', async () => {
    const p = await pair();
    await until(p, () => p.sender.snapshot.state === 'authentication' && p.receiver.snapshot.state === 'authentication');
    await p.sender.approve();
    let reflected: string | undefined;
    for (let i = 0; i < 5 && !reflected; i++) {
      const text = await p.sender.nextFrame(p.time += 10);
      if (text && decodeFrame(text).type === MessageType.READY) reflected = text;
    }
    expect(reflected).toBeDefined();
    await p.sender.receive(reflected!);
    expect(p.sender.snapshot.peerApproved).toBe(false);
    expect(p.sender.snapshot.error).toBe('READY_MAC_INVALID');
  });

  it('ignores foreign sessions and unauthenticated DATA/ACK after keys exist', async () => {
    const p = await pair(); await authenticate(p);
    const before = p.receiver.snapshot;
    await p.receiver.receive(await encodeFrame({ type: MessageType.DATA, sequence: 700, sessionId: ZERO_SESSION, payload: utf8('bad') }));
    const sid = Uint8Array.from(before.sessionId!.match(/../g)!, x => parseInt(x, 16));
    await p.receiver.receive(await encodeFrame({ type: MessageType.DATA, sequence: 701, sessionId: sid, payload: utf8('bad') }));
    expect(p.receiver.snapshot).toEqual(before);
  });

  it('times out unilateral approval and destroys the SAS and file references', async () => {
    const p = await pair();
    await until(p, () => p.sender.snapshot.state === 'authentication' && p.receiver.snapshot.state === 'authentication');
    await p.sender.approve();
    await p.sender.nextFrame(p.time + 180_001);
    expect(p.sender.snapshot.error).toBe('APPROVAL_TIMEOUT');
    expect(p.sender.snapshot.sas).toBeUndefined();
    expect(p.sender.snapshot.receivedFile).toBeUndefined();
  });

  it('does not emit COMPLETE after saving is cancelled, failed or session cancelled during save', async () => {
    const p = await pair(); await authenticate(p);
    await until(p, () => p.receiver.snapshot.state === 'save');
    for (let i = 0; i < 10; i++) await step(p);
    expect(p.frames.some(f => f.type === MessageType.COMPLETE)).toBe(false);
    await p.receiver.cancel('SAVE_INCOMPLETE');
    await p.receiver.confirmSaved();
    await step(p);
    expect(p.receiver.snapshot.state).toBe('cancelled');
    expect(p.sender.snapshot.error).toBe('PEER_NOT_SAVED');
    expect(p.frames.some(f => f.type === MessageType.COMPLETE)).toBe(false);
  });

  it('keeps sender completion unconfirmed if COMPLETE is lost and expires the session', async () => {
    const p = await pair(); await authenticate(p);
    await until(p, () => p.receiver.snapshot.state === 'save');
    await p.receiver.confirmSaved();
    await p.sender.nextFrame(p.time + 300_001);
    expect(p.sender.snapshot.error).toBe('SAVE_TIMEOUT_UNCONFIRMED');
    expect(p.sender.snapshot.state).toBe('error');
    const q = await pair();
    await q.sender.nextFrame(q.time + 3_600_001);
    expect(q.sender.snapshot.error).toBe('SESSION_EXPIRED');
  });

  it('retains READY until the peer sees it even when the first three READY frames disappear', async () => {
    const p = await pair(); await authenticate(p);
    const dropped = { sender: 0, receiver: 0 };
    await until(p, () => p.receiver.snapshot.state === 'save', 2000, (type, from) => {
      if (type === MessageType.READY && dropped[from]++ < 3) return false;
      return true;
    });
    expect(dropped.sender).toBeGreaterThanOrEqual(4);
    expect(dropped.receiver).toBeGreaterThanOrEqual(4);
  });

  it('does not restart the approval timeout when delayed READY arrives during transfer', async () => {
    const p = await pair(100_000); await authenticate(p);
    await until(p, () => p.receiver.snapshot.state === 'transferring');
    const ready = p.frames.find(frame => frame.from === 'receiver' && frame.type === MessageType.READY)!;
    await p.sender.receive(ready.text);
    await p.sender.nextFrame(p.time + 180_001);
    expect(p.sender.snapshot.state).toBe('transferring');
    expect(p.sender.snapshot.remainingMs).toBeUndefined();
    expect(p.sender.snapshot.error).toBeUndefined();
  });

  it('does not restore secret state when disposed during initialization', async () => {
    const sender = new ProtocolSession('sender', config, { name: 'file', data: utf8('secret') });
    const initializing = sender.init();
    await Promise.resolve();
    sender.dispose();
    await initializing;
    expect(Reflect.get(sender, 'privateKey')).toBeUndefined();
    expect(Reflect.get(sender, 'keys')).toBeUndefined();
    expect(await sender.nextFrame()).toBeNull();
  });

  it('does not restore keys when disposed during asynchronous ECDH derivation', async () => {
    const p = await pair();
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    const original = crypto.subtle.deriveBits.bind(crypto.subtle);
    const spy = vi.spyOn(crypto.subtle, 'deriveBits').mockImplementationOnce(async (algorithm, baseKey, length) => {
      entered(); await gate;
      return original(algorithm, baseKey, length);
    });
    const driving = (async () => { for (let i = 0; i < 100; i++) await step(p); })();
    try {
      await started;
      p.receiver.dispose(); release();
      await driving;
      expect(Reflect.get(p.receiver, 'keys')).toBeUndefined();
      expect(Reflect.get(p.receiver, 'privateKey')).toBeUndefined();
      expect(p.receiver.snapshot.sas).toBeUndefined();
      expect(await p.receiver.nextFrame()).toBeNull();
    } finally { release(); spy.mockRestore(); }
  });
});
