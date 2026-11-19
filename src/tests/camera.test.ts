import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CameraReader } from '../camera';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fakeStream() {
  const track = { stop: vi.fn(), onended: null as (() => void) | null };
  return { getTracks: () => [track], getVideoTracks: () => [track], track };
}

describe('camera lifecycle', () => {
  beforeEach(() => {
    vi.stubGlobal('document', { createElement: () => ({}) });
  });
  afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

  it('stops a permission result which arrives after stop()', async () => {
    const pending = deferred<unknown>();
    vi.stubGlobal('navigator', { mediaDevices: { getUserMedia: () => pending.promise } });
    const video = { srcObject: null, play: vi.fn(), readyState: 0 };
    const reader = new CameraReader(video as unknown as HTMLVideoElement, vi.fn(), vi.fn());
    const starting = reader.start();
    reader.stop();
    const stream = fakeStream();
    pending.resolve(stream);
    await starting;
    expect(stream.track.stop).toHaveBeenCalledOnce();
    expect(video.play).not.toHaveBeenCalled();
  });

  it('ignores old play rejection without stopping the replacement stream', async () => {
    const playback = deferred<void>();
    const first = fakeStream(), second = fakeStream();
    vi.stubGlobal('navigator', { mediaDevices: { getUserMedia: vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(second) } });
    const video = { srcObject: null, play: vi.fn().mockReturnValueOnce(playback.promise).mockResolvedValue(undefined), readyState: 0 };
    const error = vi.fn();
    const reader = new CameraReader(video as unknown as HTMLVideoElement, vi.fn(), error);
    const starting = reader.start();
    await vi.waitFor(() => expect(video.play).toHaveBeenCalledOnce());
    await reader.start('replacement');
    playback.reject(new Error('play interrupted'));
    await starting;
    expect(second.track.stop).not.toHaveBeenCalled();
    expect(video.srcObject).toBe(second);
    expect(error).not.toHaveBeenCalled();
    reader.stop();
  });

  it('ignores a stale permission rejection after a replacement succeeded', async () => {
    const permission = deferred<unknown>();
    const second = fakeStream();
    vi.stubGlobal('navigator', { mediaDevices: { getUserMedia: vi.fn().mockReturnValueOnce(permission.promise).mockResolvedValueOnce(second) } });
    const video = { srcObject: null, play: vi.fn().mockResolvedValue(undefined), readyState: 0 };
    const reader = new CameraReader(video as unknown as HTMLVideoElement, vi.fn(), vi.fn());
    const starting = reader.start();
    await reader.start('replacement');
    permission.reject(new DOMException('blocked', 'NotAllowedError'));
    await starting;
    expect(second.track.stop).not.toHaveBeenCalled();
    expect(video.srcObject).toBe(second);
    reader.stop();
  });

  it('discards stale native detection results and errors after stop()', async () => {
    const detection = deferred<Array<{rawValue: string}>>();
    const detect = vi.fn().mockReturnValue(detection.promise);
    vi.stubGlobal('BarcodeDetector', class { detect = detect; });
    vi.stubGlobal('document', { createElement: () => ({ getContext: () => ({ drawImage: vi.fn() }) }) });
    vi.stubGlobal('navigator', { mediaDevices: { getUserMedia: async () => fakeStream() } });
    const video = { srcObject: null, play: async () => undefined, readyState: 2, videoWidth: 1280, videoHeight: 720 };
    const result = vi.fn(), error = vi.fn();
    const reader = new CameraReader(video as unknown as HTMLVideoElement, result, error);
    await reader.start();
    expect(detect).toHaveBeenCalledOnce();
    reader.stop();
    detection.resolve([{ rawValue: 'old-session-frame' }]);
    await Promise.resolve(); await Promise.resolve();
    expect(result).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
  });
});
