import jsQR from 'jsqr';

type Detector = { detect(source: CanvasImageSource): Promise<Array<{ rawValue: string }>> };
type DetectorConstructor = new (options: { formats: string[] }) => Detector;

export class CameraReader {
  private stream?: MediaStream;
  private running = false;
  private generation = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private readonly canvas = document.createElement('canvas');
  private detector?: Detector;
  private lastResult = '';
  private lastResultAt = 0;

  constructor(
    private readonly video: HTMLVideoElement,
    private readonly onResult: (text: string) => Promise<void>,
    private readonly onError: (code: string) => void,
  ) {
    const Native = (globalThis as typeof globalThis & { BarcodeDetector?: DetectorConstructor }).BarcodeDetector;
    try { if (Native) this.detector = new Native({ formats: ['qr_code'] }); } catch { /* local decoder remains available */ }
  }

  async start(deviceId?: string): Promise<void> {
    this.stop();
    const generation = this.generation;
    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: {
          width: { ideal: 1280 }, height: { ideal: 720 },
          ...(deviceId ? { deviceId: { exact: deviceId } } : {}),
        },
      });
    } catch (error) {
      if (generation !== this.generation) return;
      const name = error instanceof DOMException ? error.name : '';
      throw new Error(name === 'NotAllowedError' ? 'camera-denied' : name === 'NotFoundError' ? 'camera-missing' : 'camera-unavailable');
    }
    if (generation !== this.generation) {
      stream.getTracks().forEach(track => track.stop());
      return;
    }
    this.stream = stream;
    stream.getVideoTracks().forEach(track => { track.onended = () => {
      if (generation === this.generation) this.onError('camera-stopped');
    }; });
    this.video.srcObject = stream;
    try { await this.video.play(); }
    catch {
      if (generation !== this.generation) return;
      this.stop(); throw new Error('camera-unavailable');
    }
    if (generation !== this.generation) return;
    this.running = true;
    void this.scan(generation);
  }

  async devices(): Promise<MediaDeviceInfo[]> {
    return (await navigator.mediaDevices.enumerateDevices()).filter(device => device.kind === 'videoinput');
  }

  stop(): void {
    this.running = false;
    this.generation++;
    clearTimeout(this.timer);
    this.stream?.getTracks().forEach(track => { track.onended = null; track.stop(); });
    this.stream = undefined;
    this.video.srcObject = null;
    this.lastResult = '';
  }

  private async scan(generation: number): Promise<void> {
    if (!this.running || generation !== this.generation) return;
    try {
      if (this.video.readyState >= 2 && this.video.videoWidth > 0) {
        const scale = Math.min(1, 960 / this.video.videoWidth);
        this.canvas.width = Math.round(this.video.videoWidth * scale);
        this.canvas.height = Math.round(this.video.videoHeight * scale);
        const context = this.canvas.getContext('2d', { willReadFrequently: true });
        if (!context) throw new Error('camera-unavailable');
        context.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);
        let text: string | undefined;
        if (this.detector) {
          try { text = (await this.detector.detect(this.canvas))[0]?.rawValue; }
          catch {
            if (generation !== this.generation) return;
            this.detector = undefined;
          }
        }
        if (!this.running || generation !== this.generation) return;
        if (!text) {
          const pixels = context.getImageData(0, 0, this.canvas.width, this.canvas.height);
          text = jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: 'dontInvert' })?.data;
        }
        const now = Date.now();
        // Repeated DATA still reaches the protocol so a lost ACK can be recovered.
        if (text && text.length <= 4096 && (text !== this.lastResult || now - this.lastResultAt >= 300)) {
          this.lastResult = text;
          this.lastResultAt = now;
          await this.onResult(text);
        }
      }
    } catch {
      if (this.running && generation === this.generation) this.onError('camera-read-failed');
      return;
    }
    if (this.running && generation === this.generation) this.timer = setTimeout(() => void this.scan(generation), 100);
  }
}
