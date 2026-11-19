import { create } from 'qrcode/lib/core/qrcode.js';

export type Correction = 'L' | 'M' | 'Q' | 'H';

/** Explicit alphanumeric mode keeps Base45 equally readable by both decoders. */
export async function renderQR(canvas: HTMLCanvasElement, text: string, correction: Correction = 'M'): Promise<void> {
  if (!text || text.length > 4096) throw new Error('qr-capacity');
  const qr = create([{ data: text, mode: 'alphanumeric' }], { errorCorrectionLevel: correction });
  const scale = Math.max(4, Math.floor(900 / (qr.modules.size + 8)));
  canvas.width = canvas.height = (qr.modules.size + 8) * scale;
  const context = canvas.getContext('2d');
  if (!context) throw new Error('qr-capacity');
  context.fillStyle = '#ffffff';
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = '#000000';
  for (let row = 0; row < qr.modules.size; row++) {
    for (let col = 0; col < qr.modules.size; col++) {
      if (qr.modules.get(row, col)) context.fillRect((col + 4) * scale, (row + 4) * scale, scale, scale);
    }
  }
}
