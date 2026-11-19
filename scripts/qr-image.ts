import QRCode from 'qrcode';

export function createQR(text: string, mode: 'alphanumeric' | 'byte') {
  const segment: QRCode.QRCodeSegment = mode === 'alphanumeric'
    ? { data: text, mode: 'alphanumeric' } : { data: new TextEncoder().encode(text), mode: 'byte' };
  return QRCode.create([segment], { errorCorrectionLevel: 'M' });
}

/** Synthetic, noise-free QR fixture. It is not an optical-camera benchmark. */
export function qrImage(text: string, mode: 'alphanumeric' | 'byte' = 'alphanumeric', scale = 4) {
  const qr = createQR(text, mode);
  const margin = 4;
  const width = (qr.modules.size + margin * 2) * scale;
  const pixels = new Uint8ClampedArray(width * width * 4);
  pixels.fill(255);
  for (let row = 0; row < qr.modules.size; row++) {
    for (let column = 0; column < qr.modules.size; column++) {
      if (!qr.modules.get(row, column)) continue;
      for (let y = 0; y < scale; y++) {
        const pixelY = (row + margin) * scale + y;
        for (let x = 0; x < scale; x++) {
          const offset = (pixelY * width + (column + margin) * scale + x) * 4;
          pixels[offset] = pixels[offset + 1] = pixels[offset + 2] = 0;
        }
      }
    }
  }
  return { pixels, width, height: width, version: qr.version, modules: qr.modules.size };
}
