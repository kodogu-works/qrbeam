import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

type OpticalFixture = {
  camera: HTMLCanvasElement;
  stream: MediaStream;
  cspViolations: string[];
  cancelNextSave: boolean;
  saveCalls: number;
  writes: number[][];
  closeRequested: boolean;
  closeResolved: boolean;
  resolveClose?: () => void;
};
declare global { interface Window { __optical: OpticalFixture } }

async function installDevices(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const camera = document.createElement('canvas');
    camera.width = camera.height = 900;
    const context = camera.getContext('2d')!;
    context.fillStyle = '#ffffff';
    context.fillRect(0, 0, camera.width, camera.height);
    const stream = camera.captureStream(10);
    window.__optical = {
      camera, stream, cspViolations: [], cancelNextSave: false,
      saveCalls: 0, writes: [], closeRequested: false, closeResolved: false,
    };
    window.addEventListener('securitypolicyviolation', event => {
      window.__optical.cspViolations.push(`${event.effectiveDirective}: ${event.blockedURI}`);
    });
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: {
        getUserMedia: async () => stream,
        enumerateDevices: async () => [{ kind: 'videoinput', deviceId: 'synthetic-camera', groupId: 'synthetic', label: 'Synthetic optical camera' }],
      },
    });
    // Exercise the actual bundled jsQR path, including video -> canvas decoding.
    Object.defineProperty(globalThis, 'BarcodeDetector', { configurable: true, value: undefined });
    Object.defineProperty(globalThis, 'showSaveFilePicker', {
      configurable: true,
      value: async () => {
        const fixture = window.__optical;
        fixture.saveCalls++;
        if (fixture.cancelNextSave) {
          fixture.cancelNextSave = false;
          throw new DOMException('Synthetic user cancellation', 'AbortError');
        }
        return {
          createWritable: async () => ({
            write: async (data: Uint8Array) => { fixture.writes.push(Array.from(new Uint8Array(data))); },
            close: async () => {
              fixture.closeRequested = true;
              await new Promise<void>(resolve => {
                fixture.resolveClose = () => { fixture.closeResolved = true; resolve(); };
              });
            },
            abort: async () => undefined,
          }),
        };
      },
    });
  });
}

async function captureQR(page: Page): Promise<string> {
  return page.locator('#qr-canvas').evaluate(canvas => (canvas as HTMLCanvasElement).toDataURL('image/png'));
}

async function showInCamera(page: Page, dataUrl: string): Promise<void> {
  await page.evaluate(async value => {
    const image = new Image();
    image.src = value;
    await image.decode();
    const canvas = window.__optical.camera;
    const context = canvas.getContext('2d')!;
    context.fillStyle = '#ffffff';
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
  }, dataUrl);
}

test('single-file offline optical transfer requires both approvals and successful save close', async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1366, height: 1000 }, offline: true });
  const sender = await context.newPage();
  const receiver = await context.newPage();
  const pageErrors: string[] = [];
  const networkRequests: string[] = [];
  for (const page of [sender, receiver]) {
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('request', request => { if (/^https?:/i.test(request.url())) networkRequests.push(request.url()); });
  }
  await Promise.all([installDevices(sender), installDevices(receiver)]);
  let running = false;
  let relay: Promise<void> | undefined;
  let relayError: unknown;
  try {
    const artifact = pathToFileURL(path.resolve('dist/qrbeam.html')).href;
    await Promise.all([sender.goto(artifact), receiver.goto(artifact)]);
    for (const page of [sender, receiver]) {
      await expect(page.locator('#capabilities')).toContainText('必要なAPIを検出しました');
      await expect(page.locator('#network-status')).toHaveText('ブラウザ報告：オフライン');
    }
    const original = Buffer.from(Array.from({ length: 512 }, (_, index) => index & 255));
    await sender.locator('#choose-sender').click();
    await sender.locator('#file-input').setInputFiles({ name: '秘密-テスト.bin', mimeType: 'application/octet-stream', buffer: original });
    await receiver.locator('#choose-receiver').click();
    await sender.locator('#begin').click();
    await receiver.locator('#begin').click();
    await expect(sender.locator('#workspace')).toBeVisible();
    await expect(receiver.locator('#workspace')).toBeVisible();

    // Keep Enter pressed before S4 appears; a repeated keydown must not approve it.
    await sender.keyboard.down('Enter');
    running = true;
    relay = (async () => {
      while (running) {
        const [senderQR, receiverQR] = await Promise.all([captureQR(sender), captureQR(receiver)]);
        await Promise.all([showInCamera(receiver, senderQR), showInCamera(sender, receiverQR)]);
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    })().catch(error => { relayError = error; });

    await expect(sender.locator('#sas-code')).toHaveText(/^\d{3} \d{3}$/);
    await expect(receiver.locator('#sas-code')).toHaveText(await sender.locator('#sas-code').innerText());
    await sender.locator('#approve').focus();
    await new Promise(resolve => setTimeout(resolve, 1700));
    await sender.keyboard.down('Enter');
    await expect(sender.locator('#local-approval')).toHaveText('このPC：未承認');
    await expect(receiver.locator('#local-approval')).toHaveText('このPC：未承認');
    await expect(sender.locator('#progress-section')).toBeHidden();
    await sender.keyboard.up('Enter');
    await sender.keyboard.press('Enter');
    await expect(sender.locator('#local-approval')).toHaveText('このPC：承認済み');
    await expect(receiver.locator('#peer-approval')).toHaveText('相手PC：承認を検証済み');
    await expect(sender.locator('#state-title')).toHaveText('双方の承認を確認');
    await expect(receiver.locator('#progress-section')).toBeHidden();
    await expect(receiver.locator('#save-section')).toBeHidden();
    expect(await receiver.evaluate(() => window.__optical.writes.length)).toBe(0);

    await receiver.locator('#approve').click();
    await expect(receiver.locator('#save-file')).toBeVisible();
    await expect(receiver.locator('#received-name')).toHaveText('秘密-テスト.bin');
    await expect(sender.locator('#state-title')).toHaveText('受信側で保存操作中');

    // A cancelled picker leaves the transfer unconfirmed and permits an explicit retry.
    await receiver.evaluate(() => { window.__optical.cancelNextSave = true; });
    await receiver.locator('#save-file').click();
    await expect(receiver.locator('#save-status')).toContainText('保存を取り消しました');
    await expect(sender.locator('#state-title')).toHaveText('受信側で保存操作中');
    await expect(receiver.locator('#save-file')).toBeEnabled();

    await receiver.locator('#save-file').click();
    await expect.poll(() => receiver.evaluate(() => window.__optical.closeRequested)).toBe(true);
    // Let several display/read cycles pass so premature COMPLETE would reach the sender.
    await new Promise(resolve => setTimeout(resolve, 1200));
    expect(await receiver.evaluate(() => window.__optical.closeResolved)).toBe(false);
    expect(await receiver.evaluate(() => window.__optical.writes)).toEqual([Array.from(original)]);
    await expect(sender.locator('#state-title')).toHaveText('受信側で保存操作中');
    await expect(receiver.locator('#state-title')).toHaveText('検証成功・保存してください');
    await expect(receiver.locator('#save-file')).toBeDisabled();
    await receiver.evaluate(() => window.__optical.resolveClose!());
    await expect(receiver.locator('#state-title')).toHaveText('検証成功・保存済み');
    await expect(sender.locator('#state-title')).toHaveText('転送完了');
    await expect(sender.locator('#file-digest')).toHaveText(await receiver.locator('#file-digest').innerText());
    expect(await receiver.evaluate(() => window.__optical.saveCalls)).toBe(2);
    expect(await receiver.evaluate(() => window.__optical.writes)).toEqual([Array.from(original)]);
    for (const page of [sender, receiver]) expect(await page.evaluate(() => window.__optical.cspViolations)).toEqual([]);
    expect(networkRequests).toEqual([]);
    expect(pageErrors).toEqual([]);
    expect(relayError).toBeUndefined();
  } finally {
    running = false;
    await relay;
    await context.close();
  }
});
