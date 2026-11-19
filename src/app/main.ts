import { ProtocolSession } from '../protocol';
import type { Role } from '../crypto';
import { unhex } from '../crypto/bytes';
import { AuditLog } from '../audit';
import { CameraReader } from '../camera';
import { renderQR, type Correction } from '../qr/render';
import { saveVerifiedFile, type FileInput } from '../transfer';
import { EnterGuard } from '../security/enter-guard';
import { DEFAULT_CONFIG, readConfig } from './config';

declare const __BUILD_ID__: string;

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error('invalid-app');
  return node as T;
}
function show(id: string, visible: boolean): void { element(id).hidden = !visible; }
function text(id: string, value: string): void {
  const node = element(id);
  if (node.textContent !== value) node.textContent = value;
}

const MESSAGES: Record<string, string> = {
  'camera-denied': 'カメラが許可されていません。ブラウザとOSのカメラ権限を確認し、最初からやり直してください。',
  'camera-missing': '使用できるカメラがありません。Webカメラを接続し、最初からやり直してください。',
  'camera-unavailable': 'カメラを開始できません。他のアプリによる使用やブラウザの権限設定を確認してください。',
  'camera-stopped': 'カメラが停止したため転送を中断しました。接続と権限を確認し、新しいセッションでやり直してください。',
  'camera-read-failed': 'カメラ映像を読み取れないため転送を中断しました。カメラを確認してください。',
  'same-role': '両PCが同じ役割です。一方で「送信」、もう一方で「受信」を選び、最初からやり直してください。',
  'role-mismatch': '両PCが同じ役割です。一方で「送信」、もう一方で「受信」を選び、最初からやり直してください。',
  'handshake-timeout': '鍵交換の期限を超えました。相手のQR全体が映るよう配置を調整し、最初からやり直してください。',
  'approval-timeout': '承認待ちの期限を超えました。双方でコードを確認して、新しいセッションでやり直してください。',
  'save-timeout': '受信側での保存完了を確認できませんでした（完了未確認）。受信側の保存結果を確認してください。',
  'session-expired': 'セッションの有効期限が切れました。鍵を破棄しました。最初からやり直してください。',
  'commitment-failed': 'コミットメント検証に失敗しました。認証コードは表示せず中断しました。攻撃の可能性があります。',
  'commitment-mismatch': 'コミットメント検証に失敗しました。攻撃の可能性があります。新しいセッションが必要です。',
  'invalid-public-key': '相手の公開鍵が不正なため中断しました。新しいセッションが必要です。',
  'sas-mismatch': '認証コードが一致しないため中断しました。鍵を破棄しました。新しいセッションが必要です。',
  'ready-mac-failed': '相手の承認メッセージを認証できず中断しました。新しいセッションが必要です。',
  'invalid-ready': '相手の承認メッセージが一致せず中断しました。新しいセッションが必要です。',
  'digest-mismatch': '保存完了通知のダイジェストが一致しません。転送は完了扱いにできません。',
  'decrypt-failed': '暗号文の認証に失敗しました。保存できません。新しいセッションでやり直してください。',
  'hash-mismatch': 'ファイルの検証に失敗しました。保存できません。',
  'save-incomplete': '受信側で未保存のまま中断しました。転送は完了していません。',
  'save-cancelled': '保存を取り消しました。まだ完了していません。「保存」で再試行できます。',
  'save-failed': '保存できませんでした。空き容量と保存先の権限を確認し、「保存」で再試行してください。',
  'save-session-ended': 'セッションが中断されたため保存処理を中止しました。新しいセッションでやり直してください。',
  'unsupported-save': 'この環境では保存完了を確認できるAPIが利用できません。対応するPC版Chrome / Edgeで開いてください。',
  'retry-limit': '再表示回数の上限を超えました。距離・角度・明るさを調整し、新しいセッションでやり直してください。',
  'invalid-settings': '通信設定の値が範囲外です。設定を確認してください。',
  'qr-capacity': 'QRを表示できませんでした。DATA容量や誤り訂正の設定を見直してください。',
  'cancelled': '転送を中断しました。完了していません。',
  'peer-cancelled': '相手が転送を中断しました。完了していません。',
};
function message(code: unknown): string {
  const raw = typeof code === 'string' ? code : code instanceof Error ? code.message : '';
  const aliases: Record<string, string> = {
    ROLE_CONFLICT: 'role-mismatch', PUBLIC_KEY_INVALID: 'invalid-public-key',
    COMMITMENT_INVALID: 'commitment-failed', COMMITMENT_CHANGED: 'commitment-failed',
    READY_MAC_INVALID: 'ready-mac-failed', READY_TRANSCRIPT_INVALID: 'invalid-ready',
    COMPLETE_DIGEST_INVALID: 'digest-mismatch', FILE_VERIFICATION_FAILED: 'decrypt-failed',
    SAVE_TIMEOUT_UNCONFIRMED: 'save-timeout', PEER_NOT_SAVED: 'save-incomplete',
    USER_CANCELLED: 'cancelled', PEER_CANCELLED: 'peer-cancelled',
    SESSION_EXPIRED: 'session-expired', HANDSHAKE_TIMEOUT: 'handshake-timeout',
    APPROVAL_TIMEOUT: 'approval-timeout', RETRY_LIMIT: 'retry-limit',
    SAS_MISMATCH: 'sas-mismatch', SAVE_INCOMPLETE: 'save-incomplete', CAMERA_STOPPED: 'camera-stopped',
  };
  const key = aliases[raw] ?? raw;
  return MESSAGES[key] ?? 'セッションを続けられないため中断しました。転送は完了していません。配置と設定を確認し、最初からやり直してください。';
}
function notice(value = ''): void { text('global-notice', value); show('global-notice', !!value); }
function formatBytes(value: number): string { return `${value.toLocaleString('ja-JP')} バイト`; }

let role: Role | undefined;
let selectedFile: File | undefined;
let session: ProtocolSession | undefined;
let audit: AuditLog | undefined;
let previousState = '';
let lastQR = '';
let lastScan = 0;
let opening = false;
let saving = false;
let saveController: AbortController | undefined;
let correction: Correction = 'M';
const guard = new EnterGuard(DEFAULT_CONFIG.sasEnterGuardMs);
let auditSessionSet = false;
let failures = 0;
try { failures = Math.min(100, Math.max(0, Number(localStorage.getItem('qrbeam.sasFailures')) || 0)); } catch { /* optional counter only */ }
show('security-warning', failures >= 2);

function saveFailureCounter(): void {
  try { localStorage.setItem('qrbeam.sasFailures', String(failures)); } catch { /* optional counter only */ }
  show('security-warning', failures >= 2);
}

function onAuditEvent(event: string): void {
  if (['cancel', 'error', 'timeout', 'incomplete', 'session-end'].includes(event)) saveController?.abort();
  if (!audit) return;
  try {
    const snapshot = session?.snapshot;
    if (snapshot?.sessionId && !auditSessionSet) { audit.setSession(unhex(snapshot.sessionId)); auditSessionSet = true; }
    const result = event === 'complete' ? 'success' : ['error', 'commitment-failed', 'sas-mismatch'].includes(event) ? 'failure'
      : event === 'cancel' ? 'cancelled' : event === 'incomplete' ? 'unconfirmed' : undefined;
    audit.record(event, result, snapshot?.digest ? unhex(snapshot.digest) : undefined);
    if (event === 'sas-mismatch' || event === 'commitment-failed') {
      failures++;
      saveFailureCounter();
      if (failures >= 2) audit.record('sas-warning', 'failure');
    }
    if (event === 'complete') { failures = 0; saveFailureCounter(); }
  } catch { /* Never log arbitrary data from a protocol or browser exception. */ }
}

const camera = new CameraReader(element<HTMLVideoElement>('camera-preview'), async value => {
  const active = session;
  if (!active) return;
  lastScan = Date.now();
  await active.receive(value);
  if (active === session) update();
}, code => {
  const active = session;
  if (!active) return;
  notice(message(code));
  void active.cancel('CAMERA_STOPPED').then(() => { if (active === session) { camera.stop(); update(); } });
});

function capabilityCheck(): boolean {
  const missing: string[] = [];
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle) missing.push('Web Crypto');
  if (!navigator.mediaDevices?.getUserMedia) missing.push('カメラAPI');
  if (!(globalThis as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker) missing.push('保存API');
  const mobile = /Android|iPhone|iPad|Mobile/i.test(navigator.userAgent);
  if (mobile) missing.push('PC環境');
  text('capabilities', missing.length ? `非対応の環境です：${missing.join('・')}。PC版Chrome / Edgeで開いてください。`
    : '必要なAPIを検出しました。カメラと保存の file:// 動作はこのPCでの確認が必要です。');
  return missing.length === 0;
}
const capable = capabilityCheck();
text('build-id', __BUILD_ID__);

function networkStatus(): void {
  text('network-status', navigator.onLine ? 'ブラウザ報告：オンライン' : 'ブラウザ報告：オフライン');
}
networkStatus();
window.addEventListener('online', networkStatus);
window.addEventListener('offline', networkStatus);

function choose(next: Role): void {
  role = next;
  element('choose-sender').setAttribute('aria-pressed', String(next === 'sender'));
  element('choose-receiver').setAttribute('aria-pressed', String(next === 'receiver'));
  show('file-section', next === 'sender');
  show('receive-description', next === 'receiver');
  updateBegin();
}
function updateBegin(): void {
  element<HTMLButtonElement>('begin').disabled = opening || !capable || !role || (role === 'sender' && !selectedFile);
  element<HTMLButtonElement>('choose-sender').disabled = opening;
  element<HTMLButtonElement>('choose-receiver').disabled = opening;
  element<HTMLInputElement>('file-input').disabled = opening;
}
element('choose-sender').addEventListener('click', () => choose('sender'));
element('choose-receiver').addEventListener('click', () => choose('receiver'));
element<HTMLInputElement>('file-input').addEventListener('change', event => {
  const input = event.currentTarget as HTMLInputElement;
  selectedFile = undefined;
  const file = input.files?.[0];
  if (file) {
    if (file.size > 1_048_576) { notice('ファイルの上限は1 MiB（1,048,576バイト）です。'); input.value = ''; }
    else if (new TextEncoder().encode(file.name).length > 255) { notice('ファイル名はUTF-8で255バイト以内にしてください。'); input.value = ''; }
    else { selectedFile = file; text('file-description', `${file.name} / ${formatBytes(file.size)}`); notice(); }
  }
  if (!selectedFile) text('file-description', '1 MiB（1,048,576バイト）以下・1ファイル');
  updateBegin();
});

element('begin').addEventListener('click', async () => {
  if (!role || opening || !capable || (role === 'sender' && !selectedFile)) return;
  opening = true;
  updateBegin();
  notice();
  try {
    const form = element<HTMLFormElement>('settings-form');
    if (!form.reportValidity()) return;
    const config = readConfig(form);
    correction = element<HTMLSelectElement>('correction').value as Correction;
    let file: FileInput | undefined;
    if (role === 'sender' && selectedFile) file = { name: selectedFile.name, data: new Uint8Array(await selectedFile.arrayBuffer()) };
    audit = new AuditLog(__BUILD_ID__, role);
    auditSessionSet = false;
    await camera.start(element<HTMLSelectElement>('camera-select').value || undefined);
    await listCameras();
    session = new ProtocolSession(role, config, file);
    session.onEvent = onAuditEvent;
    await session.init();
    selectedFile = undefined;
    element<HTMLInputElement>('file-input').value = '';
    element<HTMLFieldSetElement>('settings-fields').disabled = true;
    show('setup', false);
    show('workspace', true);
    text('role-label', role === 'sender' ? '送信PC' : '受信PC');
    text('camera-status', '撮影中');
    text('audit-id', audit.id);
    previousState = '';
    lastQR = '';
    lastScan = Date.now();
    update();
  } catch (error) {
    camera.stop();
    session?.dispose();
    session = undefined;
    notice(message(error));
  } finally { opening = false; updateBegin(); }
});

async function listCameras(): Promise<void> {
  const select = element<HTMLSelectElement>('camera-select');
  const current = select.value;
  try {
    const devices = await camera.devices();
    select.replaceChildren(new Option('既定のカメラ', ''));
    devices.forEach((device, index) => select.add(new Option(device.label || `カメラ ${index + 1}`, device.deviceId)));
    select.value = current;
  } catch { /* Permission/platform may hide device labels; default camera still works. */ }
}
element('camera-select').addEventListener('change', async () => {
  const active = session;
  if (!active || active.snapshot.state !== 'aligning') return;
  try { await camera.start(element<HTMLSelectElement>('camera-select').value || undefined); }
  catch (error) { if (active === session) { notice(message(error)); await active.cancel('CAMERA_STOPPED'); update(); } }
});

const DESCRIPTIONS: Record<string, [string, string, string]> = {
  'aligning': ['位置合わせ', '双方の画面を向かい合わせてください。相手のHELLOを読み取り、相互到達を確認します。', 'align'],
  'key-exchange': ['鍵交換', '公開鍵・コミットメント・nonceを交換しています。相手のQRを映し続けてください。', 'align'],
  'authentication': ['認証コードを照合', '両PCに表示された6桁を目視で比較してください。まだファイルは送信していません。', 'auth'],
  'approval-wait': ['双方の承認を確認', '両PCでの承認と、認証付きREADYの交換を待っています。', 'auth'],
  'transferring': ['暗号化ファイルを転送中', 'QRを巡回表示しています。受信確認がないフレームだけ再表示します。', 'transfer'],
  'save-wait': ['受信側で保存操作中', '転送完了はまだ確認できていません。受信側で保存し、QRを映し続けてください。', 'transfer'],
  'save': ['検証成功・保存してください', '内容の認証と検証に成功しました。「保存」で保存先を選んでください。', 'transfer'],
  'complete': ['転送完了', '保存後の完了通知とファイルダイジェストを検証しました。', 'complete'],
  'cancelled': ['中止', '転送を中断しました。新しいセッションでやり直してください。', 'prepare'],
  'error': ['転送を完了できませんでした', '完了していません。原因を確認して、新しいセッションでやり直してください。', 'prepare'],
};

function update(): void {
  if (!session) return;
  const snapshot = session.snapshot;
  const state = snapshot.state;
  const terminal = state === 'error' || state === 'cancelled';
  const complete = state === 'complete';
  const authentication = (state === 'authentication' || state === 'approval-wait') && !snapshot.localApproved;
  const details = DESCRIPTIONS[state] ?? DESCRIPTIONS.error;
  text('state-title', complete && role === 'receiver' ? '検証成功・保存済み' : details[0]);
  text('state-description', terminal && snapshot.error ? message(snapshot.error)
    : complete && role === 'receiver' ? '保存が完了しました。送信側の「転送完了」表示を確認するまで、この完了QRを表示し続けてください。' : details[1]);
  for (const step of ['prepare', 'align', 'auth', 'transfer', 'complete']) {
    const node = element(`step-${step}`);
    if (step === details[2]) node.setAttribute('aria-current', 'step'); else node.removeAttribute('aria-current');
  }
  if (state !== previousState) {
    if (authentication) guard.show(Date.now());
    if (terminal) { camera.stop(); text('camera-status', '停止'); }
    previousState = state;
  }
  show('auth-section', authentication);
  text('sas-code', snapshot.sas ?? '');
  text('enter-hint', guard.ready(Date.now()) ? '承認ボタンにフォーカスしてEnterでも承認できます。' : 'Enterは1.5秒待ち、押下中のEnterを離してから、承認ボタン上で押してください。');
  show('approval-status', state === 'authentication' || state === 'approval-wait');
  text('local-approval', `このPC：${snapshot.localApproved ? '承認済み' : '未承認'}`);
  text('peer-approval', `相手PC：${snapshot.peerApproved ? '承認を検証済み' : '承認待ち'}`);
  show('progress-section', ['transferring', 'save-wait', 'save'].includes(state));
  element<HTMLProgressElement>('progress').value = snapshot.progress;
  text('progress-label', `${Math.floor(snapshot.progress * 100)}% / 確認済み ${formatBytes(snapshot.transferredBytes)}`);
  text('transfer-metrics', `経過 ${Math.floor(snapshot.elapsedMs / 1000)} 秒 / 再表示 ${snapshot.retries} 回`);
  text('remaining', snapshot.remainingMs !== undefined && !terminal && !complete ? `待機期限まで ${Math.max(0, Math.ceil(snapshot.remainingMs / 1000))} 秒` : '');
  show('save-section', state === 'save');
  if (snapshot.receivedFile) {
    text('received-name', snapshot.receivedFile.name);
    text('received-size', formatBytes(snapshot.receivedFile.data.length));
  } else if (complete || terminal) { text('received-name', ''); text('received-size', ''); }
  element<HTMLButtonElement>('save-file').disabled = saving;
  show('completion-section', complete);
  text('file-digest', complete ? snapshot.digest ?? '' : '');
  show('finish', complete);
  show('restart', terminal);
  show('export-audit', !!audit && (complete || terminal));
  show('cancel', !complete && !terminal);
  element<HTMLSelectElement>('camera-select').disabled = state !== 'aligning';
  const stale = Date.now() - lastScan > 8000;
  text('alignment-hint', stale ? 'QRをしばらく検出できていません。相手のQR全体が鮮明に映るよう、距離・角度・画面の明るさ・QRサイズを調整してください。'
    : '相手のQR全体が映るように、画面の角度・距離・明るさを調整してください。');
}

async function approve(): Promise<void> {
  const active = session;
  if (!active || active.snapshot.localApproved) return;
  element<HTMLButtonElement>('approve').disabled = true;
  try { await active.approve(); } finally { element<HTMLButtonElement>('approve').disabled = false; update(); }
}
element('approve').addEventListener('click', event => {
  // Keyboard Enter is handled at keydown; other explicit clicks, including AT activation, remain usable.
  if ((event as MouseEvent).detail === 0 && !guard.ready(Date.now())) return;
  void approve();
});
window.addEventListener('keydown', event => {
  const accepted = guard.keydown(event.key, event.repeat, Date.now());
  if (event.key !== 'Enter' || event.target !== element('approve')) return;
  event.preventDefault();
  if (accepted && session && !element('auth-section').hidden) void approve();
}, true);
window.addEventListener('keyup', event => guard.keyup(event.key), true);
window.addEventListener('blur', () => guard.blur());

element('mismatch').addEventListener('click', async () => { await session?.cancel('SAS_MISMATCH'); update(); });
element('cancel').addEventListener('click', async () => {
  const reason = session?.snapshot.state === 'save' || saving ? 'SAVE_INCOMPLETE' : 'USER_CANCELLED';
  await session?.cancel(reason);
  update();
});
element('save-file').addEventListener('click', async () => {
  const active = session;
  const file = active?.snapshot.receivedFile;
  if (!active || active.snapshot.state !== 'save' || !file || saving) return;
  saving = true;
  const controller = new AbortController();
  saveController = controller;
  element<HTMLButtonElement>('save-file').disabled = true;
  text('save-status', '保存先を選んでください。保存が完了するまで完了通知は送りません。');
  try {
    await saveVerifiedFile(file, controller.signal);
    if (session === active && active.snapshot.state === 'save') {
      await active.confirmSaved();
      text('save-status', '保存が完了しました。');
    } else notice('保存処理は終了しましたが、セッションはすでに中断されたため完了通知は送りません。');
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error ? error.code : error;
    text('save-status', message(code));
  } finally {
    if (saveController === controller) saveController = undefined;
    saving = false;
    update();
  }
});
element('export-audit').addEventListener('click', async () => {
  if (!audit) return;
  const button = element<HTMLButtonElement>('export-audit');
  button.disabled = true;
  try { await audit.save(); notice('監査ログを保存しました。ログは組織の規程に従って保管してください。'); }
  catch { notice('監査ログを保存できませんでした。保存先を確認し、再試行してください。'); }
  finally { button.disabled = false; }
});

function finish(): void {
  if (saving) return;
  session?.dispose();
  session = undefined;
  camera.stop();
  audit = undefined;
  auditSessionSet = false;
  lastQR = '';
  previousState = '';
  element<HTMLCanvasElement>('qr-canvas').getContext('2d')?.clearRect(0, 0, 10000, 10000);
  text('file-digest', ''); text('sas-code', ''); text('received-name', ''); text('received-size', ''); text('save-status', '');
  text('file-description', '1 MiB（1,048,576バイト）以下・1ファイル');
  show('workspace', false); show('setup', true);
  element<HTMLFieldSetElement>('settings-fields').disabled = false;
  notice(); updateBegin();
}
element('finish').addEventListener('click', finish);
element('restart').addEventListener('click', finish);
element('qr-size').addEventListener('change', () => { element('qr-holder').className = `qr-holder size-${element<HTMLSelectElement>('qr-size').value}`; });
element('qr-placement').addEventListener('change', () => { element('qr-position').className = `qr-position position-${element<HTMLSelectElement>('qr-placement').value}`; });
element('settings-form').addEventListener('submit', event => event.preventDefault());

async function tick(): Promise<void> {
  const active = session;
  try {
    if (active) {
      const value = await active.nextFrame();
      if (active === session) {
        if (value && value !== lastQR) {
          await renderQR(element<HTMLCanvasElement>('qr-canvas'), value, correction);
          lastQR = value;
          text('frame-status', `${active.snapshot.phase ?? 'QR'} / ${value.length} 文字`);
        }
        update();
      }
    }
  } catch {
    if (active === session && active) { notice(message('qr-capacity')); await active.cancel('qr-capacity'); update(); }
  } finally { setTimeout(() => void tick(), 80); }
}
void tick();
window.addEventListener('pagehide', () => { session?.dispose(); session = undefined; camera.stop(); });
