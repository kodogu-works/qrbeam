import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

process.chdir(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
const html = await readFile('dist/qrbeam.html', 'utf8');
const hash = (text, encoding = 'base64') => createHash('sha256').update(text).digest(encoding);
const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
assert(csp, 'CSP missing');
assert(!csp.includes('unsafe-inline') && !csp.includes('unsafe-eval'), 'Unsafe CSP');
for (const tag of ['script', 'style']) {
  const matches = [...html.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'g'))];
  assert.equal(matches.length, 1, `Expected exactly one inline ${tag}`);
  assert(csp.includes(`${tag}-src 'sha256-${hash(matches[0][1])}'`), `Invalid ${tag} hash`);
}
assert(csp.includes("connect-src 'none'"), 'Network connections not blocked');
assert(!/<(?:script|link|iframe|img|source)\b[^>]*(?:src|href)\s*=/i.test(html), 'External resource reference');
assert(!/\s(?:on\w+|style)\s*=/i.test(html.slice(0, html.indexOf('<script>'))), 'Inline style or handler');
assert(!/__(?:CSP|CSS|JS|LICENSES|BUILD_ID)__/.test(html), 'Unresolved build placeholder');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
assert(!/\b(?:fetch|XMLHttpRequest|WebSocket|RTCPeerConnection|EventSource|sendBeacon|importScripts)\s*\(/.test(script), 'Network API in artifact');
assert(!/https?:\/\//.test(script), 'External URL in executable bundle');
assert(!/\b(?:eval|Function)\s*\(/.test(script), 'Dynamic code evaluation');
const checksum = (await readFile('dist/SHA256SUMS', 'utf8')).trim();
assert.equal(checksum, `${hash(html, 'hex')}  qrbeam.html`, 'Artifact checksum mismatch');
const metadata = JSON.parse(await readFile('dist/build.json', 'utf8'));
assert.equal(metadata.sha256, hash(html, 'hex'));
assert(metadata.dependencies.some(dependency => dependency.name === 'jsqr'), 'Local decoder missing');
assert(metadata.dependencies.some(dependency => dependency.name === 'qrcode'), 'Local QR encoder missing');
console.log('Artifact verified: embedded dependencies, CSP hashes, no network APIs or external resources, SHA-256.');
