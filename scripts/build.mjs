import { build, transform } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const sha = data => createHash('sha256').update(data).digest('hex');
const cspHash = data => createHash('sha256').update(data).digest('base64');
async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const groups = await Promise.all(entries.sort((a, b) => a.name < b.name ? -1 : 1).map(entry => {
    const filename = path.join(directory, entry.name);
    return entry.isDirectory() ? files(filename) : [filename];
  }));
  return groups.flat();
}
const inputs = [...await files('src'), ...await files('scripts'), 'package.json', 'package-lock.json', 'tsconfig.json'].sort();
const sourceHash = createHash('sha256');
for (const filename of inputs) {
  sourceHash.update(filename + '\0');
  sourceHash.update(await readFile(filename));
  sourceHash.update('\0');
}
const buildId = `0.1.0-${sourceHash.digest('hex').slice(0, 16)}`;
const result = await build({
  entryPoints: ['src/app/main.ts'], bundle: true, write: false, minify: true,
  format: 'iife', platform: 'browser', target: ['chrome100'], charset: 'ascii',
  define: { __BUILD_ID__: JSON.stringify(buildId) },
  legalComments: 'none', metafile: true,
});
const script = result.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const style = (await transform(await readFile('src/app/style.css', 'utf8'), { loader: 'css', minify: true })).code;
const csp = [
  "default-src 'none'", `script-src 'sha256-${cspHash(script)}'`, `style-src 'sha256-${cspHash(style)}'`,
  "connect-src 'none'", 'img-src data: blob:', 'media-src blob:', "object-src 'none'",
  "frame-src 'none'", "worker-src 'none'", "form-action 'none'", "base-uri 'none'",
].join('; ');
const dependencyDirs = [...new Set(Object.keys(result.metafile.inputs).flatMap(filename => {
  const match = filename.match(/^(node_modules\/(?:@[^/]+\/)?[^/]+)\//);
  return match ? [match[1]] : [];
}))].sort();
const licenses = [];
const dependencies = [];
for (const directory of dependencyDirs) {
  const info = JSON.parse(await readFile(path.join(directory, 'package.json'), 'utf8'));
  dependencies.push({ name: info.name, version: info.version, license: info.license });
  const filename = (await readdir(directory)).sort().find(name => /^licen[cs]e(?:\..*)?$/i.test(name));
  if (!filename) throw new Error(`Missing license: ${info.name}`);
  licenses.push(`${info.name} ${info.version}\n${await readFile(path.join(directory, filename), 'utf8')}`);
}
const licenseText = licenses.join('\n\n----------------------------------------\n\n');
const escapedLicenses = licenseText.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const html = (await readFile('src/app/template.html', 'utf8'))
  .replace('__CSP__', () => csp).replace('__CSS__', () => style)
  .replace('__LICENSES__', () => escapedLicenses).replace('__JS__', () => script);
await mkdir('dist', { recursive: true });
await writeFile('dist/qrbeam.html', html);
const digest = sha(html);
await writeFile('dist/SHA256SUMS', `${digest}  qrbeam.html\n`);
await writeFile('dist/THIRD-PARTY-LICENSES.txt', licenseText);
await writeFile('dist/build.json', JSON.stringify({ buildId, sha256: digest, dependencies }, null, 2) + '\n');
console.log(`Built dist/qrbeam.html (${Buffer.byteLength(html).toLocaleString('en-US')} bytes)`);
console.log(`Build: ${buildId}\nSHA-256: ${digest}`);
