import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

process.chdir(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
const [mode, key] = process.argv.slice(2);
if (!key || !['minisign', 'gpg'].includes(mode)) {
  console.error('Usage: node scripts/sign.mjs minisign /path/to/key\n       node scripts/sign.mjs gpg KEY_ID');
  process.exit(1);
}
const check = spawnSync(process.execPath, ['scripts/check-artifact.mjs'], { stdio: 'inherit' });
if (check.status !== 0) process.exit(1);
const args = mode === 'minisign'
  ? ['-Sm', 'dist/qrbeam.html', '-s', key, '-x', 'dist/qrbeam.html.minisig']
  : ['--local-user', key, '--armor', '--detach-sign', '--output', 'dist/qrbeam.html.asc', 'dist/qrbeam.html'];
const result = spawnSync(mode, args, { stdio: 'inherit' });
if (result.error || result.status !== 0) {
  console.error('Signing failed. Confirm the signing program and authorized key.');
  process.exit(1);
}
console.log(`Signed dist/qrbeam.html with ${mode}. Distribute the verification key through a separate trusted channel.`);
