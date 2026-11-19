# qrbeam

**English** | [日本語](README.ja.md)

[![CI](https://github.com/kodogu-works/qrbeam/actions/workflows/ci.yml/badge.svg)](https://github.com/kodogu-works/qrbeam/actions/workflows/ci.yml)
![Node.js](https://img.shields.io/badge/node-%3E%3D18.19-339933?logo=nodedotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript&logoColor=white)
![Status](https://img.shields.io/badge/status-development-orange)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Secure Offline File Transfer via QR Codes**

qrbeam is a web app that transfers a single file (up to 1 MiB) between two PCs using nothing but their screens and cameras — no network required. This is an initial implementation of [specification](docs/spec.md) v1.1.

Key agreement uses ephemeral ECDH P-256 keys. Before the transfer begins, both users visually compare and approve a committed 6-digit SAS (short authentication string). Message authentication uses separate keys for each direction, and the payload is encrypted with AES-256-GCM. The file name, actual size, and SHA-256 are encrypted as well, and everything is padded to 4 KiB boundaries, so an observer can learn only the approximate file size. A transfer counts as complete only after the receiver has successfully written the file to its destination and `close()` has succeeded, and the sender has verified an authenticated COMPLETE message from the receiver.

## Build and verification

Requires Node.js 18.19 or later and npm. Dependencies are needed only for development.

```sh
npm ci
npm run check
```

The build produces `dist/qrbeam.html`. QR generation and decoding, CSS, JavaScript, and license notices are all embedded in this single file, so it runs on its own. The app has no network functionality, and the CSP directive `connect-src 'none'` additionally blocks all connections.

| Command | Description |
| --- | --- |
| `npm run typecheck` | TypeScript type checking |
| `npm test` | Tests for crypto, framing, state transitions, file handling, saving, and input validation |
| `npm run build` | Generates the single HTML file, SHA256SUMS, build info, and licenses |
| `npm run verify` | Checks CSP hashes, embedded dependencies, network paths, and artifact SHA-256 |
| `npm run benchmark` | Comparison with Base45 and transfer simulation with frame loss and latency |
| `npm run test:browser` | Verifies the distributable HTML opened via `file://` and optical QR relay in Chromium |

Run `npx playwright install chromium` before running the browser tests. The tests replace only the camera feed and the save destination; QR rendering and decoding, Web Crypto, and UI interaction run the real implementation. Verification with real cameras and save dialogs must be done separately on actual hardware.

## CI

[GitHub Actions](.github/workflows/ci.yml) runs on push, pull requests, and manual dispatch. On Ubuntu 24.04 with Node.js 22/24/26, it runs `npm ci` and `npm run check`, and confirms that a rebuild yields identical SHA-256 hashes. The Node.js 26 job also runs browser E2E tests over `file://` in Chromium.

The `qrbeam-build` artifact from a successful Node.js 26 job provides the unsigned HTML, SHA256SUMS, build info, and licenses for 14 days. If browser-test diagnostics are produced on failure, they are kept as `browser-test-results` for 7 days.

## Usage

1. Verify the signature and SHA-256 following the [operations guide](docs/operations.md), and disconnect both PCs from the network.
2. Open `qrbeam.html` directly on both PCs. Set one to 送信 (Send) and the other to 受信 (Receive).
3. Select the file to send, allow camera access on both PCs, and position them so that each camera can see the QR code on the other screen.
4. Compare the 6-digit codes shown on both screens. If they match, press コードが一致・開始 (Codes match — Start) on both sides. If they do not match, press コードが違う・中止 (Codes differ — Abort).
5. Once verification succeeds on the receiver, press 保存 (Save) and choose a destination. You can retry after a cancellation or failure.
6. Confirm that the sender shows 転送完了 (Transfer complete), save the audit log with 監査ログを保存 (Save audit log) if needed, and press 終了 (Finish) on both sides.

The UI is currently available in Japanese only; English translations of the labels are given in parentheses above.

The current target platforms are desktop Chrome / Edge on Windows, macOS, and Linux. A transfer cannot start in environments where Web Crypto, camera access, or the File System Access API is unavailable.

The audit log does not record the file name, file contents, plaintext SHA-256, or actual size. The recorded file digest is an HMAC and can be matched only within the same session. Private keys and transferred data are never persisted; the only thing stored in local storage is the count of consecutive authentication failures.

## Distribution and verification status

The build also generates `dist/SHA256SUMS` and `dist/build.json`. The same source and lockfile reproduce identical artifacts, and build timestamps and local paths are not included. Signing is done with a key managed by the responsible party.

```sh
node scripts/sign.mjs minisign /path/to/authorized.key
# or
node scripts/sign.mjs gpg KEY_ID
```

> [!WARNING]
> This is a development version, not a signed release. Testing of `file://` launch and offline optical transfer on real hardware for each OS, third-party cryptographic review, and organizational operational review have not yet been completed. Passing automated tests does not guarantee fitness for handling confidential information in production. Complete erasure of data from browser memory is also not guaranteed.

Detailed documentation (in Japanese):

- [Implemented wire format](docs/protocol.md)
- [Benchmarks and measurement conditions](docs/benchmarks.md)
- [Hardware test procedures and unmeasured items](docs/testing.md)
- [Operations guide: signature verification, distribution, and auditing](docs/operations.md)

`src/` is organized according to the responsibilities in spec §8.1. Default transfer settings live in `src/app/config.ts` and can also be changed on the screen before a transfer starts. The current values — Base45, 512-byte DATA frames, window size 1, and a 350 ms display interval — are conservative provisional choices and will be tuned based on hardware evaluation.

## License

[MIT License](LICENSE) © 2026 Synge Todo

The built `qrbeam.html` embeds the following third-party libraries; their license texts are included in the HTML and in `dist/THIRD-PARTY-LICENSES.txt`.

- [qrcode](https://github.com/soldair/node-qrcode) 1.5.4 — MIT License
- [jsQR](https://github.com/cozmo/jsQR) 1.4.0 — Apache License 2.0
