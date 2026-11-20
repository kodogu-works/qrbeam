# qrbeam

[English](README.md) | **日本語**

[![CI](https://github.com/kodogu-works/qrbeam/actions/workflows/ci.yml/badge.svg)](https://github.com/kodogu-works/qrbeam/actions/workflows/ci.yml)
![Node.js](https://img.shields.io/badge/node-%3E%3D22.12-339933?logo=nodedotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript&logoColor=white)
![Status](https://img.shields.io/badge/status-development-orange)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Secure Offline File Transfer via QR Codes**

ネットワークを使わず、2台のPCの画面とカメラだけでファイルを1つ（最大1 MiB）受け渡すWebアプリです。[仕様書](docs/spec.md) v1.1に沿った初期実装にあたります。

鍵交換には使い捨てのECDH P-256鍵を使い、コミットメント付きの6桁SAS（確認コード）を双方が目視で照合・承認してから転送を始めます。メッセージ認証には方向ごとに別々の鍵を使い、本文はAES-256-GCMで暗号化します。ファイル名・実サイズ・SHA-256も暗号化したうえで、4 KiB単位にパディングするため、通信内容からファイルの大きさはおおよそしか分かりません。転送が「完了」になるのは、受信側で保存先への書き込みと`close()`が成功し、さらに送信側が受信側からの認証済みCOMPLETEを検証できたときだけです。

## ビルドと検証

Node.js 22.12以上とnpmが必要です。依存パッケージは開発時にだけ使います。

```sh
npm ci
npm run check
```

ビルドすると`dist/qrbeam.html`が生成されます。QRコードの生成・読み取り、CSS、JavaScript、ライセンス表記をすべて1つのファイルに埋め込んであるため、このHTMLだけで動作します。アプリには外部と通信する機能がなく、さらにCSPの`connect-src 'none'`で通信そのものを禁止しています。

| コマンド | 内容 |
| --- | --- |
| `npm run typecheck` | TypeScriptの型チェック |
| `npm test` | 暗号、フレーム、状態遷移、ファイル処理、保存、入力検証のテスト |
| `npm run build` | 単一HTML、SHA256SUMS、ビルド情報、ライセンスの生成 |
| `npm run verify` | CSPハッシュ、埋め込んだ依存、通信経路、成果物のSHA-256の検査 |
| `npm run benchmark` | Base45との比較と、欠落・遅延を加えた通信シミュレーション |
| `npm run test:browser` | Chromiumで`file://`から開いた配布用HTMLとQRによる光学転送を検証 |

ブラウザテストを実行する前に`npx playwright install chromium`を済ませてください。テストではカメラ映像と保存先だけを差し替え、QRの描画・読み取り、Web Crypto、画面操作は本物の実装で動かします。実際のカメラや保存ダイアログでの確認は、別途実機で行う必要があります。

## CI

[GitHub Actions](.github/workflows/ci.yml)はpush・Pull Request・手動実行に対応し、Ubuntu 24.04のNode.js 22/24/26で`npm ci`と`npm run check`、再ビルド時のSHA-256一致確認を実行します。Node.js 26ではChromiumによる`file://`のブラウザE2Eも実行します。

成功したNode.js 26ジョブの`qrbeam-build`アーティファクトから、未署名のHTML・SHA256SUMS・ビルド情報・ライセンスを14日間取得できます。ブラウザテストの診断ファイルが残っている場合は、失敗時に`browser-test-results`として7日間保存します。

## 使い方

1. [運用手順](docs/operations.md)に従って署名とSHA-256を確認し、両方のPCのネットワークを切断します。
2. 両方のPCで`qrbeam.html`を直接開き、片方を「送信」、もう片方を「受信」に設定します。
3. 送信するファイルを選び、両方でカメラの使用を許可して、互いの画面のQRコードがカメラに映るようにPCを配置します。
4. 両方の画面に表示された6桁のコードを見比べ、一致していれば双方で「コードが一致・開始」を押します。一致しない場合は中止してください。
5. 受信側で検証が成功したら「保存」を押し、保存先を選びます。キャンセルや失敗があっても、やり直せます。
6. 送信側に「転送完了」と表示されたのを確認し、必要なら監査ログを保存してから、双方で「終了」を押します。

現時点の動作確認対象は、Windows / macOS / LinuxのデスクトップChrome / Edgeです。Web Crypto、カメラ、File System Access APIのいずれかが使えない環境では転送を開始できません。

監査ログには、ファイル名、ファイルの中身、平文のSHA-256、実サイズは記録しません。記録するファイルダイジェストはHMACなので、同じセッション内でしか照合できません。秘密鍵や転送データはどこにも保存せず、ローカルストレージに残すのは連続した認証失敗の回数だけです。

## 配布と検証状況

ビルド時に`dist/SHA256SUMS`と`dist/build.json`も生成します。同じソースとロックファイルからは同じ成果物を再現でき、ビルド時刻や手元のパスは成果物に含まれません。署名は、責任者が管理する鍵で行います。

```sh
node scripts/sign.mjs minisign /path/to/authorized.key
# または
node scripts/sign.mjs gpg KEY_ID
```

**注意:** これは開発版で、署名済みのリリースではありません。各OSの実機での`file://`起動とオフライン光学転送の試験、第三者による暗号レビュー、組織としての運用審査はまだ済んでいません。自動テストが通ったからといって、機密情報の実運用に使えることを保証するものではありません。また、ブラウザのメモリ上のデータが完全に消去されることも保証しません。

- [実装したワイヤ形式](docs/protocol.md)
- [ベンチマークと測定条件](docs/benchmarks.md)
- [実機試験の手順と未測定の項目](docs/testing.md)
- [署名検証・配布・監査の運用手順](docs/operations.md)

`src/`は仕様書§8.1の責務分担に沿ってファイルを分けています。通信設定の初期値は`src/app/config.ts`にあり、転送開始前の画面からも変更できます。現在はBase45、DATAフレーム512バイト、ウィンドウサイズ1、表示間隔350 msという安全側の暫定値にしており、実機での評価を踏まえて調整する予定です。

## ライセンス

[MIT License](LICENSE) © 2026 Synge Todo

ビルドした`qrbeam.html`には次のライブラリを埋め込んでいます。各ライセンスの全文はHTML内と`dist/THIRD-PARTY-LICENSES.txt`に収録しています。

- [qrcode](https://github.com/soldair/node-qrcode) 1.5.4 — MIT License
- [jsQR](https://github.com/cozmo/jsQR) 1.4.0 — Apache License 2.0
