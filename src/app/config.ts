import type { ProtocolConfig } from '../protocol';

// Optical defaults are provisional until the two-PC qualification in docs/testing.md.
export const DEFAULT_CONFIG: ProtocolConfig = {
  payloadBytes: 512,
  windowSize: 1,
  minFrameIntervalMs: 350,
  handshakeTimeoutMs: 120_000,
  approvalWaitTimeoutMs: 180_000,
  saveWaitTimeoutMs: 300_000,
  sessionMaxLifetimeMs: 3_600_000,
  maxRetries: 100,
  sasEnterGuardMs: 1_500,
  paddingBlock: 4096,
};

export type OpticalOptions = { correction: 'L' | 'M' | 'Q' | 'H'; qrSize: number };

export function readConfig(form: HTMLFormElement): ProtocolConfig {
  const values = new FormData(form);
  const result = { ...DEFAULT_CONFIG };
  const limits: Record<string, [number, number]> = {
    payloadBytes: [128, 768], windowSize: [1, 8], minFrameIntervalMs: [150, 3000],
    handshakeTimeoutMs: [30_000, 600_000], approvalWaitTimeoutMs: [30_000, 600_000],
    saveWaitTimeoutMs: [60_000, 900_000], sessionMaxLifetimeMs: [600_000, 7_200_000],
    maxRetries: [10, 1000],
  };
  for (const [key, [min, max]] of Object.entries(limits)) {
    const raw = values.get(key);
    if (raw === null) continue;
    const value = Number(raw);
    if (!Number.isInteger(value) || value < min || value > max) throw new Error('invalid-settings');
    (result as unknown as Record<string, number>)[key] = value;
  }
  if (![1, 2, 4, 8].includes(result.windowSize)) throw new Error('invalid-settings');
  return result;
}
