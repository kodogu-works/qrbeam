import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    setupFiles: ['src/tests/setup.ts'],
    include: ['src/tests/**/*.test.ts'],
    pool: 'threads',
    poolOptions: { threads: { maxThreads: 2, minThreads: 1 } },
    testTimeout: 20000,
  },
});
