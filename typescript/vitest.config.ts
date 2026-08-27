import crypto from 'crypto';

// Vite's CJS build on newer Node versions may call crypto.getRandomValues,
// which is only available on globalThis.crypto / crypto.webcrypto.
// @ts-ignore
if (typeof (crypto as any).getRandomValues !== 'function') {
  (crypto as any).getRandomValues = crypto.webcrypto.getRandomValues.bind(crypto.webcrypto);
}

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['node_modules/', 'dist/', '**/*.test.ts'],
    },
  },
});
