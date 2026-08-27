import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
  plugins: [
    cloudflareTest({
      // Bindings come from wrangler.jsonc so the tests run against the same shape as the
      // deployed Worker (KV namespace, rate limit bindings, compatibility date).
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        // The workerd binary bundled with the test pool lags behind the deployed
        // runtime, so it cannot start with wrangler.jsonc's compatibility_date. Pin the
        // tests to the newest date this binary supports; bump it when the pool updates.
        compatibilityDate: '2026-08-22',
        // The admin API is disabled without a token, so the tests provide their own
        // instead of depending on a real secret.
        bindings: { SHIELD_ADMIN_TOKEN: 'test-admin-token' },
      },
    }),
  ],
});
