/**
 * Ambient binding types.
 *
 * `wrangler types` would generate a `worker-configuration.d.ts` with the same shape, but
 * the project keeps the binding surface hand-written in `config/types.ts` so it is
 * reviewable in one place. This file only bridges that interface to the global
 * `Cloudflare.Env` namespace that `cloudflare:test` and `cloudflare:workers` expect.
 */

declare namespace Cloudflare {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  interface Env extends import('./config/types').Env {}
}
