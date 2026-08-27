/**
 * Deep merge for configuration overrides.
 *
 * Rules, as documented in docs/config-reference.md:
 *   - plain objects are merged key by key
 *   - arrays REPLACE the base array (an override array is the complete new value)
 *   - `null` replaces the base value (used to disable a rate limit group)
 *   - `undefined` / missing keys leave the base value alone
 *   - values whose type does not match the base are ignored, so a malformed KV entry
 *     degrades to the static config instead of corrupting it
 */

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Merge `override` over `base`. `base` is never mutated.
 *
 * Type mismatches are dropped rather than thrown: this runs on untrusted JSON coming
 * from KV, and a fail-open shield must not die because someone typo'd a value.
 */
export function deepMerge<T>(base: T, override: unknown): T {
  if (override === undefined) return base;

  if (isPlainObject(base)) {
    if (!isPlainObject(override)) return base;
    const out: Record<string, unknown> = { ...base };
    for (const key of Object.keys(override)) {
      if (!Object.prototype.hasOwnProperty.call(base, key)) continue;
      const overrideValue = override[key];
      if (overrideValue === undefined) continue;
      const baseValue = (base as Record<string, unknown>)[key];

      if (overrideValue === null) {
        // Explicit null is meaningful (e.g. `rateLimits.login: null` disables the group),
        // but only where the base already allows null or is an object we can null out.
        out[key] = baseValue === null || isPlainObject(baseValue) ? null : baseValue;
        continue;
      }
      if (Array.isArray(baseValue) || baseValue === null) {
        // Arrays replace wholesale. A nullable object slot is replaced wholesale too.
        if (Array.isArray(baseValue) && !Array.isArray(overrideValue)) continue;
        out[key] = overrideValue;
        continue;
      }
      if (isPlainObject(baseValue)) {
        out[key] = deepMerge(baseValue, overrideValue);
        continue;
      }
      if (typeof baseValue === typeof overrideValue) {
        out[key] = overrideValue;
      }
    }
    return out as T;
  }

  return base;
}
