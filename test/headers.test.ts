import { describe, expect, it } from 'vitest';
import { defaultSiteConfig } from '../src/config/defaults';
import { deepMerge } from '../src/config/merge';
import type { DeepPartial, HeadersConfig } from '../src/config/types';
import { applySecurityHeaders } from '../src/engine/headers';

function headersConfig(overrides: DeepPartial<HeadersConfig> = {}): HeadersConfig {
  return deepMerge(defaultSiteConfig.headers, overrides);
}

function originResponse(init: ResponseInit = {}): Response {
  return new Response('<html>origin</html>', {
    status: 200,
    headers: { 'Content-Type': 'text/html', ...(init.headers as Record<string, string>) },
    ...init,
  });
}

describe('applySecurityHeaders', () => {
  it('adds the default header set', async () => {
    const out = applySecurityHeaders(originResponse(), headersConfig());
    expect(out.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(out.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(out.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
    expect(out.headers.get('Permissions-Policy')).toContain('camera=()');
    expect(out.headers.get('X-Frame-Options')).toBe('SAMEORIGIN');
    expect(out.headers.get('Content-Security-Policy-Report-Only')).toBe("frame-ancestors 'self'");
    expect(out.headers.get('Content-Security-Policy')).toBeNull();
  });

  it('never changes the status code or the body', async () => {
    const out = applySecurityHeaders(originResponse({ status: 404 }), headersConfig());
    expect(out.status).toBe(404);
    expect(await out.text()).toBe('<html>origin</html>');
  });

  it('leaves Set-Cookie untouched', () => {
    const response = originResponse();
    response.headers.append('Set-Cookie', 'a=1; Path=/');
    response.headers.append('Set-Cookie', 'b=2; Path=/');
    const out = applySecurityHeaders(response, headersConfig());
    expect(out.headers.getAll('Set-Cookie')).toEqual(['a=1; Path=/', 'b=2; Path=/']);
  });

  it('removes X-Powered-By', () => {
    const response = originResponse({ headers: { 'X-Powered-By': 'PHP/8.2.0' } });
    const out = applySecurityHeaders(response, headersConfig());
    expect(out.headers.get('X-Powered-By')).toBeNull();
  });

  it('keeps X-Powered-By when removeXPoweredBy is off', () => {
    const response = originResponse({ headers: { 'X-Powered-By': 'PHP/8.2.0' } });
    const out = applySecurityHeaders(response, headersConfig({ removeXPoweredBy: false }));
    expect(out.headers.get('X-Powered-By')).toBe('PHP/8.2.0');
  });

  it('does not send HSTS unless it is opted into', () => {
    expect(
      applySecurityHeaders(originResponse(), headersConfig()).headers.get(
        'Strict-Transport-Security',
      ),
    ).toBeNull();
  });

  it('builds the HSTS value from the flags', () => {
    const basic = applySecurityHeaders(
      originResponse(),
      headersConfig({ hsts: true, hstsMaxAge: 600 }),
    );
    expect(basic.headers.get('Strict-Transport-Security')).toBe('max-age=600');

    const full = applySecurityHeaders(
      originResponse(),
      headersConfig({
        hsts: true,
        hstsMaxAge: 600,
        hstsIncludeSubdomains: true,
        hstsPreload: true,
      }),
    );
    expect(full.headers.get('Strict-Transport-Security')).toBe(
      'max-age=600; includeSubDomains; preload',
    );
  });

  it('refuses to emit preload without includeSubDomains', () => {
    const out = applySecurityHeaders(
      originResponse(),
      headersConfig({ hsts: true, hstsMaxAge: 600, hstsPreload: true }),
    );
    expect(out.headers.get('Strict-Transport-Security')).toBe('max-age=600');
  });

  it('maps frameAncestors to X-Frame-Options', () => {
    expect(
      applySecurityHeaders(originResponse(), headersConfig({ frameAncestors: "'none'" })).headers.get(
        'X-Frame-Options',
      ),
    ).toBe('DENY');
    expect(
      applySecurityHeaders(
        originResponse(),
        headersConfig({ frameAncestors: "'self' https://partner.example" }),
      ).headers.get('X-Frame-Options'),
    ).toBeNull();
  });

  it('appends frame-ancestors to a custom policy', () => {
    const out = applySecurityHeaders(
      originResponse(),
      headersConfig({ csp: "default-src 'self'", cspReportOnly: false }),
    );
    expect(out.headers.get('Content-Security-Policy')).toBe(
      "default-src 'self'; frame-ancestors 'self'",
    );
  });

  it('does not duplicate frame-ancestors when the policy already has it', () => {
    const out = applySecurityHeaders(
      originResponse(),
      headersConfig({ csp: "default-src 'self'; frame-ancestors 'none'", cspReportOnly: false }),
    );
    expect(out.headers.get('Content-Security-Policy')).toBe(
      "default-src 'self'; frame-ancestors 'none'",
    );
  });

  it('does not stack a second CSP on top of one the origin already sends', () => {
    const response = originResponse({
      headers: { 'Content-Security-Policy': "default-src 'none'" },
    });
    const out = applySecurityHeaders(
      response,
      headersConfig({ csp: "default-src 'self'", cspReportOnly: false }),
    );
    expect(out.headers.get('Content-Security-Policy')).toBe("default-src 'none'");
  });

  it('passes null-body responses through untouched', () => {
    const notModified = new Response(null, { status: 304 });
    expect(applySecurityHeaders(notModified, headersConfig())).toBe(notModified);
  });
});
