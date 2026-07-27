import { describe, expect, it } from 'vitest';
import { getSessionMeta, parseMetaCookie } from '../meta.js';
import type { SessionMeta } from '../types.js';

const VALID_META: SessionMeta = {
  v: 1,
  sub: 'idp-subject',
  sid: '8charhas',
  gen: 7,
  active_until: 1784070000,
  refresh_until: 1784660000,
  absolute_until: 1786600000,
  custody: 'ok',
};

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf-8').toString('base64url');
}

describe('parseMetaCookie', () => {
  it('decodes a valid meta cookie from a Cookie-header-shaped string', () => {
    const cookieHeader = `other=1; broker_meta=${encode(VALID_META)}; another=2`;
    expect(parseMetaCookie(cookieHeader)).toEqual(VALID_META);
  });

  it('returns null when the cookie is absent', () => {
    expect(parseMetaCookie('other=1; another=2')).toBeNull();
    expect(parseMetaCookie('')).toBeNull();
  });

  it('returns null for corrupt (non-base64) cookie content, never throws', () => {
    expect(() => parseMetaCookie('broker_meta=%%%not-base64%%%')).not.toThrow();
    expect(parseMetaCookie('broker_meta=%%%not-base64%%%')).toBeNull();
  });

  it('returns null for base64 that decodes to invalid JSON', () => {
    const garbage = Buffer.from('not json', 'utf-8').toString('base64url');
    expect(parseMetaCookie(`broker_meta=${garbage}`)).toBeNull();
  });

  it('returns null for well-formed JSON missing required fields', () => {
    const partial = encode({ v: 1, sub: 'idp-subject' });
    expect(parseMetaCookie(`broker_meta=${partial}`)).toBeNull();
  });

  it('returns null for an out-of-taxonomy custody value', () => {
    const bad = encode({ ...VALID_META, custody: 'unknown' });
    expect(parseMetaCookie(`broker_meta=${bad}`)).toBeNull();
  });

  it('never throws on empty or degenerate input', () => {
    expect(() => parseMetaCookie('broker_meta=')).not.toThrow();
    expect(parseMetaCookie('broker_meta=')).toBeNull();
    expect(() => parseMetaCookie(';;;===')).not.toThrow();
  });
});

describe('getSessionMeta', () => {
  it('reads from an injected cookie string without touching document', () => {
    expect(getSessionMeta(`broker_meta=${encode(VALID_META)}`)).toEqual(VALID_META);
  });

  it('falls back to document.cookie when no argument is given', () => {
    document.cookie = `broker_meta=${encode(VALID_META)}`;
    expect(getSessionMeta()).toEqual(VALID_META);
  });

  it('returns null when document.cookie has no broker_meta', () => {
    document.cookie = 'broker_meta=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
    expect(getSessionMeta('')).toBeNull();
  });
});
