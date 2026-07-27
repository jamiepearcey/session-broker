import { describe, expect, it, vi } from 'vitest';
import { createBrokerFetch } from '../fetch.js';
import type { RefreshOutcome } from '../refresh.js';

const REFRESH_OUTCOME: RefreshOutcome = {
  meta: {
    v: 1,
    sub: 'idp-subject',
    sid: 'sid12345',
    gen: 2,
    active_until: 1000,
    refresh_until: 2000,
    absolute_until: 3000,
    custody: 'ok',
  },
  rttMs: 1,
  serverHandlerUs: null,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

describe('createBrokerFetch', () => {
  it('passes through non-401 responses untouched, never calling refresh', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ ok: true }, 200));
    const refresh = vi.fn(async (): Promise<RefreshOutcome> => {
      throw new Error('should not be called');
    });
    const brokerFetch = createBrokerFetch(refresh, fetchImpl as unknown as typeof fetch);

    const res = await brokerFetch('/api/thing');

    expect(res.status).toBe(200);
    expect(refresh).not.toHaveBeenCalled();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('on a session_stale 401: awaits the single refresh and retries exactly once', async () => {
    let call = 0;
    const fetchImpl = vi.fn(async () => {
      call += 1;
      if (call === 1) return jsonResponse({ error: 'session_stale', detail: 'x' }, 401);
      return jsonResponse({ ok: true }, 200);
    });
    const refresh = vi.fn(async (): Promise<RefreshOutcome> => REFRESH_OUTCOME);
    const brokerFetch = createBrokerFetch(refresh, fetchImpl as unknown as typeof fetch);

    const res = await brokerFetch('/api/thing');

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(res.status).toBe(200);
  });

  it('does NOT retry a second time when the retried request also 401s', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ error: 'session_stale', detail: 'x' }, 401));
    const refresh = vi.fn(async (): Promise<RefreshOutcome> => REFRESH_OUTCOME);
    const brokerFetch = createBrokerFetch(refresh, fetchImpl as unknown as typeof fetch);

    const res = await brokerFetch('/api/thing');

    expect(refresh).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledTimes(2); // original attempt + exactly one retry
    expect(res.status).toBe(401);
  });

  it('surfaces non-refreshable 401s (session_expired) without attempting a refresh', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ error: 'session_expired', detail: 'x', login_url: '/auth/login' }, 401),
    );
    const refresh = vi.fn(async (): Promise<RefreshOutcome> => {
      throw new Error('should not be called');
    });
    const brokerFetch = createBrokerFetch(refresh, fetchImpl as unknown as typeof fetch);

    const res = await brokerFetch('/api/thing');

    expect(refresh).not.toHaveBeenCalled();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe('session_expired');
  });

  it('surfaces invalid_session 401s without attempting a refresh (ANONYMOUS is not recoverable by refreshing)', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ error: 'invalid_session', detail: 'x' }, 401));
    const refresh = vi.fn(async (): Promise<RefreshOutcome> => {
      throw new Error('should not be called');
    });
    const brokerFetch = createBrokerFetch(refresh, fetchImpl as unknown as typeof fetch);

    await brokerFetch('/api/thing');

    expect(refresh).not.toHaveBeenCalled();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('surfaces the original 401 (not the refresh error) when the refresh itself is denied', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ error: 'session_stale', detail: 'x' }, 401));
    const refresh = vi.fn(async (): Promise<RefreshOutcome> => {
      throw new Error('refresh denied');
    });
    const brokerFetch = createBrokerFetch(refresh, fetchImpl as unknown as typeof fetch);

    const res = await brokerFetch('/api/thing');

    expect(fetchImpl).toHaveBeenCalledTimes(1); // no retry attempted
    expect(res.status).toBe(401);
  });

  it('always forces credentials: same-origin, overriding caller-supplied init', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ ok: true }, 200));
    const refresh = vi.fn(async (): Promise<RefreshOutcome> => REFRESH_OUTCOME);
    const brokerFetch = createBrokerFetch(refresh, fetchImpl as unknown as typeof fetch);

    await brokerFetch('/api/thing', { credentials: 'omit' });

    expect(fetchImpl).toHaveBeenCalledWith('/api/thing', expect.objectContaining({ credentials: 'same-origin' }));
  });
});
