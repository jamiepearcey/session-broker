import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RefreshDeniedError, singleFlightRefresh, startRefreshTimers } from '../refresh.js';
import type { SessionMeta } from '../types.js';

const META: SessionMeta = {
  v: 1,
  sub: 'idp-subject',
  sid: 'sid12345',
  gen: 3,
  active_until: 1000,
  refresh_until: 2000,
  absolute_until: 3000,
  custody: 'ok',
};

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

describe('singleFlightRefresh', () => {
  it('collapses two concurrent callers into exactly one network call', async () => {
    const fetchImpl = vi.fn(
      async () => jsonResponse(META, { headers: { 'content-type': 'application/json', 'x-broker-handler-us': '42' } }),
    );
    const refresh = singleFlightRefresh(fetchImpl as unknown as typeof fetch);

    const [a, b] = await Promise.all([refresh(), refresh()]);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(a.meta).toEqual(META);
    expect(b.meta).toEqual(META);
    expect(a.serverHandlerUs).toBe(42);
  });

  it('collapses many concurrent callers (not just two) into one call', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(META));
    const refresh = singleFlightRefresh(fetchImpl as unknown as typeof fetch);

    const outcomes = await Promise.all(Array.from({ length: 20 }, () => refresh()));

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    for (const outcome of outcomes) expect(outcome.meta).toEqual(META);
  });

  it('starts a fresh network call once the previous one has settled', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(META));
    const refresh = singleFlightRefresh(fetchImpl as unknown as typeof fetch);

    await refresh();
    await refresh();

    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('rejects with RefreshDeniedError carrying the parsed error body on non-2xx', async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify({ error: 'session_expired', detail: 'boom', login_url: '/auth/login' }), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const refresh = singleFlightRefresh(fetchImpl as unknown as typeof fetch);

    await expect(refresh()).rejects.toMatchObject({
      name: 'RefreshDeniedError',
      code: 'session_expired',
      status: 401,
      loginUrl: '/auth/login',
    });
  });

  it('a failed refresh still clears the single-flight slot for the next attempt', async () => {
    let call = 0;
    const fetchImpl = vi.fn(async () => {
      call += 1;
      if (call === 1) {
        return new Response(JSON.stringify({ error: 'invalid_session', detail: 'no cookie' }), {
          status: 401,
          headers: { 'content-type': 'application/json' },
        });
      }
      return jsonResponse(META);
    });
    const refresh = singleFlightRefresh(fetchImpl as unknown as typeof fetch);

    await expect(refresh()).rejects.toThrow();
    const outcome = await refresh();

    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(outcome.meta).toEqual(META);
  });

  it('POSTs same-origin credentialed requests to /session/refresh', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(META));
    const refresh = singleFlightRefresh(fetchImpl as unknown as typeof fetch);

    await refresh();

    expect(fetchImpl).toHaveBeenCalledWith(
      '/session/refresh',
      expect.objectContaining({ method: 'POST', credentials: 'same-origin' }),
    );
  });
});

describe('startRefreshTimers (denial handling)', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  function harness(refresh: () => Promise<never> | Promise<unknown>) {
    let clock = 1_000_000;
    const calls: number[] = [];
    const handle = startRefreshTimers({
      isLeader: () => true,
      // active_until is already in the past — the state a tab wakes into, and
      // the one that used to compute a zero delay on every reschedule.
      getMeta: () => ({
        v: 1,
        sub: 's',
        sid: 'sid',
        gen: 1,
        active_until: Math.floor(clock / 1000) - 600,
        refresh_until: Math.floor(clock / 1000) + 600,
        absolute_until: Math.floor(clock / 1000) + 6000,
        custody: 'ok',
      }),
      refresh: () => {
        calls.push(clock);
        return refresh() as Promise<never>;
      },
      now: () => clock,
      onError: () => {},
    });
    return { handle, calls, advance: (ms: number) => (clock += ms) };
  }

  it('halts instead of spinning when the session is beyond local recovery', async () => {
    // Regression: a dead session made every reschedule fire immediately, so a
    // single stale tab hammered POST /session/refresh in a hot loop. Observed
    // live as dozens of 401s per second from one idle browser tab.
    const denied = () =>
      Promise.reject(new RefreshDeniedError('session_expired', 'gone', 401));
    const { handle, calls } = harness(denied);

    await vi.waitFor(() => expect(calls.length).toBeGreaterThan(0));
    await Promise.resolve();
    await Promise.resolve();

    expect(handle.isHalted()).toBe(true);

    // Everything that could re-arm the timer must now be a no-op.
    handle.reschedule();
    handle.reschedule();
    await vi.advanceTimersByTimeAsync(60_000);

    expect(calls).toHaveLength(1);
    handle.dispose();
  });

  it('backs off rather than spinning on a retryable denial', async () => {
    const denied = () =>
      Promise.reject(new RefreshDeniedError('rate_limited', 'slow down', 429));
    const { handle, calls, advance } = harness(denied);

    await vi.waitFor(() => expect(calls.length).toBeGreaterThan(0));
    await Promise.resolve();
    await Promise.resolve();

    // Not terminal, so it stays armed — but never within the floor.
    expect(handle.isHalted()).toBe(false);
    handle.reschedule();
    advance(100);
    await vi.advanceTimersByTimeAsync(100);
    expect(calls).toHaveLength(1);

    handle.dispose();
  });
});
