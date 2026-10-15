import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { SessionProvider, useSession } from '../provider.js';

/** A browser's fetch throws "Illegal invocation" unless `this` is the window (or undefined). */
function thisSensitiveFetch() {
  const calls: string[] = [];
  const impl = function (this: unknown, input: RequestInfo | URL): Promise<Response> {
    if (this !== undefined && this !== globalThis) throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
    calls.push(String(input));
    return Promise.resolve(new Response(JSON.stringify({ logged_out: true }), { status: 200 }));
  };
  return { impl: impl as unknown as typeof fetch, calls };
}

function wrapper(fetchImpl?: typeof fetch) {
  return ({ children }: { children: ReactNode }) => (
    <SessionProvider events="off" {...(fetchImpl ? { fetchImpl } : {})}>
      {children}
    </SessionProvider>
  );
}

describe('SessionProvider fetch binding', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('logout works when the ambient fetch cares about `this` (the default)', async () => {
    const { impl, calls } = thisSensitiveFetch();
    vi.stubGlobal('fetch', impl);
    const { result } = renderHook(() => useSession(), { wrapper: wrapper() });
    let out: Awaited<ReturnType<typeof result.current.logout>> | undefined;
    await act(async () => {
      out = await result.current.logout();
    });
    expect(calls).toEqual(['/logout']);
    expect(out?.loggedOut).toBe(true);
  });

  it('logout works when a host passes a bare, this-sensitive fetch as fetchImpl', async () => {
    const { impl, calls } = thisSensitiveFetch();
    const { result } = renderHook(() => useSession(), { wrapper: wrapper(impl) });
    await act(async () => {
      await result.current.logout();
    });
    expect(calls).toEqual(['/logout']);
  });
});
