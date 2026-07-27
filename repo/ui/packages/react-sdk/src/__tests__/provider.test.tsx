import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { SessionProvider, useLeader, useSession, useSessionEvents } from '../provider.js';
import type { EventSourceFactory, EventSourceLike } from '../events.js';
import type { LocksLike } from '../leader.js';
import type { SessionMeta } from '../types.js';

/**
 * Same exclusive, FIFO-queued `navigator.locks` fake as leader.test.ts,
 * duplicated locally rather than imported so this file's fixtures stay
 * self-contained. Installed as the real `navigator.locks` for the duration
 * of a test — `SessionProvider` always calls `electLeader()` with no
 * argument, so this is the only way to control which of two rendered
 * providers ("tabs") wins the lock.
 */
class FakeLockManager implements LocksLike {
  private held = false;
  private queue: Array<() => void> = [];

  request(_name: string, options: { signal?: AbortSignal }, callback: () => Promise<void>): Promise<void> {
    return new Promise((resolve, reject) => {
      let granted = false;
      const release = () => {
        if (!this.held) return;
        this.held = false;
        const next = this.queue.shift();
        if (next) next();
      };
      const tryAcquire = () => {
        if (this.held) {
          this.queue.push(tryAcquire);
          return;
        }
        this.held = true;
        granted = true;
        callback().then(
          () => {
            release();
            resolve();
          },
          (err) => {
            release();
            reject(err);
          },
        );
      };
      options.signal?.addEventListener('abort', () => {
        if (granted) return;
        const queued = this.queue.indexOf(tryAcquire);
        if (queued >= 0) this.queue.splice(queued, 1);
        reject(new DOMException('aborted', 'AbortError'));
      });
      tryAcquire();
    });
  }
}

/** A minimal, no-op `EventSourceLike`, for tests that only care whether a stream was opened at all — not what it does. */
class StubEventSource implements EventSourceLike {
  closed = false;
  addEventListener(): void {
    /* not exercised in the stub tests */
  }
  removeEventListener(): void {
    /* not exercised in the stub tests */
  }
  close(): void {
    this.closed = true;
  }
}

/** A scriptable `EventSourceLike`, for the one test that exercises real event delivery end-to-end through the provider. */
class ScriptableEventSource implements EventSourceLike {
  closed = false;
  private readonly listeners = new Map<string, Set<(event: Event) => void>>();

  addEventListener(type: string, listener: (event: Event) => void): void {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(listener);
  }
  removeEventListener(type: string, listener: (event: Event) => void): void {
    this.listeners.get(type)?.delete(listener);
  }
  close(): void {
    this.closed = true;
  }
  emitOpen(): void {
    for (const listener of this.listeners.get('open') ?? []) listener(new Event('open'));
  }
  emitMessage(name: string, data: unknown): void {
    const event = new MessageEvent(name, { data: JSON.stringify(data) });
    for (const listener of this.listeners.get(name) ?? []) listener(event);
  }
}

function trackedFactory(): { factory: EventSourceFactory; calls: string[] } {
  const calls: string[] = [];
  const factory: EventSourceFactory = (url) => {
    calls.push(url);
    return new StubEventSource();
  };
  return { factory, calls };
}

async function flush(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

function wrapperWith(props: {
  events?: 'leader-only' | 'per-tab' | 'off';
  eventSourceFactory?: EventSourceFactory;
  fetchImpl?: typeof fetch;
}): ({ children }: { children: ReactNode }) => ReactNode {
  return function Wrapper({ children }: { children: ReactNode }) {
    return <SessionProvider {...props}>{children}</SessionProvider>;
  };
}

describe('SessionProvider events wiring', () => {
  let originalLocks: unknown;

  beforeEach(() => {
    originalLocks = (navigator as unknown as { locks?: unknown }).locks;
    document.cookie = 'broker_meta=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  });

  afterEach(() => {
    Object.defineProperty(navigator, 'locks', { value: originalLocks, configurable: true });
  });

  function installLocks(locks: LocksLike): void {
    Object.defineProperty(navigator, 'locks', { value: locks, configurable: true });
  }

  it("events: 'off' never opens a stream, even though this tab is leader", async () => {
    installLocks(new FakeLockManager());
    const { factory, calls } = trackedFactory();

    const { result, unmount } = renderHook(() => ({ leader: useLeader(), events: useSessionEvents() }), {
      wrapper: wrapperWith({ events: 'off', eventSourceFactory: factory }),
    });
    await flush();

    expect(result.current.leader).toBe(true);
    expect(calls).toHaveLength(0);
    expect(result.current.events.active).toBe(false);
    expect(result.current.events.connectionState).toBe('disabled');

    unmount();
  });

  it("events: 'leader-only' (the default) — the non-leader tab opens no stream; the leader tab does", async () => {
    const locks = new FakeLockManager();
    installLocks(locks);

    const leader = trackedFactory();
    const leaderHook = renderHook(() => ({ leader: useLeader(), events: useSessionEvents() }), {
      wrapper: wrapperWith({ eventSourceFactory: leader.factory }),
    });
    await flush();
    expect(leaderHook.result.current.leader).toBe(true);
    expect(leader.calls).toHaveLength(1);
    expect(leaderHook.result.current.events.active).toBe(true);
    expect(leaderHook.result.current.events.activeBecauseLeader).toBe(true);

    const nonLeader = trackedFactory();
    const nonLeaderHook = renderHook(() => ({ leader: useLeader(), events: useSessionEvents() }), {
      wrapper: wrapperWith({ eventSourceFactory: nonLeader.factory }),
    });
    await flush();

    expect(nonLeaderHook.result.current.leader).toBe(false);
    expect(nonLeader.calls).toHaveLength(0);
    expect(nonLeaderHook.result.current.events.active).toBe(false);
    expect(nonLeaderHook.result.current.events.connectionState).toBe('disabled');

    leaderHook.unmount();
    nonLeaderHook.unmount();
  });

  it("events: 'per-tab' opens a stream on every tab, leader or not", async () => {
    const locks = new FakeLockManager();
    installLocks(locks);

    const leader = trackedFactory();
    const leaderHook = renderHook(() => useLeader(), {
      wrapper: wrapperWith({ events: 'per-tab', eventSourceFactory: leader.factory }),
    });
    await flush();
    expect(leaderHook.result.current).toBe(true);
    expect(leader.calls).toHaveLength(1);

    const nonLeader = trackedFactory();
    const nonLeaderHook = renderHook(() => ({ leader: useLeader(), events: useSessionEvents() }), {
      wrapper: wrapperWith({ events: 'per-tab', eventSourceFactory: nonLeader.factory }),
    });
    await flush();

    expect(nonLeaderHook.result.current.leader).toBe(false);
    expect(nonLeader.calls).toHaveLength(1);
    expect(nonLeaderHook.result.current.events.active).toBe(true);
    // Active here because per-tab mode says so, not because of leadership.
    expect(nonLeaderHook.result.current.events.activeBecauseLeader).toBe(false);

    leaderHook.unmount();
    nonLeaderHook.unmount();
  });

  it('a leadership handoff opens the stream on the newly-promoted tab and closes it on the demoted one', async () => {
    const locks = new FakeLockManager();
    installLocks(locks);

    const tabA = trackedFactory();
    const tabAHook = renderHook(() => ({ leader: useLeader(), events: useSessionEvents() }), {
      wrapper: wrapperWith({ eventSourceFactory: tabA.factory }),
    });
    await flush();
    expect(tabAHook.result.current.leader).toBe(true);
    expect(tabA.calls).toHaveLength(1);

    const tabB = trackedFactory();
    const tabBHook = renderHook(() => ({ leader: useLeader(), events: useSessionEvents() }), {
      wrapper: wrapperWith({ eventSourceFactory: tabB.factory }),
    });
    await flush();
    expect(tabBHook.result.current.leader).toBe(false);
    expect(tabB.calls).toHaveLength(0);

    tabAHook.unmount(); // releases the lock, promoting tab B
    await flush();

    expect(tabBHook.result.current.leader).toBe(true);
    expect(tabB.calls).toHaveLength(1);
    expect(tabBHook.result.current.events.active).toBe(true);

    tabBHook.unmount();
  });

  it('session.killed moves status to expired and halts the refresh timer without triggering a refresh; custody.changed updates meta', async () => {
    installLocks(new FakeLockManager());

    const meta: SessionMeta = {
      v: 1,
      sub: 'idp-subject',
      sid: 'sid12345',
      gen: 1,
      active_until: Math.floor(Date.now() / 1000) + 3600,
      refresh_until: Math.floor(Date.now() / 1000) + 7200,
      absolute_until: Math.floor(Date.now() / 1000) + 100_000,
      custody: 'ok',
    };
    document.cookie = `broker_meta=${Buffer.from(JSON.stringify(meta), 'utf-8').toString('base64url')}`;

    let source: ScriptableEventSource | null = null;
    const factory: EventSourceFactory = () => {
      source = new ScriptableEventSource();
      return source;
    };
    const fetchImpl = vi.fn(async (): Promise<Response> => {
      throw new Error('a session.killed hint must never itself trigger a refresh call');
    });

    const { result, unmount } = renderHook(() => useSession(), {
      wrapper: wrapperWith({ eventSourceFactory: factory, fetchImpl: fetchImpl as unknown as typeof fetch }),
    });
    await flush();

    expect(result.current.status).toBe('active');
    expect(result.current.meta?.custody).toBe('ok');

    act(() => {
      source?.emitOpen();
      source?.emitMessage('custody.changed', { sid: meta.sid, custody: 'degraded' });
    });
    expect(result.current.meta?.custody).toBe('degraded');
    expect(result.current.status).toBe('active');

    act(() => {
      source?.emitMessage('session.killed', { sid: meta.sid, reason: 'upstream_revoked' });
    });

    expect(result.current.status).toBe('expired');
    expect(fetchImpl).not.toHaveBeenCalled();

    unmount();
    document.cookie = 'broker_meta=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
  });
});
