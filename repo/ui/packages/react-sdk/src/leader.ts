/**
 * Leader election by *holding* a Web Lock forever (ADR-0008).
 *
 * The tab that acquires `navigator.locks.request('broker-refresh-leader', ...)`
 * runs the refresh timer; the lock is released when the tab closes, when
 * `release()` is called, or (implicitly) never otherwise — at which point the
 * next waiting tab is granted the lock and promotes itself.
 *
 * One platform detail drives the shape of this file: an `AbortSignal` only
 * cancels a lock request that is still *pending*. Aborting after the lock has
 * been granted does nothing at all. So a held lock can only be given up by
 * settling the promise the callback returned — which is why the holder keeps a
 * `resolve` handle rather than relying on the controller for both cases.
 * Getting this wrong strands the lock in a tab that no longer wants it, and
 * every later election in that tab queues behind a ghost forever. There
 * is deliberately no other coordination channel (no BroadcastChannel, no
 * SharedWorker) — see ADR-0008: server-side refresh coalescing is what makes
 * redundant leaders harmless, so client coordination only needs to be an
 * optimization, never a correctness mechanism.
 *
 * Where Web Locks are unavailable (pre-2022 browsers), every tab simply
 * considers itself leader — the fallback stays exactly this simple because
 * the same server backstop absorbs the resulting redundant timers.
 */

const LOCK_NAME = 'broker-refresh-leader';

/** The subset of `LockManager` this module needs, so tests can supply a fake. */
export interface LocksLike {
  request(name: string, options: { signal?: AbortSignal }, callback: () => Promise<void>): Promise<void>;
}

export type LeaderChangeListener = (isLeader: boolean) => void;

export interface LeaderElection {
  /** Whether this tab currently holds the leader lock (or is the no-Web-Locks fallback). */
  isLeader(): boolean;
  /** Subscribe to promotion/demotion. Returns an unsubscribe function. */
  onChange(listener: LeaderChangeListener): () => void;
  /**
   * Tear down this tab's participation: aborts the pending/held lock
   * request (releasing an actually-held lock so the next tab can promote,
   * rather than leaving it orphaned) and stops reporting leadership. Meant
   * for provider unmount / test cleanup, not a normal part of the leader
   * protocol.
   */
  release(): void;
}

/**
 * Start leader election. Call once per tab (the provider owns the single
 * instance) — a second call competes for the same lock like any other tab
 * would.
 */
export function electLeader(
  locks: LocksLike | undefined = typeof navigator !== 'undefined'
    ? (navigator.locks as unknown as LocksLike | undefined)
    : undefined,
): LeaderElection {
  let leading = false;
  let released = false;
  /** Resolving this hands the lock back; set only once the lock is granted. */
  let releaseHeldLock: (() => void) | undefined;
  const listeners = new Set<LeaderChangeListener>();
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : undefined;

  function promote() {
    if (released || leading) return;
    leading = true;
    for (const listener of listeners) listener(true);
  }

  if (!locks) {
    // No Web Locks API: every tab is its own leader (ADR-0008 fallback).
    promote();
  } else {
    // The lock is held for as long as this promise stays pending, i.e.
    // forever, unless `release()` aborts the request.
    const signal = controller?.signal;
    locks
      .request(LOCK_NAME, signal ? { signal } : {}, () => {
        // Holding the lock *is* being leader, so this promise stays pending
        // for the tab's lifetime — but `release()` must be able to settle it,
        // because aborting a granted request is a no-op on the platform.
        return new Promise<void>((resolve) => {
          if (released) {
            resolve();
            return;
          }
          releaseHeldLock = resolve;
          promote();
        });
      })
      .catch(() => {
        // Abort (release()) or acquisition failure — this tab just never
        // leads; it still gets the lazy-check fallback in every tab
        // regardless of leadership.
      });
  }

  return {
    isLeader: () => leading,
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    release() {
      if (leading) {
        leading = false;
        for (const listener of listeners) listener(false);
      }
      released = true;
      // Settles a *granted* lock; the abort covers the still-pending case.
      // Both are needed — neither one alone handles both states.
      releaseHeldLock?.();
      releaseHeldLock = undefined;
      controller?.abort();
    },
  };
}
