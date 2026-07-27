import { describe, expect, it } from 'vitest';
import { electLeader } from '../leader.js';
import type { LocksLike } from '../leader.js';

/**
 * A minimal, exclusive, FIFO-queued mock of `navigator.locks` for the one
 * lock name this module uses: at most one holder at a time, and the next
 * waiter granted when the holder gives the lock up.
 *
 * It models one platform rule that an earlier, laxer version of this fake did
 * not, and which hid a real bug: **an `AbortSignal` cancels only a pending
 * request.** Once the lock is granted, aborting does nothing, and the lock is
 * released solely by the callback's promise settling.
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
        // The lock lives exactly as long as the callback's promise.
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
        // Matches the platform: a granted lock ignores the signal entirely.
        if (granted) return;
        const queued = this.queue.indexOf(tryAcquire);
        if (queued >= 0) this.queue.splice(queued, 1);
        reject(new DOMException('aborted', 'AbortError'));
      });
      tryAcquire();
    });
  }
}

describe('electLeader (Web Locks unavailable)', () => {
  it('every tab is its own leader in the fallback path', () => {
    const election = electLeader(undefined);
    expect(election.isLeader()).toBe(true);
  });
});

describe('electLeader (mocked navigator.locks)', () => {
  it('acquires the lock and reports leadership once granted', async () => {
    const locks = new FakeLockManager();
    const election = electLeader(locks);
    await Promise.resolve();
    await Promise.resolve();

    expect(election.isLeader()).toBe(true);
  });

  it('a second tab stays non-leader while the first holds the lock, then is promoted on release', async () => {
    const locks = new FakeLockManager();

    const tabA = electLeader(locks);
    await Promise.resolve();
    await Promise.resolve();
    expect(tabA.isLeader()).toBe(true);

    const promotions: boolean[] = [];
    const tabB = electLeader(locks);
    tabB.onChange((leading) => promotions.push(leading));
    await Promise.resolve();
    await Promise.resolve();
    expect(tabB.isLeader()).toBe(false);

    tabA.release();
    await Promise.resolve();
    await Promise.resolve();

    expect(tabA.isLeader()).toBe(false);
    expect(tabB.isLeader()).toBe(true);
    expect(promotions).toEqual([true]);
  });

  it('onChange fires with false when a held lock is released', async () => {
    const locks = new FakeLockManager();
    const election = electLeader(locks);
    await Promise.resolve();
    await Promise.resolve();

    const seen: boolean[] = [];
    election.onChange((leading) => seen.push(leading));
    election.release();

    expect(seen).toEqual([false]);
  });

  it('onChange can be unsubscribed', async () => {
    const locks = new FakeLockManager();
    const election = electLeader(locks);
    await Promise.resolve();
    await Promise.resolve();

    const seen: boolean[] = [];
    const unsubscribe = election.onChange((leading) => seen.push(leading));
    unsubscribe();
    election.release();

    expect(seen).toEqual([]);
  });

  it('three tabs promote one at a time as each leader releases', async () => {
    const locks = new FakeLockManager();
    const tabs = [electLeader(locks), electLeader(locks), electLeader(locks)];
    await Promise.resolve();
    await Promise.resolve();

    const leaderIndex = () => tabs.findIndex((tab) => tab.isLeader());
    expect(leaderIndex()).toBe(0);

    tabs[0]?.release();
    await Promise.resolve();
    await Promise.resolve();
    expect(leaderIndex()).toBe(1);

    tabs[1]?.release();
    await Promise.resolve();
    await Promise.resolve();
    expect(leaderIndex()).toBe(2);
  });
});

describe('electLeader (release semantics)', () => {
  it('releasing a *held* lock lets the next tab promote', async () => {
    // Regression: an AbortSignal does not release a granted Web Lock, so a
    // release() that only aborted left the lock stranded and every later
    // election in that tab queued behind a ghost holder forever. Observed
    // live as a tab that held the lock but rendered "Not leader".
    const locks = new FakeLockManager();
    const first = electLeader(locks);
    await Promise.resolve();
    await Promise.resolve();
    expect(first.isLeader()).toBe(true);

    const second = electLeader(locks);
    await Promise.resolve();
    await Promise.resolve();
    expect(second.isLeader()).toBe(false);

    first.release();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    expect(first.isLeader()).toBe(false);
    expect(second.isLeader()).toBe(true);
  });

  it('a remounted provider reacquires leadership in the same tab', async () => {
    // React StrictMode mounts effects twice in development; the first
    // election must hand the lock back so the second can lead.
    const locks = new FakeLockManager();
    const mounted = electLeader(locks);
    await Promise.resolve();
    await Promise.resolve();
    mounted.release();

    const remounted = electLeader(locks);
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();

    expect(remounted.isLeader()).toBe(true);
  });
});
