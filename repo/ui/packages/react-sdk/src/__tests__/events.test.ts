import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startSessionEventStream } from '../events.js';
import type { EventSourceLike } from '../events.js';

/**
 * A fake `EventSource` scripted by the test rather than a real timer, but
 * one that enforces the two platform rules this module is built around —
 * an earlier, laxer fake is exactly how the `AbortSignal`/held-lock bug in
 * leader.ts slipped through, and the brief for this file names the same
 * risk explicitly:
 *
 * 1. **No status visibility.** `emitError()` fires a bare `Event` — there is
 *    no `.status`, no way to tell a 401 apart from a network blip. Any
 *    production code that tried to branch on something richer than "error
 *    happened" would have nothing to read here, matching the real API.
 * 2. **A closed source hears nothing further.** Once `close()` has been
 *    called, `emitOpen()`/`emitError()`/`emitMessage()` are no-ops — mirrors
 *    `readyState === CLOSED` being permanent. A fake that kept delivering
 *    events after close would hide bugs where production code forgets to
 *    drop its reference to a stale instance.
 *
 * Each reconnect in `events.ts` constructs a *new* `FakeEventSource` (via
 * `factory`), exactly as a new `EventSource` is constructed for each of our
 * own manual reconnect attempts — this fake never reconnects itself, because
 * `events.ts` never lets the browser do that; it always closes and re-opens
 * under its own backoff instead.
 */
class FakeEventSource implements EventSourceLike {
  readonly url: string;
  closed = false;
  private readonly listeners = new Map<string, Set<(event: Event) => void>>();

  constructor(url: string) {
    this.url = url;
  }

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
    if (this.closed) return;
    for (const listener of this.listeners.get('open') ?? []) listener(new Event('open'));
  }

  /** No status, no detail — exactly what the real `error` event carries. */
  emitError(): void {
    if (this.closed) return;
    for (const listener of this.listeners.get('error') ?? []) listener(new Event('error'));
  }

  emitMessage(name: string, data: unknown): void {
    if (this.closed) return;
    const event = new MessageEvent(name, { data: JSON.stringify(data) });
    for (const listener of this.listeners.get(name) ?? []) listener(event);
  }
}

function harness() {
  const instances: FakeEventSource[] = [];
  const factory = (url: string) => {
    const source = new FakeEventSource(url);
    instances.push(source);
    return source;
  };
  return { instances, factory };
}

const SESSION_KILLED = { sid: 'sid12345', reason: 'upstream_revoked' as const };
const CUSTODY_CHANGED = { sid: 'sid12345', custody: 'degraded' as const };

describe('startSessionEventStream (single connection, multiple subscribers)', () => {
  it('opens exactly one connection no matter how many listeners subscribe', () => {
    const { instances, factory } = harness();
    const stream = startSessionEventStream({ factory });

    const seenA: unknown[] = [];
    const seenB: unknown[] = [];
    stream.subscribe((event) => seenA.push(event));
    stream.subscribe((event) => seenB.push(event));

    expect(instances).toHaveLength(1);

    instances[0]?.emitOpen();
    instances[0]?.emitMessage('session.killed', SESSION_KILLED);

    expect(seenA).toHaveLength(1);
    expect(seenB).toHaveLength(1);
    expect(seenA[0]).toMatchObject({ name: 'session.killed', data: SESSION_KILLED });

    stream.close();
  });

  it('an unsubscribed listener stops receiving events but the shared connection stays open for the rest', () => {
    const { instances, factory } = harness();
    const stream = startSessionEventStream({ factory });
    instances[0]?.emitOpen();

    const seenA: unknown[] = [];
    const seenB: unknown[] = [];
    const unsubA = stream.subscribe((event) => seenA.push(event));
    stream.subscribe((event) => seenB.push(event));
    unsubA();

    instances[0]?.emitMessage('custody.changed', CUSTODY_CHANGED);

    expect(seenA).toHaveLength(0);
    expect(seenB).toHaveLength(1);
    expect(instances).toHaveLength(1);

    stream.close();
  });

  it('decodes custody.changed and session.killed payloads, and drops malformed ones instead of throwing', () => {
    const { instances, factory } = harness();
    const stream = startSessionEventStream({ factory });
    instances[0]?.emitOpen();

    const seen: unknown[] = [];
    stream.subscribe((event) => seen.push(event));

    instances[0]?.emitMessage('custody.changed', CUSTODY_CHANGED);
    instances[0]?.emitMessage('session.killed', { sid: 'x', reason: 'not_a_real_reason' });
    instances[0]?.emitMessage('custody.changed', { sid: 'x', custody: 'not_a_real_custody' });

    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ name: 'custody.changed', data: CUSTODY_CHANGED });

    stream.close();
  });
});

describe('startSessionEventStream (terminal halt — no infinite reconnect)', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('halts after maxConsecutiveFailures errors with no intervening open, and never reconnects again', async () => {
    // Regression shape: this endpoint 401s forever once the session is dead,
    // and EventSource cannot see that status — left unchecked this is the
    // exact infinite-reconnect-against-a-dead-session bug refresh.ts's
    // TERMINAL_CODES halt already fixed once, one layer up.
    const { instances, factory } = harness();
    const stream = startSessionEventStream({ factory, maxConsecutiveFailures: 3, baseBackoffMs: 1_000, maxBackoffMs: 30_000 });

    expect(instances).toHaveLength(1);
    instances[0]?.emitError();
    expect(stream.isHalted()).toBe(false);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(instances).toHaveLength(2);
    instances[1]?.emitError();
    expect(stream.isHalted()).toBe(false);

    await vi.advanceTimersByTimeAsync(2_000);
    expect(instances).toHaveLength(3);
    instances[2]?.emitError();

    expect(stream.isHalted()).toBe(true);
    expect(stream.getState()).toBe('closed');

    // No amount of further waiting brings back a 4th connection attempt.
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(instances).toHaveLength(3);

    stream.close();
  });

  it('every failed attempt closes its own EventSource — a halted stream never leaves a live connection behind', async () => {
    const { instances, factory } = harness();
    startSessionEventStream({ factory, maxConsecutiveFailures: 2, baseBackoffMs: 1_000 });

    instances[0]?.emitError();
    await vi.advanceTimersByTimeAsync(1_000);
    instances[1]?.emitError();

    for (const instance of instances) expect(instance.closed).toBe(true);
  });

  it('an open in between resets the failure streak, so it does not halt on the count alone', async () => {
    const { instances, factory } = harness();
    const stream = startSessionEventStream({ factory, maxConsecutiveFailures: 3, baseBackoffMs: 1_000 });

    instances[0]?.emitError();
    await vi.advanceTimersByTimeAsync(1_000);
    instances[1]?.emitOpen(); // proves the endpoint is reachable — the streak resets here
    instances[1]?.emitError();
    await vi.advanceTimersByTimeAsync(1_000); // back to the base delay, not doubled again
    expect(instances).toHaveLength(3);
    instances[2]?.emitError();

    // Two consecutive failures since the last open (not three) — still armed.
    expect(stream.isHalted()).toBe(false);

    stream.close();
  });
});

describe('startSessionEventStream (backoff between reconnects)', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('doubles the delay after each consecutive failure, capped at maxBackoffMs', async () => {
    const { instances, factory } = harness();
    startSessionEventStream({
      factory,
      maxConsecutiveFailures: 10,
      baseBackoffMs: 1_000,
      maxBackoffMs: 5_000,
    });

    expect(instances).toHaveLength(1);
    instances[0]?.emitError();

    // 1st retry: 1000ms
    await vi.advanceTimersByTimeAsync(999);
    expect(instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(instances).toHaveLength(2);

    // 2nd retry: 2000ms
    instances[1]?.emitError();
    await vi.advanceTimersByTimeAsync(1_999);
    expect(instances).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(instances).toHaveLength(3);

    // 3rd retry: 4000ms
    instances[2]?.emitError();
    await vi.advanceTimersByTimeAsync(3_999);
    expect(instances).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(1);
    expect(instances).toHaveLength(4);

    // 4th retry would be 8000ms, but capped at maxBackoffMs (5000ms).
    instances[3]?.emitError();
    await vi.advanceTimersByTimeAsync(4_999);
    expect(instances).toHaveLength(4);
    await vi.advanceTimersByTimeAsync(1);
    expect(instances).toHaveLength(5);
  });

  it('never fires a reconnect attempt before its computed delay, even under repeated fake-timer advances', async () => {
    const { instances, factory } = harness();
    startSessionEventStream({ factory, maxConsecutiveFailures: 10, baseBackoffMs: 2_000 });
    instances[0]?.emitError();

    for (let i = 0; i < 19; i += 1) {
      await vi.advanceTimersByTimeAsync(100);
      expect(instances).toHaveLength(1);
    }
    await vi.advanceTimersByTimeAsync(100); // total 2000ms
    expect(instances).toHaveLength(2);
  });
});

describe('startSessionEventStream (state and lifecycle)', () => {
  it('starts connecting, moves to open, and reports closed after close()', () => {
    const { instances, factory } = harness();
    const stream = startSessionEventStream({ factory });

    expect(stream.getState()).toBe('connecting');
    instances[0]?.emitOpen();
    expect(stream.getState()).toBe('open');

    stream.close();
    expect(stream.getState()).toBe('closed');
    expect(instances[0]?.closed).toBe(true);
  });

  it('close() is idempotent and stops any pending reconnect', async () => {
    vi.useFakeTimers();
    try {
      const { instances, factory } = harness();
      const stream = startSessionEventStream({ factory, baseBackoffMs: 1_000 });
      instances[0]?.emitError();

      stream.close();
      stream.close();
      await vi.advanceTimersByTimeAsync(10_000);

      expect(instances).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('reports connection failures via onError without throwing', () => {
    const { instances, factory } = harness();
    const onError = vi.fn();
    const stream = startSessionEventStream({ factory, onError });

    instances[0]?.emitError();

    expect(onError).toHaveBeenCalledTimes(1);
    stream.close();
  });
});

describe('startSessionEventStream (no EventSource available)', () => {
  it('degrades quietly to a halted, closed stream instead of throwing when no factory is available and EventSource is undefined', () => {
    const globalWithEventSource = globalThis as { EventSource?: unknown };
    const originalEventSource = globalWithEventSource.EventSource;
    delete globalWithEventSource.EventSource;
    try {
      const stream = startSessionEventStream({});
      expect(stream.isHalted()).toBe(true);
      expect(stream.getState()).toBe('closed');
      stream.close();
    } finally {
      globalWithEventSource.EventSource = originalEventSource;
    }
  });
});
