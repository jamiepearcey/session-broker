/**
 * The forced-race demonstration (§8 item 3, the headline property).
 *
 * This fires `concurrency` parallel `POST /session/refresh` calls as raw
 * `fetch`, deliberately bypassing the SDK's in-tab single-flight
 * (`refresh.ts`'s `singleFlightRefresh`). That bypass is the point: the
 * property being demonstrated is the *server's* coalescing (ADR-0002),
 * i.e. that N concurrent refreshes from possibly-many tabs converge on one
 * minted generation with zero failures — not that this one tab's client
 * code successfully deduplicated its own calls, which would be a much
 * weaker (and misleading) demonstration of the same UI.
 *
 * Every number below is measured from the actual responses, never assumed.
 */

export interface RaceResult {
  requested: number;
  succeeded: number;
  failed: number;
  /** Distinct `gen` values seen across all successful responses, sorted ascending. */
  generations: number[];
  durationMs: number;
  /** One line per failure, for the log — not fabricated, taken from the actual rejection/response. */
  failureDetail: string[];
}

export async function runForcedRace(concurrency = 20): Promise<RaceResult> {
  const started = performance.now();

  const attempts = Array.from({ length: concurrency }, () =>
    fetch('/session/refresh', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { accept: 'application/json' },
    }),
  );
  const settled = await Promise.allSettled(attempts);
  const durationMs = performance.now() - started;

  let succeeded = 0;
  const generations: number[] = [];
  const failureDetail: string[] = [];

  for (const outcome of settled) {
    if (outcome.status === 'rejected') {
      failureDetail.push(describeReason(outcome.reason));
      continue;
    }
    const response = outcome.value;
    if (!response.ok) {
      failureDetail.push(`HTTP ${response.status}`);
      continue;
    }
    try {
      const body = (await response.json()) as { gen?: unknown };
      if (typeof body.gen === 'number') {
        succeeded += 1;
        generations.push(body.gen);
      } else {
        failureDetail.push('200 response missing numeric "gen"');
      }
    } catch {
      failureDetail.push('200 response was not valid JSON');
    }
  }

  const distinctGenerations = Array.from(new Set(generations)).sort((a, b) => a - b);

  return {
    requested: concurrency,
    succeeded,
    failed: concurrency - succeeded,
    generations: distinctGenerations,
    durationMs,
    failureDetail,
  };
}

function describeReason(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}
