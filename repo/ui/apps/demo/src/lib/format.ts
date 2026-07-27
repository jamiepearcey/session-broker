/** Formatting helpers shared by the panels — kept dumb on purpose, no fabricated fallback values. */

export function formatMs(ms: number): string {
  return `${ms.toFixed(2)} ms`;
}

export function formatUs(us: number | null): string {
  if (us === null) return '—';
  if (us >= 1000) return `${(us / 1000).toFixed(2)} ms`;
  return `${us.toFixed(0)} µs`;
}

export function formatClock(epochMs: number): string {
  return new Date(epochMs).toLocaleTimeString(undefined, {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/** Seconds-until (or since, negative) an epoch-seconds timestamp, for the live-updating countdowns. */
export function secondsUntil(epochSeconds: number, nowMs: number): number {
  return Math.round(epochSeconds - nowMs / 1000);
}

export function formatCountdown(seconds: number): string {
  const sign = seconds < 0 ? '-' : '';
  const abs = Math.abs(seconds);
  const h = Math.floor(abs / 3600);
  const m = Math.floor((abs % 3600) / 60);
  const s = abs % 60;
  const parts = h > 0 ? [h, m, s] : [m, s];
  return sign + parts.map((p, i) => (i === 0 ? String(p) : String(p).padStart(2, '0'))).join(':');
}
