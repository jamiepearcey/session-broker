import { useState, type ReactElement } from 'react';
import { useRefreshLog } from '@session-broker/react';
import { formatClock, formatMs, formatUs } from '../lib/format.js';
import { cn } from '../lib/utils.js';

/**
 * §8 item 4: measured `performance.now()` round-trip per refresh, shown
 * next to the server-reported `X-Broker-Handler-Us` — two distinct
 * numbers, so the sub-ms server-side claim is visibly separate from
 * network RTT rather than conflated into one figure.
 */
export function RefreshLog(): ReactElement {
  const { entries, refreshNow } = useRefreshLog();
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function trigger() {
    setTriggering(true);
    setError(null);
    try {
      await refreshNow();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTriggering(false);
    }
  }

  const rows = [...entries].reverse();

  return (
    <section aria-label="Refresh log" className="rounded-md border border-outline-subtle bg-surface-panel p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">Refresh log</h2>
        <button type="button" onClick={() => void trigger()} disabled={triggering} className="btn-ghost">
          {triggering ? 'Refreshing…' : 'Trigger refresh'}
        </button>
      </div>

      {error && <p className="mb-2 text-[12px] text-destructive">Last manual refresh failed: {error}</p>}

      {rows.length === 0 ? (
        <p className="text-[12.5px] text-muted-foreground">No refreshes observed yet in this tab.</p>
      ) : (
        <table className="w-full text-[11.5px]">
          <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
            <tr className="border-b border-outline-subtle">
              <th className="px-2 py-1.5 text-left">time</th>
              <th className="px-2 py-1.5 text-right">gen</th>
              <th className="px-2 py-1.5 text-right">client RTT</th>
              <th className="px-2 py-1.5 text-right">server handler</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((entry, i) => (
              <tr
                key={`${entry.at}-${entry.gen}`}
                className={cn('border-b border-outline-subtle/60', i === 0 && 'bg-primary/5')}
              >
                <td className="px-2 py-1.5 font-mono text-muted-foreground">{formatClock(entry.at)}</td>
                <td className="px-2 py-1.5 text-right font-mono tabular-nums text-foreground">{entry.gen}</td>
                <td className="px-2 py-1.5 text-right font-mono tabular-nums text-muted-foreground">
                  {formatMs(entry.rttMs)}
                </td>
                <td className="px-2 py-1.5 text-right font-mono tabular-nums text-muted-foreground">
                  {formatUs(entry.serverHandlerUs)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
