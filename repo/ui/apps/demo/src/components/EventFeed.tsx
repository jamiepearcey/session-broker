import type { ReactElement } from 'react';
import { useSessionEvents } from '@session-broker/react';
import type { SessionStreamProviderState } from '@session-broker/react';
import { formatClock } from '../lib/format.js';
import { cn } from '../lib/utils.js';
import { StatusBadge, type StateVariant } from './StatusBadge.js';

const CONNECTION_LABEL: Record<SessionStreamProviderState, string> = {
  disabled: 'No stream',
  connecting: 'Connecting…',
  open: 'Connected',
  closed: 'Disconnected',
};

const CONNECTION_VARIANT: Record<SessionStreamProviderState, StateVariant> = {
  disabled: 'neutral',
  connecting: 'info',
  open: 'ok',
  closed: 'warn',
};

const REASON_LABEL: Record<string, string> = {
  logged_out: 'logged_out',
  upstream_revoked: 'upstream_revoked',
  admin_revoked: 'admin_revoked',
};

const REASON_VARIANT: Record<string, StateVariant> = {
  logged_out: 'neutral',
  upstream_revoked: 'error',
  admin_revoked: 'error',
};

const CUSTODY_VARIANT: Record<string, StateVariant> = {
  ok: 'ok',
  degraded: 'warn',
  dead: 'error',
};

/**
 * `GET /session/events` (§ADR-0008's HTTP/1.1-vs-HTTP/2 trade-off applies
 * here too): named SSE events, filtered server-side to this session. Under
 * the default `'leader-only'` mode only the leader tab's feed fills in —
 * every other tab shows "No stream" and still learns the same facts, just
 * at the next lazy check/refresh instead of sub-second.
 */
export function EventFeed(): ReactElement {
  const { entries, connectionState, active, activeBecauseLeader } = useSessionEvents();
  const rows = [...entries].reverse();

  return (
    <section aria-label="Live event feed" className="rounded-md border border-outline-subtle bg-surface-panel p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
          Live event feed
        </h2>
        <div className="flex items-center gap-2">
          <StatusBadge variant={CONNECTION_VARIANT[connectionState]} pulse={connectionState === 'open'}>
            {CONNECTION_LABEL[connectionState]}
          </StatusBadge>
          {active && (
            <StatusBadge variant={activeBecauseLeader ? 'active' : 'neutral'}>
              {activeBecauseLeader ? 'this tab (leader)' : 'this tab'}
            </StatusBadge>
          )}
        </div>
      </div>

      <p className="mb-3 text-[12px] leading-relaxed text-muted-foreground">
        <code className="rounded bg-surface-toolbar px-1 py-0.5 font-mono text-[11px]">GET /session/events</code> —
        push notice of <code className="rounded bg-surface-toolbar px-1 py-0.5 font-mono text-[11px]">session.killed</code>{' '}
        and <code className="rounded bg-surface-toolbar px-1 py-0.5 font-mono text-[11px]">custody.changed</code>, a
        hint that prompts this tab to act — never a source of truth on its own (INV-9).
      </p>

      {rows.length === 0 ? (
        <p className="text-[12.5px] text-muted-foreground">No events observed yet in this tab.</p>
      ) : (
        <table className="w-full text-[11.5px]">
          <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
            <tr className="border-b border-outline-subtle">
              <th className="px-2 py-1.5 text-left">time</th>
              <th className="px-2 py-1.5 text-left">event</th>
              <th className="px-2 py-1.5 text-right">detail</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((entry, i) => (
              <tr
                key={`${entry.receivedAt}-${i}`}
                className={cn('border-b border-outline-subtle/60', i === 0 && 'bg-primary/5')}
              >
                <td className="px-2 py-1.5 font-mono text-muted-foreground">{formatClock(entry.receivedAt)}</td>
                <td className="px-2 py-1.5 font-mono text-foreground">{entry.name}</td>
                <td className="px-2 py-1.5 text-right">
                  {entry.name === 'session.killed' ? (
                    <StatusBadge variant={REASON_VARIANT[entry.data.reason] ?? 'neutral'}>
                      {REASON_LABEL[entry.data.reason] ?? entry.data.reason}
                    </StatusBadge>
                  ) : (
                    <StatusBadge variant={CUSTODY_VARIANT[entry.data.custody] ?? 'neutral'}>
                      {entry.data.custody}
                    </StatusBadge>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
