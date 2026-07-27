import type { ReactElement } from 'react';
import { useLeader } from '@session-broker/react';
import { StatusBadge } from './StatusBadge.js';

/**
 * The detailed leader-election explainer, kept inside the Session view. The
 * compact, always-visible version of the same `useLeader()` state lives in
 * the sidebar (see components/Sidebar.tsx) per the "keep it prominent"
 * requirement — this panel is the fuller explanation, not a duplicate
 * source of truth.
 */
export function LeaderBadge(): ReactElement {
  const isLeader = useLeader();

  return (
    <section aria-label="Leader election" className="rounded-md border border-outline-subtle bg-surface-panel p-4">
      <h2 className="mb-3 text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
        Leader election
      </h2>
      <StatusBadge variant={isLeader ? 'active' : 'neutral'} pulse={isLeader}>
        {isLeader ? 'This tab is leader' : 'Not leader'}
      </StatusBadge>
      <p className="mt-3 text-[12px] leading-relaxed text-muted-foreground">
        Open this page in two more tabs. Exactly one holds the{' '}
        <code className="rounded bg-surface-toolbar px-1 py-0.5 font-mono text-[11px]">broker-refresh-leader</code>{' '}
        Web Lock at a time; close the leading tab and watch another promote — with no coordination traffic, because
        there is none (ADR-0008).
      </p>
    </section>
  );
}
