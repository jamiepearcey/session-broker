import { useEffect, useRef, useState, type ReactElement } from 'react';
import { useSession } from '@session-broker/react';
import { formatCountdown, secondsUntil } from '../lib/format.js';
import { cn } from '../lib/utils.js';
import { StatusBadge, type StateVariant } from './StatusBadge.js';

const STATUS_LABEL: Record<string, string> = {
  anonymous: 'Anonymous',
  active: 'Active',
  refreshing: 'Refreshing…',
  expired: 'Expired',
};

const STATUS_VARIANT: Record<string, StateVariant> = {
  anonymous: 'neutral',
  active: 'ok',
  refreshing: 'info',
  expired: 'error',
};

const CUSTODY_LABEL: Record<string, string> = {
  ok: 'OK',
  degraded: 'Degraded',
  dead: 'Dead',
};

const CUSTODY_VARIANT: Record<string, StateVariant> = {
  ok: 'ok',
  degraded: 'warn',
  dead: 'error',
};

export function LivePanel(): ReactElement {
  const { status, meta } = useSession();
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [justRotated, setJustRotated] = useState(false);
  const prevGen = useRef<number | null>(null);

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 250);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (meta && prevGen.current !== null && meta.gen !== prevGen.current) {
      setJustRotated(true);
      const timeout = setTimeout(() => setJustRotated(false), 900);
      return () => clearTimeout(timeout);
    }
    prevGen.current = meta?.gen ?? null;
    return undefined;
  }, [meta]);

  return (
    <section aria-label="Live session panel" className="rounded-md border border-outline-subtle bg-surface-panel p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">Live session</h2>
        <StatusBadge variant={STATUS_VARIANT[status] ?? 'neutral'}>{STATUS_LABEL[status] ?? status}</StatusBadge>
      </div>

      {!meta ? (
        <p className="text-[12.5px] text-muted-foreground">
          No{' '}
          <code className="rounded bg-surface-toolbar px-1 py-0.5 font-mono text-[11px]">broker_meta</code> cookie
          present — this tab has no session.
        </p>
      ) : (
        <div className="space-y-5">
          <div className="flex items-baseline gap-3">
            <span className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
              generation
            </span>
            <span
              className={cn(
                'inline-block font-mono text-4xl font-bold tabular-nums',
                justRotated && 'gen-rotate',
              )}
            >
              {meta.gen}
            </span>
          </div>

          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-[12.5px]">
            <dt className="self-center text-muted-foreground">sub</dt>
            <dd className="truncate text-right font-mono text-foreground">{meta.sub}</dd>
            <dt className="self-center text-muted-foreground">sid</dt>
            <dd className="truncate text-right font-mono text-foreground" title={meta.sid}>
              {meta.sid}
            </dd>
            <dt className="self-center text-muted-foreground">custody</dt>
            <dd className="text-right">
              <StatusBadge variant={CUSTODY_VARIANT[meta.custody] ?? 'neutral'}>
                {CUSTODY_LABEL[meta.custody] ?? meta.custody}
              </StatusBadge>
            </dd>
          </dl>

          <div className="grid grid-cols-1 gap-3 border-t border-outline-subtle pt-4 sm:grid-cols-3">
            <ClockTile label="active_until" seconds={secondsUntil(meta.active_until, nowMs)} />
            <ClockTile label="refresh_until" seconds={secondsUntil(meta.refresh_until, nowMs)} />
            <ClockTile label="absolute_until" seconds={secondsUntil(meta.absolute_until, nowMs)} />
          </div>
        </div>
      )}
    </section>
  );
}

function ClockTile({ label, seconds }: { label: string; seconds: number }): ReactElement {
  return (
    <div className="rounded-md border border-outline-subtle bg-surface-toolbar px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">{label}</div>
      <div
        className={cn(
          'mt-1 font-mono text-[15px] tabular-nums',
          seconds < 0 ? 'text-destructive' : 'text-foreground',
        )}
      >
        {formatCountdown(seconds)}
      </div>
    </div>
  );
}
