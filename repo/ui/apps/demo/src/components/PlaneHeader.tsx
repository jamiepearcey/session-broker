// Ported from the ArrowRef console
// (infrastructure/query-cache/repo/ui/src/components/PlaneHeader.tsx): row 1
// = plane chip + `/route` in mono, row 2 = title + summary + actions, a
// plane-coloured left rail. Trimmed relative to the reference — this app has
// no breadcrumb trail, cross-view "not this" panel, or command palette, so
// `breadcrumb`/`vs`/`aside`/`onNavigate`/`leading` were dropped rather than
// carried over unused.
import { cn } from '../lib/utils.js';
import { PLANES, type PlaneId } from '../lib/planes.js';

const RAIL: Record<PlaneId, string> = {
  signals: 'border-plane-signals',
  compute: 'border-plane-compute',
  messaging: 'border-plane-messaging',
  budget: 'border-plane-budget',
};

const CHIP: Record<PlaneId, string> = {
  signals: 'bg-plane-signals/15 text-plane-signals',
  compute: 'bg-plane-compute/15 text-plane-compute',
  messaging: 'bg-plane-messaging/15 text-plane-messaging',
  budget: 'bg-plane-budget/15 text-plane-budget',
};

export function PlaneHeader({
  plane,
  title,
  route,
  summary,
  actions,
  children,
  className,
}: {
  plane: PlaneId;
  title: string;
  route: string;
  summary: string;
  actions?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
}) {
  const p = PLANES[plane];

  return (
    <header className={cn('shrink-0 border-b border-outline-subtle bg-surface-panel', className)}>
      <div className={cn('flex gap-0 border-l-[3px]', RAIL[plane])}>
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2 border-b border-outline-subtle/70 px-6 py-2">
            <span
              className={cn(
                'shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
                CHIP[plane],
              )}
            >
              {p.label}
            </span>
            <code className="shrink-0 rounded border border-outline-strong bg-surface-toolbar px-1.5 py-0.5 font-mono text-[10.5px] text-muted-foreground">
              {route}
            </code>
          </div>
          <div className="px-6 py-3">
            <div className="flex flex-wrap items-start gap-3">
              <div className="min-w-0 flex-1">
                <h1 className="text-[17px] font-semibold tracking-tight">{title}</h1>
                <p className="mt-0.5 max-w-2xl text-[12.5px] leading-snug text-muted-foreground">{summary}</p>
              </div>
              {actions}
            </div>
            {children}
          </div>
        </div>
      </div>
    </header>
  );
}
