// The left rail, in the ArrowRef console's register (brand + liveness dot,
// uppercase micro-caps, lucide icons, plane-tinted active states, a pinned
// footer) — trimmed to this app's much smaller surface: no InfraSwitcher, no
// project grid, just four flat views. The liveness dot here is driven by the
// real `useSession().status`, not a `/healthz` poll, since that is the truer
// "is this tab alive" signal for a client demo.
import { useEffect, useState } from 'react';
import { useLeader, useSession } from '@session-broker/react';
import { AlertTriangle, Activity, LogIn, LogOut, Moon, ScrollText, ShieldCheck, Sun, Zap } from 'lucide-react';
import { cn } from '../lib/utils.js';
import { ROUTE_PATH, type ViewId } from '../lib/route.js';
import { StatusBadge } from './StatusBadge.js';

const NAV: { id: ViewId; label: string; icon: typeof Activity }[] = [
  { id: 'session', label: 'Session', icon: Activity },
  { id: 'race', label: 'Race', icon: Zap },
  { id: 'refresh', label: 'Refresh log', icon: ScrollText },
  { id: 'failures', label: 'Failure paths', icon: AlertTriangle },
];

const STATUS_DOT: Record<string, string> = {
  active: 'bg-ok',
  refreshing: 'bg-info animate-pulse',
  expired: 'bg-destructive',
  anonymous: 'bg-muted-foreground',
};

const THEME_KEY = 'session-broker-demo.theme';

export function Sidebar({ view, onNavigate }: { view: ViewId; onNavigate: (v: ViewId) => void }) {
  const { status, login, logout } = useSession();
  const isLeader = useLeader();
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      return localStorage.getItem(THEME_KEY) === 'light' ? 'light' : 'dark';
    } catch {
      return 'dark';
    }
  });

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* private mode */
    }
  }, [theme]);

  return (
    <aside className="flex h-full w-[240px] shrink-0 flex-col border-r border-outline-subtle bg-surface-sidebar">
      <div className="flex items-center gap-2 border-b border-outline-subtle px-3 py-3">
        <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-icon-tile text-icon-tile-foreground">
          <ShieldCheck className="h-3.5 w-3.5" />
        </div>
        <div className="min-w-0 flex-1 leading-tight">
          <div className="text-[13px] font-semibold tracking-tight">session-broker</div>
        </div>
        <span
          title={`Session status: ${status}`}
          className={cn('h-2 w-2 shrink-0 rounded-full', STATUS_DOT[status] ?? 'bg-muted-foreground')}
        />
      </div>

      {/* Leader badge: kept prominent (always visible, not tucked inside the
          Session view) per the porting brief — a StatusBadge with `pulse`
          exactly when `useLeader()` is true. */}
      <div className="border-b border-outline-subtle px-3 py-2.5">
        <StatusBadge variant={isLeader ? 'active' : 'neutral'} pulse={isLeader} className="w-full justify-center">
          {isLeader ? 'This tab is leader' : 'Not leader'}
        </StatusBadge>
      </div>

      <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto p-2">
        {NAV.map((n) => {
          const active = view === n.id;
          const Icon = n.icon;
          return (
            <button
              key={n.id}
              type="button"
              aria-current={active ? 'page' : undefined}
              onClick={() => onNavigate(n.id)}
              className={cn(
                'flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left transition-colors',
                active ? 'bg-surface-active' : 'hover:bg-surface-hover',
              )}
            >
              <Icon className={cn('h-4 w-4 shrink-0', active ? 'text-icon-active' : 'text-icon-muted')} />
              <span
                className={cn(
                  'block truncate text-[13px]',
                  active ? 'font-medium text-foreground' : 'text-foreground/80',
                )}
              >
                {n.label}
              </span>
              <code className="ml-auto shrink-0 font-mono text-[10px] text-muted-foreground">
                {ROUTE_PATH[n.id]}
              </code>
            </button>
          );
        })}
      </nav>

      <div className="flex flex-col gap-1 border-t border-outline-subtle p-2">
        <button
          type="button"
          onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
          className="flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-[12.5px] text-foreground/80 hover:bg-surface-hover"
        >
          {theme === 'dark' ? (
            <Sun className="h-4 w-4 shrink-0 text-icon-muted" />
          ) : (
            <Moon className="h-4 w-4 shrink-0 text-icon-muted" />
          )}
          {theme === 'dark' ? 'Light theme' : 'Dark theme'}
        </button>
        {status === 'anonymous' || status === 'expired' ? (
          <button type="button" onClick={() => login()} className="btn-primary justify-center">
            <LogIn className="h-3.5 w-3.5" /> Log in
          </button>
        ) : (
          <button type="button" onClick={() => void logout()} className="btn-ghost justify-center">
            <LogOut className="h-3.5 w-3.5" /> Log out
          </button>
        )}
      </div>
    </aside>
  );
}
