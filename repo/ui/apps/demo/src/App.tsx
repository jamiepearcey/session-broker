import type { ReactElement } from 'react';
import { Sidebar } from './components/Sidebar.js';
import { SessionView } from './views/SessionView.js';
import { RaceView } from './views/RaceView.js';
import { RefreshView } from './views/RefreshView.js';
import { FailuresView } from './views/FailuresView.js';
import { useRoute } from './lib/route.js';

// Structure ported from the ArrowRef console
// (infrastructure/query-cache/repo/ui/src/App.tsx): a fixed left rail, one
// view at a time in the main pane, over the same dark token set. Routing
// stays a trivial hash router (lib/route.ts) per the porting brief — no
// router dependency for four flat views.
export function App(): ReactElement {
  const [view, navigate] = useRoute();

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-surface-app text-foreground">
      <Sidebar view={view} onNavigate={navigate} />
      <main className="min-w-0 flex-1">
        {view === 'session' && <SessionView />}
        {view === 'race' && <RaceView />}
        {view === 'refresh' && <RefreshView />}
        {view === 'failures' && <FailuresView />}
      </main>
    </div>
  );
}
