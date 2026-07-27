import type { ReactElement } from 'react';
import { PlaneHeader } from '../components/PlaneHeader.js';
import { LivePanel } from '../components/LivePanel.js';
import { LeaderBadge } from '../components/LeaderBadge.js';
import { EventFeed } from '../components/EventFeed.js';

export function SessionView(): ReactElement {
  return (
    <div className="flex h-full flex-col">
      <PlaneHeader
        plane="signals"
        route="/session"
        title="Session"
        summary="The live decoded broker_meta cookie for this tab — generation, identity, custody, and the three clocks that govern it (§3/§4)."
      />
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-6">
        <LivePanel />
        <LeaderBadge />
        <EventFeed />
      </div>
    </div>
  );
}
