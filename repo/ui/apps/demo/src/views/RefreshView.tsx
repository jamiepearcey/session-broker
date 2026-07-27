import type { ReactElement } from 'react';
import { PlaneHeader } from '../components/PlaneHeader.js';
import { RefreshLog } from '../components/RefreshLog.js';

export function RefreshView(): ReactElement {
  return (
    <div className="flex h-full flex-col">
      <PlaneHeader
        plane="messaging"
        route="/refresh"
        title="Refresh log"
        summary="Every refresh this tab has observed — measured client round-trip next to the server's own X-Broker-Handler-Us, kept separate on purpose."
      />
      <div className="min-h-0 flex-1 overflow-y-auto p-6">
        <RefreshLog />
      </div>
    </div>
  );
}
