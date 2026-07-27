import type { ReactElement } from 'react';
import { PlaneHeader } from '../components/PlaneHeader.js';
import { RaceButton } from '../components/RaceButton.js';

export function RaceView(): ReactElement {
  return (
    <div className="flex h-full flex-col">
      <PlaneHeader
        plane="compute"
        route="/race"
        title="Race"
        summary="Fire 20 concurrent refreshes and watch the server's coalescing hold — 0 failed, 1 generation minted, measured live."
      />
      <div className="min-h-0 flex-1 overflow-y-auto p-6">
        <RaceButton />
      </div>
    </div>
  );
}
