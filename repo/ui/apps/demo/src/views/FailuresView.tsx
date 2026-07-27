import type { ReactElement } from 'react';
import { PlaneHeader } from '../components/PlaneHeader.js';
import { FailureControls } from '../components/FailureControls.js';

export function FailuresView(): ReactElement {
  return (
    <div className="flex h-full flex-col">
      <PlaneHeader
        plane="budget"
        route="/failures"
        title="Failure paths"
        summary="Drive the mock IdP directly — expire tokens, revoke refresh grants, inject upstream failures — and watch custody react."
      />
      <div className="min-h-0 flex-1 overflow-y-auto p-6">
        <FailureControls />
      </div>
    </div>
  );
}
