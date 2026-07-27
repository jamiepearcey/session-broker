import { useState, type ReactElement, type ReactNode } from 'react';
import { useSession } from '@session-broker/react';
import { cn } from '../lib/utils.js';
import { Select } from './Select.js';
import {
  dumpMockIdpState,
  expireSubject,
  failNextUpstreamCalls,
  revokeRefreshFor,
  type ControlResult,
} from '../lib/testControl.js';

const STATUS_OPTIONS = [
  { value: '500', label: '500', description: 'Internal server error' },
  { value: '502', label: '502', description: 'Bad gateway' },
  { value: '503', label: '503', description: 'Service unavailable' },
  { value: '429', label: '429', description: 'Rate limited' },
];

const ERROR_OPTIONS = [
  { value: 'temporarily_unavailable', label: 'temporarily_unavailable' },
  { value: 'invalid_grant', label: 'invalid_grant' },
  { value: 'server_error', label: 'server_error' },
];

/**
 * §8 item 5: drives the mock IdP's `/__test__/*` control surface
 * (`crates/mock-idp`) via the Vite dev proxy. These exercise the failure
 * paths (upstream expiry, refresh-token revocation, injected `/token`
 * failures) that `keepalive.rs` (M4) and the OAuth flow (M2) are meant to
 * react to; until those land the buttons still fire real requests against
 * the mock IdP, but there is no session-broker keepalive worker yet to
 * observe reacting to them.
 */
export function FailureControls(): ReactElement {
  const { meta } = useSession();
  const [subject, setSubject] = useState(meta?.sub ?? 'user-1');
  const [failCount, setFailCount] = useState(3);
  const [failStatus, setFailStatus] = useState('503');
  const [failError, setFailError] = useState('temporarily_unavailable');
  const [lastResult, setLastResult] = useState<{ label: string; result: ControlResult<unknown> } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function run<T>(label: string, action: () => Promise<ControlResult<T>>) {
    setBusy(label);
    const result = await action();
    setLastResult({ label, result });
    setBusy(null);
  }

  return (
    <section aria-label="Failure-path controls" className="space-y-4">
      <ControlGroup title="Subject">
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="text"
            className="input w-48"
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
            aria-label="Subject"
          />
          <span className="text-[11.5px] text-muted-foreground">
            defaults to this tab&apos;s meta.sub once logged in
          </span>
        </div>
      </ControlGroup>

      <ControlGroup title="Kill / degrade upstream">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className="btn-ghost"
            disabled={busy !== null}
            onClick={() => void run('expire', () => expireSubject(subject))}
          >
            Force upstream token expiry
          </button>
          <button
            type="button"
            className="btn-ghost"
            disabled={busy !== null}
            onClick={() => void run('revoke-refresh', () => revokeRefreshFor(subject))}
          >
            Revoke refresh token
          </button>
        </div>
      </ControlGroup>

      <ControlGroup title="Inject upstream failures">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <label className="space-y-1">
            <span className="block text-[10.5px] uppercase tracking-[0.06em] text-muted-foreground">count</span>
            <input
              type="text"
              inputMode="numeric"
              className="input w-full"
              value={failCount}
              onChange={(event) => setFailCount(Number(event.target.value) || 1)}
              aria-label="Failure count"
            />
          </label>
          <label className="space-y-1">
            <span className="block text-[10.5px] uppercase tracking-[0.06em] text-muted-foreground">status</span>
            <Select value={failStatus} onChange={setFailStatus} options={STATUS_OPTIONS} aria-label="Failure status" />
          </label>
          <label className="space-y-1">
            <span className="block text-[10.5px] uppercase tracking-[0.06em] text-muted-foreground">error code</span>
            <Select
              value={failError}
              onChange={setFailError}
              options={ERROR_OPTIONS}
              aria-label="Failure error code"
            />
          </label>
        </div>
        <button
          type="button"
          className="btn-ghost mt-3"
          disabled={busy !== null}
          onClick={() => void run('fail-next', () => failNextUpstreamCalls(failCount, Number(failStatus), failError))}
        >
          Fail next {failCount} upstream call(s)
        </button>
      </ControlGroup>

      <ControlGroup title="Inspect">
        <button
          type="button"
          className="btn-ghost"
          disabled={busy !== null}
          onClick={() => void run('state', () => dumpMockIdpState())}
        >
          Dump mock-idp state
        </button>
      </ControlGroup>

      {lastResult && (
        <p className={cn('font-mono text-[11.5px]', lastResult.result.ok ? 'text-ok' : 'text-destructive')}>
          {lastResult.label}: {lastResult.result.ok ? 'ok' : 'failed'} (status {lastResult.result.status}
          {lastResult.result.error ? `, ${lastResult.result.error}` : ''})
          {lastResult.result.body ? ` — ${JSON.stringify(lastResult.result.body).slice(0, 200)}` : ''}
        </p>
      )}
    </section>
  );
}

function ControlGroup({ title, children }: { title: string; children: ReactNode }): ReactElement {
  return (
    <div className="border-t border-outline-subtle pt-4 first:border-t-0 first:pt-0">
      <h3 className="mb-2 text-[12px] font-semibold text-foreground/90">{title}</h3>
      {children}
    </div>
  );
}
