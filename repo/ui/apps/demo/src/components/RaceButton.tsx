import { useState, type ReactElement } from 'react';
import { runForcedRace, type RaceResult } from '../lib/race.js';
import { formatMs } from '../lib/format.js';
import { cn } from '../lib/utils.js';

type Phase = 'idle' | 'running' | 'done' | 'error';

/**
 * The headline demonstration (§8 item 3): fire 20 parallel `POST
 * /session/refresh` requests and show what actually happened — never a
 * hardcoded "0 failed, 1 generation" placeholder, the real counts from
 * this run. Deliberately bypasses the SDK's single-flight (see
 * `lib/race.ts`) so this proves *server-side* coalescing, not client-side
 * request dedup.
 */
export function RaceButton(): ReactElement {
  const [phase, setPhase] = useState<Phase>('idle');
  const [result, setResult] = useState<RaceResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function fire() {
    setPhase('running');
    setErrorMessage(null);
    try {
      const outcome = await runForcedRace(20);
      setResult(outcome);
      setPhase('done');
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
      setPhase('error');
    }
  }

  return (
    <section
      aria-label="Forced concurrency race"
      className="rounded-md border border-primary/30 bg-surface-panel p-5"
    >
      <h2 className="mb-3 text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
        Forced race — the headline property
      </h2>

      <div className="flex flex-wrap items-center justify-between gap-4">
        <p className="max-w-2xl text-[12.5px] leading-relaxed text-muted-foreground">
          Fires 20 parallel{' '}
          <code className="rounded bg-surface-toolbar px-1 py-0.5 font-mono text-[11px]">
            POST /session/refresh
          </code>{' '}
          calls as raw <code className="rounded bg-surface-toolbar px-1 py-0.5 font-mono text-[11px]">fetch</code> —
          bypassing this tab&apos;s own single-flight — to exercise the server&apos;s refresh coalescing directly.
          Non-invalidating rotation plus coalescing means this should always land on{' '}
          <strong className="text-foreground">0 failed</strong> and{' '}
          <strong className="text-foreground">1 generation minted</strong>, no matter how many requests race in.
        </p>
        <button
          type="button"
          onClick={() => void fire()}
          disabled={phase === 'running'}
          className="btn-primary shrink-0 px-4 py-2 text-[13px]"
        >
          {phase === 'running' ? 'Racing…' : 'Fire forced race (20 requests)'}
        </button>
      </div>

      {phase === 'error' && errorMessage && (
        <div className="mt-4 rounded-md border border-destructive/45 bg-surface-danger px-3 py-2.5 text-[12.5px] text-warn-foreground">
          The race itself failed to run: <code className="font-mono">{errorMessage}</code>. Is the broker reachable
          at the dev proxy target?
        </div>
      )}

      {result && (
        <>
          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-5">
            <StatTile label="Requested" value={result.requested} tone="neutral" />
            <StatTile label="Succeeded" value={result.succeeded} tone="ok" />
            <StatTile
              label="Failed"
              value={result.failed}
              tone={result.failed === 0 ? 'ok' : 'error'}
              hint={result.failed === 0 ? 'target: 0' : undefined}
            />
            <StatTile
              label="Generations minted"
              value={result.generations.length}
              tone={result.generations.length <= 1 ? 'ok' : 'error'}
              hint={result.generations.length <= 1 ? 'target: 1' : `gens: ${result.generations.join(', ')}`}
            />
            <StatTile label="Wall time" value={formatMs(result.durationMs)} tone="neutral" isText />
          </div>

          {result.failureDetail.length > 0 && (
            <div className="mt-4 rounded-md border border-destructive/45 bg-surface-danger px-3 py-2.5 text-[12px] text-warn-foreground">
              {result.failureDetail.length} failure line(s), measured, not summarized away:
              <ul className="mt-1.5 list-disc space-y-0.5 pl-4 font-mono text-[11px]">
                {result.failureDetail.slice(0, 10).map((line, index) => (
                  <li key={index}>{line}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </section>
  );
}

interface StatTileProps {
  label: string;
  value: number | string;
  tone: 'ok' | 'error' | 'neutral';
  hint?: string | undefined;
  isText?: boolean;
}

const TONE_TEXT: Record<StatTileProps['tone'], string> = {
  ok: 'text-ok',
  error: 'text-destructive',
  neutral: 'text-foreground',
};

function StatTile({ label, value, tone, hint, isText }: StatTileProps): ReactElement {
  return (
    <div className="rounded-md border border-outline-subtle bg-surface-toolbar px-3 py-3">
      <div className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">{label}</div>
      <div
        className={cn(
          'mt-1 font-mono font-bold tabular-nums leading-none',
          isText ? 'text-lg' : 'text-2xl',
          TONE_TEXT[tone],
        )}
      >
        {value}
      </div>
      {hint && <div className="mt-1 truncate text-[10.5px] text-muted-foreground">{hint}</div>}
    </div>
  );
}
