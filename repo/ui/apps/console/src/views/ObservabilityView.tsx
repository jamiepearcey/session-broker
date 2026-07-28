// Setting up observability, and the one runtime control the console is allowed
// to have.
//
// ## The line this view draws, and why
//
// It can change **how loud the diagnostics are**. It cannot change **where the
// record goes** — sinks, retention, redaction and the audit tiers are
// deployment config, applied at restart (ADR-0015 §"Runtime controls").
//
// The reason is direct: this console holds the admin key, and blinding the
// audit trail is the first thing someone who reached it would want to do.
// "That needs a config change and a restart" is a meaningfully higher bar than
// "that needs the credential they already have". So everything below either
// *reports* configuration or *generates the config you would paste*, and the
// only thing it mutates is a verbosity level that expires on its own.

import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Clipboard,
  Check,
  Gauge,
  RefreshCw,
  ScrollText,
  Volume2,
} from "lucide-react";

import { StatusBadge } from "@/components/StatusBadge";
import { ErrorNote, Panel, Toolbar } from "@/components/chrome";
import { adminApi, fmtTime, fmtUntil, type Observability } from "@/lib/api";

/** Directives an operator actually reaches for, rather than a level dropdown.
 *  `EnvFilter` takes per-target directives and during an incident that is the
 *  shape you want — the whole broker at trace is mostly noise from the parts
 *  that are working. */
// Every preset names BOTH `session_broker` (the crate's module-path events) and
// `broker` (the explicit targets — `broker::http`, `broker::authz`,
// `broker::audit`, `broker::telemetry`). An `EnvFilter` directive matches the
// target, so `session_broker=debug` alone turns on none of the per-request or
// authz detail an operator raising verbosity during an incident is actually
// after — it looks like it worked and shows nothing.
const DEFAULT_FILTER = "session_broker=debug,broker=debug";

const PRESETS = [
  { label: "Debug (whole broker)", filter: DEFAULT_FILTER },
  { label: "Trace (whole broker)", filter: "session_broker=trace,broker=trace" },
  { label: "HTTP requests", filter: "session_broker=info,broker::http=debug" },
  { label: "Authz decisions", filter: "session_broker=info,broker::authz=debug" },
  { label: "Audit stream", filter: "session_broker=info,broker::audit=debug" },
  { label: "Keepalive worker", filter: "session_broker::keepalive=trace" },
];

const DURATIONS = [
  { label: "5 minutes", secs: 300 },
  { label: "15 minutes", secs: 900 },
  { label: "1 hour", secs: 3600 },
];

export function ObservabilityView() {
  const [state, setState] = useState<Observability | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [filter, setFilter] = useState(DEFAULT_FILTER);
  const [duration, setDuration] = useState(900);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setState(await adminApi.observability());
      setError(null);
    } catch (e) {
      setError(e as Error);
    }
  }, []);

  useEffect(() => {
    void load();
    // An override expires on the broker's own timer, so a static view would go
    // on claiming the lights are up minutes after they came down.
    const timer = setInterval(() => void load(), 10_000);
    return () => clearInterval(timer);
  }, [load]);

  const apply = async (restore: boolean) => {
    setBusy(true);
    try {
      if (restore) await adminApi.restoreLogLevel();
      else await adminApi.setLogLevel(filter, duration);
      await load();
      setError(null);
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Toolbar
        title="Observability"
        blurb="Two planes with different promises. Diagnostics (logs and metrics) are lossy, cheap and shipped by your deployment. The audit record is durable, queryable and kept for a bounded window in the broker's own store. This page reports both, and can raise the diagnostic volume for a while — it cannot move the record."
        icon={Activity}
      >
        {state?.override_active && <StatusBadge variant="warn">verbosity raised</StatusBadge>}
        {state && state.audit_dropped_total > 0 && (
          <StatusBadge variant="error">{state.audit_dropped_total} audit events dropped</StatusBadge>
        )}
        <button type="button" onClick={() => void load()} className="btn-ghost">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </Toolbar>

      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
        {error && <ErrorNote error={error} />}
        {state === null && !error && <p className="text-[12px] text-muted-foreground">Loading…</p>}

        {state && (
          <>
            {state.audit_dropped_total > 0 && (
              <Panel tone="danger">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <div className="space-y-1">
                    <div className="text-[12px] font-medium text-foreground">
                      The audit record has a hole.
                    </div>
                    <p className="text-[11.5px] text-muted-foreground">
                      {state.audit_dropped_total} events were dropped at the queue bound since this
                      broker started, and {state.audit_gaps} gap marker
                      {state.audit_gaps === 1 ? "" : "s"} record the shortfall in the trail. For the
                      periods those markers cover, absence of a row is <em>not</em> evidence of
                      absence. Raise <code className="font-mono">audit_queue_capacity</code> or find
                      out what stalled the store writer.
                    </p>
                  </div>
                </div>
              </Panel>
            )}
            {state.audit_failed_total > 0 && (
              <Panel tone="warn">
                <div className="text-[12px] font-medium text-foreground">
                  {state.audit_failed_total} admin operations were refused because their audit row
                  could not be written.
                </div>
                <p className="mt-1 text-[11.5px] text-muted-foreground">
                  This is the fail-closed guarantee working, not a bug: no credential is issued
                  without a record of it being issued. But it means the store is unhealthy.
                </p>
              </Panel>
            )}

            <Section title="Diagnostics" icon={ScrollText}>
              <Facts
                rows={[
                  ["Format", state.log_format, state.log_format === "text" ? "set json where a collector reads it" : null],
                  ["Sinks", state.sinks.join(" + "), state.sinks.length === 1 ? "stdout only — the recommended deployment" : null],
                  ["Log file", state.log_file ?? "—", state.log_file ? `rotated ${state.log_file_rotation}; deleting old files is your job, not the broker's` : null],
                  ["Configured filter", state.configured_filter, null],
                  [
                    "In force now",
                    state.effective_filter,
                    state.override_active
                      ? `temporary — restores ${fmtUntil(state.override_expires_at)}`
                      : null,
                  ],
                  ["Metrics", state.metrics_path ?? "disabled", state.metrics_path ? "Prometheus text, internal listener, unauthenticated" : null],
                ]}
              />
            </Section>

            <Section title="Temporary verbosity" icon={Volume2}>
              <p className="text-[11.5px] text-muted-foreground">
                Raise the level for a bounded window without a restart. It restores itself when the
                window closes — a level switch with no deadline is a level switch that stays on.
                Changing it is recorded in the audit trail, because turning the lights down is
                itself a security-relevant act.
              </p>

              {state.override_active ? (
                <Panel tone="warn" className="mt-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="text-[12px] font-medium text-foreground">
                        <code className="font-mono">{state.effective_filter}</code>
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        restores {fmtUntil(state.override_expires_at)} (
                        {fmtTime(state.override_expires_at)})
                        {state.override_requested_by ? ` · set via ${state.override_requested_by}` : ""}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="btn-ghost"
                      disabled={busy}
                      onClick={() => void apply(true)}
                    >
                      Restore now
                    </button>
                  </div>
                </Panel>
              ) : (
                <div className="mt-3 flex flex-wrap items-end gap-2">
                  <label className="flex flex-col gap-1">
                    <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                      Filter
                    </span>
                    <select
                      className="input"
                      value={filter}
                      onChange={(e) => setFilter(e.target.value)}
                    >
                      {PRESETS.map((p) => (
                        <option key={p.filter} value={p.filter}>
                          {p.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="flex flex-col gap-1">
                    <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                      For
                    </span>
                    <select
                      className="input"
                      value={duration}
                      onChange={(e) => setDuration(Number(e.target.value))}
                    >
                      {DURATIONS.filter((d) => d.secs <= state.override_max_secs).map((d) => (
                        <option key={d.secs} value={d.secs}>
                          {d.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    type="button"
                    className="btn-primary"
                    disabled={busy}
                    onClick={() => void apply(false)}
                  >
                    Raise verbosity
                  </button>
                  <span className="text-[11px] text-muted-foreground">
                    ceiling {Math.round(state.override_max_secs / 60)} min
                  </span>
                </div>
              )}
            </Section>

            <Section title="Audit record" icon={Gauge}>
              <Facts
                rows={[
                  [
                    "Retention",
                    state.audit_retention_days === 0
                      ? "kept forever"
                      : `${state.audit_retention_days} days`,
                    state.audit_retention_days === 0
                      ? "the table is never pruned — the store's growth is unbounded"
                      : "older rows are pruned hourly; the log archive is the long tail",
                  ],
                  [
                    "Rows in window",
                    state.audit_rows.toLocaleString(),
                    state.audit_oldest_at
                      ? `oldest ${fmtTime(state.audit_oldest_at)}`
                      : "no history yet — the record starts when the first event happens",
                  ],
                  [
                    "Queue",
                    `${state.audit_queue_depth} / ${state.audit_queue_capacity}`,
                    "Tier-B events enqueued and not yet committed",
                  ],
                  [
                    "Subjects",
                    state.audit_subject_mode,
                    state.audit_subject_mode === "plain"
                      ? "stored as the IdP gave them"
                      : "pseudonymised — still correlatable, no longer naming people",
                  ],
                  [
                    "Rotations recorded",
                    state.audit_record_rotations ? "yes" : "no",
                    state.audit_record_rotations
                      ? "high volume; anomalous rotations are recorded either way"
                      : "anomalous rotations are still always recorded",
                  ],
                  [
                    "Exchange coalescing",
                    `${state.audit_coalesce_secs}s`,
                    "repeat token exchanges for one backend+session collapse to one row; refusals never do",
                  ],
                ]}
              />
            </Section>

            <Section title="Wiring it up" icon={Clipboard}>
              <p className="text-[11.5px] text-muted-foreground">
                These are the settings this broker would need, not settings this page can write. A
                console holding the admin key must not be able to redirect the audit stream, so
                sinks and retention are config plus a restart.
              </p>
              <div className="mt-3 grid gap-3 lg:grid-cols-2">
                <Snippet
                  title="Ship JSON to a collector"
                  hint="The recommended deployment: stdout only, the sidecar owns transport."
                  body={`BROKER_LOG_FORMAT=json\nBROKER_AUDIT_RETENTION_DAYS=90`}
                />
                <Snippet
                  title="No collector — write a file too"
                  hint="Rotation is the broker's; deletion is logrotate's."
                  body={`BROKER_LOG_FORMAT=json\nBROKER_LOG_FILE=/var/log/session-broker/broker.log\nBROKER_LOG_FILE_ROTATION=daily`}
                />
                <Snippet
                  title="Prometheus scrape"
                  hint="The INTERNAL listener, not the public one."
                  body={`- job_name: session-broker\n  static_configs:\n    - targets: ["127.0.0.1:8090"]\n  metrics_path: /metrics`}
                />
                <Snippet
                  title="Split audit from diagnostics on the way out"
                  hint="Vector: long retention belongs in the archive, not in the broker's file."
                  body={`[transforms.split]\ntype = "route"\ninputs = ["broker"]\nroute.audit = '.target == "broker::audit"'`}
                />
              </div>
              <p className="mt-3 text-[11.5px] text-muted-foreground">
                Alert on <code className="font-mono">broker_audit_dropped_total</code> increasing:
                that is the one metric here whose nonzero value means the security record is
                incomplete.
              </p>
            </Section>
          </>
        )}
      </div>
    </div>
  );
}

function Section({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: typeof Activity;
  children: React.ReactNode;
}) {
  return (
    <Panel>
      <div className="mb-2 flex items-center gap-2">
        <Icon className="h-3.5 w-3.5 text-primary" />
        <h2 className="text-[12px] font-semibold text-foreground">{title}</h2>
      </div>
      {children}
    </Panel>
  );
}

/** A label, a value, and — where it earns its place — what the value means.
 *  A bare "text" next to "Format" tells an operator nothing about whether that
 *  is the right answer for their deployment. */
function Facts({ rows }: { rows: [string, string, string | null][] }) {
  return (
    <dl className="grid gap-x-4 gap-y-1.5 sm:grid-cols-[auto_1fr]">
      {rows.map(([label, value, note]) => (
        <div key={label} className="contents">
          <dt className="text-[11px] text-muted-foreground sm:text-right">{label}</dt>
          <dd className="text-[11.5px] text-foreground">
            <span className="font-mono">{value}</span>
            {note && <span className="ml-2 text-[11px] text-muted-foreground">— {note}</span>}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Snippet({ title, hint, body }: { title: string; hint: string; body: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-md border border-outline-subtle bg-surface-app p-2.5">
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <div className="text-[11.5px] font-medium text-foreground">{title}</div>
          <div className="text-[11px] text-muted-foreground">{hint}</div>
        </div>
        <button
          type="button"
          className="btn-ghost shrink-0"
          onClick={() => {
            void navigator.clipboard.writeText(body);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Clipboard className="h-3.5 w-3.5" />}
        </button>
      </div>
      <pre className="mt-2 overflow-x-auto whitespace-pre text-[11px] leading-relaxed text-muted-foreground">
        {body}
      </pre>
    </div>
  );
}
