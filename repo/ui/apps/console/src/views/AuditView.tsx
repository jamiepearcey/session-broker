// The audit trail.
//
// A separate view from Observability on purpose: that one is about the plumbing,
// this one is the record. They are read at different moments by people asking
// different questions, and folding a dense scrollable table into a settings page
// makes both worse.
//
// ## What this view is careful about
//
// An empty result must never read as "nothing happened". The window is bounded
// (90 days by default) and the queue can drop under pressure, so the header
// always says where history starts and whether it has holes. A trail that
// silently omits its own limits is worse than no trail, because it invites a
// conclusion it cannot support.

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Download, RefreshCw, ScrollText, Search } from "lucide-react";

import { StatusBadge, type StateVariant } from "@/components/StatusBadge";
import { ErrorNote, Panel, Toolbar } from "@/components/chrome";
import {
  adminApi,
  downloadAuditNdjson,
  fmtTime,
  type AuditFilters,
  type AuditPage,
  type AuditRow,
} from "@/lib/api";

/** Action groups an operator thinks in, mapped to the prefix the API filters on. */
const SCOPES = [
  { label: "Everything", prefix: "" },
  { label: "Credentials", prefix: "key." },
  { label: "Sessions", prefix: "session." },
  { label: "Logins", prefix: "login." },
  { label: "Token exchange", prefix: "token." },
  { label: "Upstream custody", prefix: "custody." },
  { label: "Observability", prefix: "logging." },
];

const RANGES = [
  { label: "Last hour", secs: 3600 },
  { label: "Last 24 hours", secs: 86_400 },
  { label: "Last 7 days", secs: 604_800 },
  { label: "Last 30 days", secs: 2_592_000 },
  { label: "Everything kept", secs: 0 },
];

/** Colour carries meaning here, so it is assigned by what the row MEANS, not by
 *  outcome alone: a recorded anomaly is a success in the "we wrote it down"
 *  sense and still the row you most want to see. */
function tone(row: AuditRow): StateVariant {
  if (row.action === "audit.gap") return "error";
  if (row.action === "session.anomaly") return "warn";
  if (row.outcome === "failure") return "warn";
  if (row.action.startsWith("key.") || row.action === "session.revoked") return "ok";
  return "neutral";
}

export function AuditView() {
  const [page, setPage] = useState<AuditPage | null>(null);
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [error, setError] = useState<Error | null>(null);
  const [scope, setScope] = useState("");
  const [range, setRange] = useState(86_400);
  const [subject, setSubject] = useState("");
  const [outcome, setOutcome] = useState("");
  const [loading, setLoading] = useState(false);

  const filters = useCallback(
    (cursor?: number): AuditFilters => ({
      action: scope || undefined,
      subject: subject.trim() || undefined,
      outcome: outcome || undefined,
      since: range ? Math.floor(Date.now() / 1000) - range : undefined,
      before_seq: cursor,
      limit: 200,
    }),
    [scope, subject, outcome, range],
  );

  const load = useCallback(
    async (cursor?: number) => {
      setLoading(true);
      try {
        const result = await adminApi.audit(filters(cursor));
        // Appending on a cursor load, replacing otherwise: "load more" must not
        // discard what the operator is already reading.
        setRows((prev) => (cursor ? [...prev, ...result.rows] : result.rows));
        setPage(result);
        setError(null);
      } catch (e) {
        setError(e as Error);
      } finally {
        setLoading(false);
      }
    },
    [filters],
  );

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Toolbar
        title="Audit trail"
        blurb="Who did what, from the broker's own store — not from the log pipeline, so it answers even when a collector is misconfigured. High-frequency checks (edge authorisation, session refresh) are deliberately absent: they change nothing, so they are metrics, not history."
        icon={ScrollText}
      >
        {page && (
          <StatusBadge variant="neutral">
            {page.rows_total.toLocaleString()} rows · {page.retention_days || "∞"} day window
          </StatusBadge>
        )}
        {page && page.gaps > 0 && <StatusBadge variant="error">{page.gaps} gaps</StatusBadge>}
        <button
          type="button"
          className="btn-ghost"
          onClick={() => void downloadAuditNdjson(filters()).catch((e) => setError(e as Error))}
        >
          <Download className="h-3.5 w-3.5" /> NDJSON
        </button>
        <button type="button" onClick={() => void load()} className="btn-ghost">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </Toolbar>

      <div className="flex flex-wrap items-end gap-2 border-b border-outline-subtle px-4 py-2.5">
        <Field label="Scope">
          <select className="input" value={scope} onChange={(e) => setScope(e.target.value)}>
            {SCOPES.map((s) => (
              <option key={s.label} value={s.prefix}>
                {s.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Range">
          <select
            className="input"
            value={range}
            onChange={(e) => setRange(Number(e.target.value))}
          >
            {RANGES.map((r) => (
              <option key={r.label} value={r.secs}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Outcome">
          <select className="input" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="">Any</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
          </select>
        </Field>
        <Field label="Subject">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
            <input
              className="input pl-7"
              placeholder="exact sub"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
            />
          </div>
        </Field>
      </div>

      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
        {error && <ErrorNote error={error} />}

        {page && page.rows_total === 0 && (
          <Panel>
            <div className="text-[12px] font-medium text-foreground">No history yet.</div>
            <p className="mt-1 text-[11.5px] text-muted-foreground">
              The record starts at the first audited event after this broker was upgraded — there is
              no backfill. An empty trail here means nothing has happened <em>since then</em>, not
              that nothing ever happened.
            </p>
          </Panel>
        )}

        {page && page.rows_total > 0 && rows.length === 0 && (
          <p className="text-[12px] text-muted-foreground">
            Nothing matches these filters. {page.oldest_at ? `History goes back to ${fmtTime(page.oldest_at)}.` : ""}
          </p>
        )}

        {page && page.gaps > 0 && (
          <Panel tone="danger">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div>
                <div className="text-[12px] font-medium text-foreground">
                  This window contains {page.gaps} gap marker{page.gaps === 1 ? "" : "s"}.
                </div>
                <p className="mt-1 text-[11.5px] text-muted-foreground">
                  Events were dropped at the queue bound. For the periods those{" "}
                  <code className="font-mono">audit.gap</code> rows cover, the absence of a row is
                  not evidence that nothing happened.
                </p>
              </div>
            </div>
          </Panel>
        )}

        {rows.length > 0 && (
          <table className="w-full text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b border-outline-subtle">
                <th className="px-2 py-1.5 text-left">When</th>
                <th className="px-2 py-1.5 text-left">Action</th>
                <th className="px-2 py-1.5 text-left">Actor</th>
                <th className="px-2 py-1.5 text-left">Subject</th>
                <th className="px-2 py-1.5 text-left">Target</th>
                <th className="px-2 py-1.5 text-left">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.seq} className="border-b border-outline-subtle/60 align-top">
                  <td className="whitespace-nowrap px-2 py-1.5 tabular-nums text-muted-foreground">
                    {fmtTime(row.at)}
                  </td>
                  <td className="px-2 py-1.5">
                    <StatusBadge variant={tone(row)}>{row.action}</StatusBadge>
                    {row.outcome === "failure" && row.reason && (
                      <div className="mt-0.5 font-mono text-[10.5px] text-muted-foreground">
                        {row.reason}
                      </div>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-muted-foreground">
                    {row.actor_kind}
                    {row.actor_id && (
                      <div className="font-mono text-[10.5px]">{row.actor_id}</div>
                    )}
                  </td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">
                    {row.subject ?? "—"}
                  </td>
                  {/* One column for "which thing", because a row only ever names
                      one: a key, a session, or a grant. Three sparse columns
                      would be three columns of dashes. */}
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">
                    {row.key_id ?? row.sid ?? row.custody_id ?? "—"}
                  </td>
                  <td className="px-2 py-1.5 text-muted-foreground">
                    {row.detail ? (
                      <code className="text-[10.5px]">{JSON.stringify(row.detail)}</code>
                    ) : (
                      "—"
                    )}
                    {row.client_ip_prefix && (
                      <div className="text-[10.5px]">from {row.client_ip_prefix}</div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {page?.next_before_seq && (
          <button
            type="button"
            className="btn-ghost"
            disabled={loading}
            onClick={() => void load(page.next_before_seq ?? undefined)}
          >
            Load older
          </button>
        )}
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}
