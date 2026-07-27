// Upstream grant health.
//
// The distinction this view exists to make visible: a session can be perfectly
// valid while the upstream token behind it is degraded or dead. Session auth
// does not depend on upstream liveness — only token exchange does — so without
// this panel the symptom of a failing keepalive is "some calls started failing"
// with nothing anywhere saying why.

import { useCallback, useEffect, useState } from "react";
import { HeartPulse, RefreshCw } from "lucide-react";

import { StatusBadge, type StateVariant } from "@/components/StatusBadge";
import { ErrorNote, Toolbar } from "@/components/chrome";
import { adminApi, fmtUntil, type Custody } from "@/lib/api";

const STATUS: Record<string, StateVariant> = {
  ok: "ok",
  degraded: "warn",
  dead: "error",
};

export function CustodyView() {
  const [rows, setRows] = useState<Custody[] | null>(null);
  const [error, setError] = useState<Error | null>(null);

  const load = useCallback(async () => {
    try {
      setRows(await adminApi.custody());
      setError(null);
    } catch (e) {
      setError(e as Error);
    }
  }, []);

  useEffect(() => {
    void load();
    // Custody state is the one thing here that changes on its own, on the
    // keepalive worker's schedule. A manual-refresh-only view of a background
    // process is how a degraded grant goes unnoticed.
    const timer = setInterval(() => void load(), 15_000);
    return () => clearInterval(timer);
  }, [load]);

  const degraded = rows?.filter((r) => r.status !== "ok").length ?? 0;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Toolbar
        title="Upstream custody"
        blurb="The grants the broker holds on users' behalf, and when it will next renew them. A session stays valid even when its grant is unhealthy — only calls to upstream APIs fail — so this is the only place that symptom is visible."
        icon={HeartPulse}
      >
        {rows && <StatusBadge variant="neutral">{rows.length} tracked</StatusBadge>}
        {degraded > 0 && <StatusBadge variant="warn">{degraded} not healthy</StatusBadge>}
        <button type="button" onClick={() => void load()} className="btn-ghost">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </Toolbar>

      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
        {error && <ErrorNote error={error} />}
        {rows === null && !error && <p className="text-[12px] text-muted-foreground">Loading…</p>}
        {rows?.length === 0 && (
          <p className="text-[12px] text-muted-foreground">
            No grants are being tracked. Dead ones are not listed — their refresh token will never
            work again, so the worker stops scheduling them.
          </p>
        )}

        {rows && rows.length > 0 && (
          <table className="w-full text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b border-outline-subtle">
                <th className="px-2 py-1.5 text-left">Custody</th>
                <th className="px-2 py-1.5 text-left">Health</th>
                <th className="px-2 py-1.5 text-left">Token expires</th>
                <th className="px-2 py-1.5 text-left">Next renewal</th>
                <th className="px-2 py-1.5 text-left">Failures</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.custody_id} className="border-b border-outline-subtle/60">
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">
                    {c.custody_id.slice(0, 12)}…
                  </td>
                  <td className="px-2 py-1.5">
                    <StatusBadge variant={STATUS[c.status] ?? "neutral"}>{c.status}</StatusBadge>
                  </td>
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {fmtUntil(c.access_exp)}
                  </td>
                  {/* Renewal should always be comfortably BEFORE expiry — the
                      worker aims at 0.6 of the lifetime, leaving two retry
                      budgets. Renewal after expiry means it is behind. */}
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {fmtUntil(c.next_refresh)}
                  </td>
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {c.fail_count > 0 ? (
                      <StatusBadge variant="warn">{c.fail_count} consecutive</StatusBadge>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
