// Live sessions, and the ability to cut one off.
//
// What this deliberately does NOT show: token hashes, generations, or anything
// else from the credential path. The broker's own admin lane reads sessions
// from the store rather than the in-memory map for the same reason — an
// operator surface has no business near credential material even in hashed
// form. What an operator needs is who is signed in, until when, and a way to
// end it.

import { useCallback, useEffect, useState } from "react";
import { RefreshCw, Users, UserX } from "lucide-react";

import { StatusBadge } from "@/components/StatusBadge";
import { ErrorNote, Panel, Toolbar } from "@/components/chrome";
import { adminApi, fmtTime, fmtUntil, type AdminSession } from "@/lib/api";

export function Sessions() {
  const [rows, setRows] = useState<AdminSession[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [confirming, setConfirming] = useState<AdminSession | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setRows(await adminApi.sessions());
      setError(null);
    } catch (e) {
      setError(e as Error);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const revoke = async () => {
    if (!confirming) return;
    setBusy(true);
    try {
      await adminApi.revokeSession(confirming.sid);
      setConfirming(null);
      await load();
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Toolbar
        title="Sessions"
        blurb="Everyone currently signed in. Revoking kills every generation of a session at once, in memory and on disk — the user is signed out of every tab immediately."
        icon={Users}
      >
        {rows && <StatusBadge variant="neutral">{rows.length} live</StatusBadge>}
        <button type="button" onClick={() => void load()} className="btn-ghost">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </Toolbar>

      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
        {error && <ErrorNote error={error} />}
        {rows === null && !error && <p className="text-[12px] text-muted-foreground">Loading…</p>}
        {rows?.length === 0 && (
          <p className="text-[12px] text-muted-foreground">Nobody is signed in.</p>
        )}

        {rows && rows.length > 0 && (
          <table className="w-full text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b border-outline-subtle">
                <th className="px-2 py-1.5 text-left">Subject</th>
                <th className="px-2 py-1.5 text-left">Session</th>
                <th className="px-2 py-1.5 text-left">Gen</th>
                <th className="px-2 py-1.5 text-left">Idle expiry</th>
                <th className="px-2 py-1.5 text-left">Hard ceiling</th>
                <th className="px-2 py-1.5" />
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.sid} className="border-b border-outline-subtle/60">
                  <td className="px-2 py-1.5 text-foreground">{s.sub}</td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">
                    {s.sid.slice(0, 12)}…
                  </td>
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {s.current_gen}
                  </td>
                  {/* Relative for idle (it slides, so "when" matters less than
                      "how long left") and absolute for the ceiling (it never
                      moves, so it is a date an operator can plan around). */}
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {fmtUntil(s.idle_exp)}
                  </td>
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {fmtTime(s.absolute_exp)}
                  </td>
                  <td className="px-2 py-1.5 text-right">
                    <button
                      type="button"
                      className="btn-danger"
                      onClick={() => setConfirming(s)}
                    >
                      <UserX className="h-3.5 w-3.5" /> Sign out
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {confirming && (
          <Panel tone="danger">
            <div className="mb-1 text-[12px] font-medium text-foreground">
              Sign out {confirming.sub}?
            </div>
            <p className="mb-2 text-[11.5px] text-warn-foreground/85">
              Every generation of this session dies at once, so all of that user&apos;s tabs are
              signed out immediately. They can sign back in — this is not a suspension.
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                className="btn-danger"
                disabled={busy}
                onClick={() => void revoke()}
              >
                Sign them out
              </button>
              <button type="button" className="btn-ghost" onClick={() => setConfirming(null)}>
                Cancel
              </button>
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}
