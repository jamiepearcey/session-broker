// Backend API keys — the console's reason to exist.
//
// Two affordances carry real weight here, and both are shaped by the fact that
// a key is a credential rather than a record:
//
//   - **Issuing shows the secret once.** The panel that appears after creation
//     is the only chance to copy it, and it says so plainly rather than letting
//     someone discover it by coming back later.
//   - **Revoking is a typed confirmation.** Revocation takes effect on the next
//     request with no undo, and a misclick on the wrong row silently breaks a
//     production service. Re-typing the key's name is cheap for the person who
//     means it and a real stop for the person who does not.

import { useCallback, useEffect, useState } from "react";
import { KeyRound, Plus, RefreshCw, ShieldOff } from "lucide-react";

import { StatusBadge } from "@/components/StatusBadge";
import { adminApi, fmtTime, type ApiKey, type IssuedKey } from "@/lib/api";
import { ErrorNote, Panel, Toolbar } from "@/components/chrome";

export function Keys() {
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [issued, setIssued] = useState<IssuedKey | null>(null);
  const [newName, setNewName] = useState("");
  const [confirming, setConfirming] = useState<ApiKey | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setKeys(await adminApi.keys());
      setError(null);
    } catch (e) {
      setError(e as Error);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const create = async () => {
    if (!newName.trim()) return;
    setBusy(true);
    try {
      setIssued(await adminApi.createKey(newName.trim()));
      setNewName("");
      await load();
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  const revoke = async () => {
    if (!confirming) return;
    setBusy(true);
    try {
      await adminApi.revokeKey(confirming.key_id);
      setConfirming(null);
      setConfirmText("");
      await load();
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  const live = keys?.filter((k) => k.live).length ?? 0;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Toolbar
        title="Backend API keys"
        blurb="Credentials that let a service exchange a session for an upstream token. Each one is half of the internal lane's dual authentication — a key alone can never name a user."
        icon={KeyRound}
      >
        <StatusBadge variant="neutral">{live} live</StatusBadge>
        {keys && keys.length > live && (
          <StatusBadge variant="neutral">{keys.length - live} revoked</StatusBadge>
        )}
        <button type="button" onClick={() => void load()} className="btn-ghost">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </Toolbar>

      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
        {error && <ErrorNote error={error} />}

        {/* The one-shot secret. Deliberately loud, and deliberately not
            dismissible by accident — closing it is the only way past. */}
        {issued && (
          <Panel tone="warn">
            <div className="mb-2 text-[12px] font-medium text-foreground">
              Key issued for “{issued.name}”. Copy it now.
            </div>
            <p className="mb-2 text-[11.5px] text-warn-foreground/85">
              Only a hash is stored. This is the one time the broker can show you the secret —
              there is no endpoint that reveals it later, which is what makes a readable admin
              database survivable. If you lose it, issue another and revoke this one.
            </p>
            <code className="block break-all rounded border border-outline-subtle bg-surface-input px-2 py-1.5 font-mono text-[11.5px] text-foreground">
              {issued.secret}
            </code>
            <div className="mt-2 flex gap-2">
              <button
                type="button"
                className="btn-ghost"
                onClick={() => void navigator.clipboard?.writeText(issued.secret)}
              >
                Copy
              </button>
              <button type="button" className="btn-ghost" onClick={() => setIssued(null)}>
                I have stored it
              </button>
            </div>
          </Panel>
        )}

        <Panel>
          <div className="mb-2 text-[11px] font-medium text-foreground">Issue a key</div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="input flex-1"
              placeholder="Which service is this for? e.g. qp-omsd"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void create()}
            />
            <button
              type="button"
              disabled={busy || !newName.trim()}
              onClick={() => void create()}
              className="btn-primary"
            >
              <Plus className="h-3.5 w-3.5" /> Issue
            </button>
          </div>
          <p className="mt-1.5 text-[11px] text-muted-foreground">
            Name it after the service that will hold it. Five keys called “key” answer nothing
            during an incident.
          </p>
        </Panel>

        {keys === null && !error && <p className="text-[12px] text-muted-foreground">Loading…</p>}

        {keys?.length === 0 && (
          <p className="text-[12px] text-muted-foreground">
            No keys issued. Services will fall back to the bootstrap key from configuration, which
            cannot be revoked without a deploy.
          </p>
        )}

        {keys && keys.length > 0 && (
          <table className="w-full text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b border-outline-subtle">
                <th className="px-2 py-1.5 text-left">Name</th>
                <th className="px-2 py-1.5 text-left">Key id</th>
                <th className="px-2 py-1.5 text-left">Created</th>
                <th className="px-2 py-1.5 text-left">Last used</th>
                <th className="px-2 py-1.5 text-left">State</th>
                <th className="px-2 py-1.5" />
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.key_id} className="border-b border-outline-subtle/60">
                  <td className="px-2 py-1.5 text-foreground">{k.name}</td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">{k.key_id}</td>
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {fmtTime(k.created_at)}
                  </td>
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {/* Never-used is worth seeing: it usually means a service was
                        given a key and never actually switched to it. */}
                    {k.last_used_at ? fmtTime(k.last_used_at) : "never"}
                  </td>
                  <td className="px-2 py-1.5">
                    {k.live ? (
                      <StatusBadge variant="ok">live</StatusBadge>
                    ) : (
                      <StatusBadge variant="neutral">revoked {fmtTime(k.revoked_at)}</StatusBadge>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-right">
                    {k.live && (
                      <button
                        type="button"
                        className="btn-danger"
                        onClick={() => {
                          setConfirming(k);
                          setConfirmText("");
                        }}
                      >
                        <ShieldOff className="h-3.5 w-3.5" /> Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Typed confirmation. The cost of a misclick here is a production
            service losing its credential on the next request, with no undo. */}
        {confirming && (
          <Panel tone="danger">
            <div className="mb-1 text-[12px] font-medium text-foreground">
              Revoke “{confirming.name}”?
            </div>
            <p className="mb-2 text-[11.5px] text-warn-foreground/85">
              This takes effect on the very next request — there is no cache to wait out and no
              undo. Any service still using this key will start getting 401s immediately. Type{" "}
              <span className="font-mono text-foreground">{confirming.name}</span> to confirm.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <input
                className="input flex-1"
                value={confirmText}
                autoFocus
                onChange={(e) => setConfirmText(e.target.value)}
              />
              <button
                type="button"
                className="btn-danger"
                disabled={busy || confirmText !== confirming.name}
                onClick={() => void revoke()}
              >
                Revoke
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
