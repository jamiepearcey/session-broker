// User grants — which tenant, roles and indexes a signed-in person gets in a
// token (`docs/design/token-issuer-scope.md`).
//
// The broker authenticates people through the identity provider; what they may
// do in a consumer comes from this table, keyed by the provider's `sub`. There is
// no mapping from provider groups. A user with no live grant gets no token.
//
// Revoking is typed, as on the other credential views: the `sub` is what is
// typed, because a grant has no other name.

import { useCallback, useEffect, useState } from "react";
import { Plus, RefreshCw, ShieldOff, UserCheck } from "lucide-react";

import { StatusBadge } from "@/components/StatusBadge";
import { adminApi, fmtTime, type Tenant, type UserGrant } from "@/lib/api";
import { ErrorNote, Panel, Toolbar } from "@/components/chrome";
import { words } from "@/lib/utils";

export function UserGrants() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenant, setTenant] = useState("");
  const [grants, setGrants] = useState<UserGrant[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [confirming, setConfirming] = useState<UserGrant | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);

  const [sub, setSub] = useState("");
  const [newTenant, setNewTenant] = useState("default");
  const [roles, setRoles] = useState("");
  const [indexes, setIndexes] = useState("*");

  const load = useCallback(async () => {
    try {
      const [rows, ts] = await Promise.all([
        adminApi.userGrants(tenant || undefined),
        adminApi.tenants(),
      ]);
      setGrants(rows);
      setTenants(ts);
      setError(null);
    } catch (e) {
      setError(e as Error);
    }
  }, [tenant]);

  useEffect(() => {
    void load();
  }, [load]);

  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  const create = () =>
    act(async () => {
      await adminApi.createUserGrant({
        sub: sub.trim(),
        tenant: newTenant.trim() || "default",
        roles: words(roles),
        ...(words(indexes).length > 0 ? { indexes: words(indexes) } : {}),
      });
      setSub("");
      setRoles("");
    });

  const revoke = () =>
    act(async () => {
      if (!confirming) return;
      await adminApi.revokeUserGrant(confirming.sub, confirming.tenant);
      setConfirming(null);
      setConfirmText("");
    });

  const live = grants?.filter((g) => g.live).length ?? 0;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Toolbar
        title="User grants"
        blurb="What a signed-in person gets when their session is exchanged for a token: one tenant, a set of roles and the indexes they reach. Keyed by the identity provider's subject; no grant means no token."
        icon={UserCheck}
      >
        <StatusBadge variant="neutral">{live} live</StatusBadge>
        {grants && grants.length > live && (
          <StatusBadge variant="neutral">{grants.length - live} revoked</StatusBadge>
        )}
        <select
          className="input"
          aria-label="Tenant filter"
          value={tenant}
          onChange={(e) => setTenant(e.target.value)}
        >
          <option value="">All tenants</option>
          {tenants.map((t) => (
            <option key={t.tenant} value={t.tenant}>
              {t.tenant}
              {t.live ? "" : " (disabled)"}
            </option>
          ))}
        </select>
        <button type="button" onClick={() => void load()} className="btn-ghost">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </Toolbar>

      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
        {error && <ErrorNote error={error} />}

        {/* Up here, not under the table: a long list would put it off-screen. */}
        {confirming && (
          <Panel tone="danger">
            <div className="mb-1 text-[12px] font-medium text-foreground">
              Revoke the grant for “{confirming.sub}” in {confirming.tenant}?
            </div>
            <p className="mb-2 text-[11.5px] text-warn-foreground/85">
              The user gets no new tokens for this tenant from the next request. Tokens already
              issued run out their lifetime. Type{" "}
              <span className="font-mono text-foreground">{confirming.sub}</span> to confirm.
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
                disabled={busy || confirmText !== confirming.sub}
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

        <Panel>
          <div className="mb-2 text-[11px] font-medium text-foreground">Grant a user</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-4">
            <input
              className="input"
              placeholder="Subject (sub) from the identity provider"
              aria-label="Subject"
              value={sub}
              onChange={(e) => setSub(e.target.value)}
            />
            <input
              className="input"
              list="grant-tenant-options"
              placeholder="Tenant"
              aria-label="Tenant"
              value={newTenant}
              onChange={(e) => setNewTenant(e.target.value)}
            />
            <input
              className="input"
              placeholder="Roles, e.g. viewer admin"
              aria-label="Roles"
              value={roles}
              onChange={(e) => setRoles(e.target.value)}
            />
            <input
              className="input"
              placeholder="Indexes (default *)"
              aria-label="Indexes"
              value={indexes}
              onChange={(e) => setIndexes(e.target.value)}
            />
          </div>
          <datalist id="grant-tenant-options">
            {tenants.map((t) => (
              <option key={t.tenant} value={t.tenant} />
            ))}
          </datalist>
          <div className="mt-2 flex items-center gap-2">
            <button
              type="button"
              disabled={busy || !sub.trim() || words(roles).length === 0}
              onClick={() => void create()}
              className="btn-primary"
            >
              <Plus className="h-3.5 w-3.5" /> Grant
            </button>
            <p className="text-[11px] text-muted-foreground">
              Roles and indexes are separated by spaces or commas. A user can hold one grant per
              tenant.
            </p>
          </div>
        </Panel>

        {grants === null && !error && <p className="text-[12px] text-muted-foreground">Loading…</p>}

        {grants?.length === 0 && (
          <p className="text-[12px] text-muted-foreground">
            No grants{tenant ? ` in ${tenant}` : ""}. Signed-in users cannot obtain a token until
            they have one.
          </p>
        )}

        {grants && grants.length > 0 && (
          <table className="w-full text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b border-outline-subtle">
                <th className="px-2 py-1.5 text-left">Subject</th>
                <th className="px-2 py-1.5 text-left">Tenant</th>
                <th className="px-2 py-1.5 text-left">Roles</th>
                <th className="px-2 py-1.5 text-left">Indexes</th>
                <th className="px-2 py-1.5 text-left">Created</th>
                <th className="px-2 py-1.5 text-left">State</th>
                <th className="px-2 py-1.5" />
              </tr>
            </thead>
            <tbody>
              {grants.map((g) => (
                <tr key={`${g.tenant}/${g.sub}`} className="border-b border-outline-subtle/60">
                  <td className="px-2 py-1.5 font-mono text-foreground">{g.sub}</td>
                  <td className="px-2 py-1.5 text-muted-foreground">{g.tenant}</td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">{g.roles.join(" ")}</td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">{g.indexes.join(" ")}</td>
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {fmtTime(g.created_at)}
                  </td>
                  <td className="px-2 py-1.5">
                    {g.live ? (
                      <StatusBadge variant="ok">live</StatusBadge>
                    ) : (
                      <StatusBadge variant="neutral">revoked {fmtTime(g.revoked_at)}</StatusBadge>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-right">
                    {g.live && (
                      <button
                        type="button"
                        className="btn-danger"
                        onClick={() => {
                          setConfirming(g);
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

      </div>
    </div>
  );
}
