// Machine principals — the credentials a service holds to ask the broker for a
// signed token (`docs/design/token-issuer-scope.md`).
//
// Same two affordances as `Keys.tsx`, for the same reason: a principal secret is
// a credential, not a record.
//
//   - **A secret is shown once.** Creating a principal and adding a secret both
//     end in the same one-shot panel.
//   - **Revoking is typed.** Revoking a principal stops new tokens at once, and
//     a misclick on the wrong row breaks a service. Revoking one secret is the
//     same, with the secret id as the word to type.
//
// Secrets do not expire unless the operator says so, and adding one leaves the
// older ones working until they are revoked (or `expire_old` is given), so
// rotating a service's credential never has to be a cut-over.

import { useCallback, useEffect, useState } from "react";
import { KeyRound, Plus, RefreshCw, ShieldOff } from "lucide-react";

import { StatusBadge } from "@/components/StatusBadge";
import {
  adminApi,
  fmtTime,
  type IssuedSecret,
  type NewPrincipal,
  type Principal,
  type PrincipalDetail,
  type Tenant,
} from "@/lib/api";
import { ErrorNote, Panel, Toolbar } from "@/components/chrome";
import { hoursToSecs, words } from "@/lib/utils";

const KINDS: Principal["kind"][] = ["ingest", "node", "replica", "reader", "admin"];

type Issued = { heading: string; secret: IssuedSecret };
type Confirm = { heading: string; word: string; run: () => Promise<void> };

export function Principals() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenant, setTenant] = useState("");
  const [principals, setPrincipals] = useState<Principal[] | null>(null);
  const [selected, setSelected] = useState<PrincipalDetail | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [issued, setIssued] = useState<Issued | null>(null);
  const [confirming, setConfirming] = useState<Confirm | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);

  // Create form.
  const [name, setName] = useState("");
  const [newTenant, setNewTenant] = useState("default");
  const [kind, setKind] = useState<Principal["kind"]>("ingest");
  const [scopes, setScopes] = useState("");
  const [indexes, setIndexes] = useState("*");
  const [audience, setAudience] = useState("");
  const [maxHours, setMaxHours] = useState("");
  const [expiresHours, setExpiresHours] = useState("");

  // Add-secret form.
  const [secretExpiresHours, setSecretExpiresHours] = useState("");
  const [expireOldHours, setExpireOldHours] = useState("");

  const load = useCallback(async () => {
    try {
      const [rows, ts] = await Promise.all([
        adminApi.principals(tenant || undefined),
        adminApi.tenants(),
      ]);
      setPrincipals(rows);
      setTenants(ts);
      setError(null);
    } catch (e) {
      setError(e as Error);
    }
  }, [tenant]);

  useEffect(() => {
    void load();
  }, [load]);

  const open = async (principalId: string) => {
    try {
      setSelected(await adminApi.principal(principalId));
      setError(null);
    } catch (e) {
      setError(e as Error);
    }
  };

  // Runs a mutation with the shared busy/error handling, then reloads.
  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
      setError(null);
      await load();
    } catch (e) {
      setError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  const maxSecs = hoursToSecs(maxHours);
  const expiresSecs = hoursToSecs(expiresHours);
  const formOk =
    name.trim() !== "" &&
    audience.trim() !== "" &&
    words(scopes).length > 0 &&
    maxSecs !== null &&
    expiresSecs !== null;

  const create = () =>
    act(async () => {
      if (maxSecs === null || expiresSecs === null) return;
      const body: NewPrincipal = {
        name: name.trim(),
        tenant: newTenant.trim() || "default",
        kind,
        scopes: words(scopes),
        audience: audience.trim(),
        ...(words(indexes).length > 0 ? { indexes: words(indexes) } : {}),
        ...(maxSecs !== undefined ? { max_ttl_secs: maxSecs } : {}),
        ...(expiresSecs !== undefined ? { expires_in_secs: expiresSecs } : {}),
      };
      const { secret, ...created } = await adminApi.createPrincipal(body);
      setIssued({ heading: `Principal “${created.name}” created (${created.principal_id}).`, secret });
      setName("");
      setScopes("");
    });

  const secretExpiry = hoursToSecs(secretExpiresHours);
  const oldExpiry = hoursToSecs(expireOldHours);

  const addSecret = (p: PrincipalDetail) =>
    act(async () => {
      if (secretExpiry === null || oldExpiry === null) return;
      const added = await adminApi.addPrincipalSecret(p.principal_id, {
        ...(secretExpiry !== undefined ? { expires_in_secs: secretExpiry } : {}),
        ...(oldExpiry !== undefined ? { expire_old_in_secs: oldExpiry } : {}),
      });
      setIssued({ heading: `Secret added to “${p.name}”.`, secret: added });
      setSecretExpiresHours("");
      setExpireOldHours("");
      setSelected(await adminApi.principal(p.principal_id));
    });

  const live = principals?.filter((p) => p.live).length ?? 0;
  const audiences = [...new Set(principals?.map((p) => p.audience) ?? [])];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Toolbar
        title="Principals"
        blurb="Machine identities. A service posts its principal id and secret to the broker and gets back a short-lived signed token for one audience; the tenant comes from the principal, never from the request."
        icon={KeyRound}
      >
        <StatusBadge variant="neutral">{live} live</StatusBadge>
        {principals && principals.length > live && (
          <StatusBadge variant="neutral">{principals.length - live} revoked</StatusBadge>
        )}
        <select
          className="input"
          aria-label="Tenant filter"
          value={tenant}
          onChange={(e) => {
            setTenant(e.target.value);
            setSelected(null);
          }}
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

        {issued && (
          <Panel tone="warn">
            <div className="mb-2 text-[12px] font-medium text-foreground">
              {issued.heading} Copy the secret now.
            </div>
            <p className="mb-2 text-[11.5px] text-warn-foreground/85">
              Only a hash is stored, so this is the one time the broker can show the secret. If it
              is lost, add another secret and revoke this one.
            </p>
            <code className="block break-all rounded border border-outline-subtle bg-surface-input px-2 py-1.5 font-mono text-[11.5px] text-foreground">
              {issued.secret.secret}
            </code>
            <div className="mt-1.5 text-[11px] text-warn-foreground/85">
              Secret id <span className="font-mono">{issued.secret.secret_id}</span> ·{" "}
              {issued.secret.expires_at
                ? `stops working ${fmtTime(issued.secret.expires_at)}`
                : "does not expire"}
            </div>
            <div className="mt-2 flex gap-2">
              <button
                type="button"
                className="btn-ghost"
                onClick={() => void navigator.clipboard?.writeText(issued.secret.secret)}
              >
                Copy
              </button>
              <button type="button" className="btn-ghost" onClick={() => setIssued(null)}>
                I have stored it
              </button>
            </div>
          </Panel>
        )}

        {/* Up here, not under the table: a long list would put it off-screen. */}
        {confirming && (
          <Panel tone="danger">
            <div className="mb-1 text-[12px] font-medium text-foreground">{confirming.heading}</div>
            <p className="mb-2 text-[11.5px] text-warn-foreground/85">
              The broker stops issuing tokens for it on the next request, with no undo. Tokens
              already issued run out their lifetime. Type{" "}
              <span className="font-mono text-foreground">{confirming.word}</span> to confirm.
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
                disabled={busy || confirmText !== confirming.word}
                onClick={() => {
                  const run = confirming.run;
                  setConfirming(null);
                  setConfirmText("");
                  void act(run);
                }}
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
          <div className="mb-2 text-[11px] font-medium text-foreground">Create a principal</div>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
            <input
              className="input"
              placeholder="Name, e.g. agent-eu-1"
              aria-label="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <input
              className="input"
              list="tenant-options"
              placeholder="Tenant"
              aria-label="Tenant"
              value={newTenant}
              onChange={(e) => setNewTenant(e.target.value)}
            />
            <select
              className="input"
              aria-label="Kind"
              value={kind}
              onChange={(e) => setKind(e.target.value as Principal["kind"])}
            >
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
            <input
              className="input"
              placeholder="Scopes, e.g. ingest query"
              aria-label="Scopes"
              value={scopes}
              onChange={(e) => setScopes(e.target.value)}
            />
            <input
              className="input"
              placeholder="Indexes (default *)"
              aria-label="Indexes"
              value={indexes}
              onChange={(e) => setIndexes(e.target.value)}
            />
            <input
              className="input"
              list="audience-options"
              placeholder="Audience, e.g. logless:prod:agent"
              aria-label="Audience"
              value={audience}
              onChange={(e) => setAudience(e.target.value)}
            />
            <input
              className="input"
              placeholder="Max token lifetime, hours (blank: broker default)"
              aria-label="Max token lifetime in hours"
              value={maxHours}
              onChange={(e) => setMaxHours(e.target.value)}
            />
            <input
              className="input"
              placeholder="First secret expires after, hours (blank: never)"
              aria-label="First secret expiry in hours"
              value={expiresHours}
              onChange={(e) => setExpiresHours(e.target.value)}
            />
            <div>
              <button
                type="button"
                disabled={busy || !formOk}
                onClick={() => void create()}
                className="btn-primary"
              >
                <Plus className="h-3.5 w-3.5" /> Create
              </button>
            </div>
          </div>
          <datalist id="tenant-options">
            {tenants.map((t) => (
              <option key={t.tenant} value={t.tenant} />
            ))}
          </datalist>
          <datalist id="audience-options">
            {audiences.map((a) => (
              <option key={a} value={a} />
            ))}
          </datalist>
          <p className="mt-1.5 text-[11px] text-muted-foreground">
            Scopes and indexes are separated by spaces or commas. The audience is the one service
            the token will be good for; the broker checks it against its configured audiences when
            it issues. A tenant nobody has used yet is created on the spot, so check the spelling.
          </p>
        </Panel>

        {principals === null && !error && <p className="text-[12px] text-muted-foreground">Loading…</p>}

        {principals?.length === 0 && (
          <p className="text-[12px] text-muted-foreground">
            No principals{tenant ? ` in ${tenant}` : ""}. Create one above and paste its id and
            secret into the service&apos;s configuration.
          </p>
        )}

        {principals && principals.length > 0 && (
          <table className="w-full text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b border-outline-subtle">
                <th className="px-2 py-1.5 text-left">Name</th>
                <th className="px-2 py-1.5 text-left">Principal id</th>
                <th className="px-2 py-1.5 text-left">Tenant</th>
                <th className="px-2 py-1.5 text-left">Kind</th>
                <th className="px-2 py-1.5 text-left">Scopes</th>
                <th className="px-2 py-1.5 text-left">Indexes</th>
                <th className="px-2 py-1.5 text-left">Audience</th>
                <th className="px-2 py-1.5 text-left">Last used</th>
                <th className="px-2 py-1.5 text-left">State</th>
                <th className="px-2 py-1.5" />
              </tr>
            </thead>
            <tbody>
              {principals.map((p) => (
                <tr key={p.principal_id} className="border-b border-outline-subtle/60">
                  <td className="px-2 py-1.5 text-foreground">{p.name}</td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">{p.principal_id}</td>
                  <td className="px-2 py-1.5 text-muted-foreground">{p.tenant}</td>
                  <td className="px-2 py-1.5 text-muted-foreground">{p.kind}</td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">{p.scopes.join(" ")}</td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">{p.indexes.join(" ")}</td>
                  <td className="px-2 py-1.5 font-mono text-muted-foreground">{p.audience}</td>
                  <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                    {/* Never-used usually means the secret was handed over and the
                        service was never switched to it. */}
                    {p.last_used_at ? fmtTime(p.last_used_at) : "never"}
                  </td>
                  <td className="px-2 py-1.5">
                    {p.live ? (
                      <StatusBadge variant="ok">live</StatusBadge>
                    ) : (
                      <StatusBadge variant="neutral">revoked {fmtTime(p.revoked_at)}</StatusBadge>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-right">
                    <div className="flex justify-end gap-1.5">
                      <button type="button" className="btn-ghost" onClick={() => void open(p.principal_id)}>
                        Secrets
                      </button>
                      {p.live && (
                        <button
                          type="button"
                          className="btn-danger"
                          onClick={() => {
                            setConfirming({
                              heading: `Revoke principal “${p.name}”?`,
                              word: p.name,
                              run: async () => {
                                await adminApi.revokePrincipal(p.principal_id);
                                setSelected((s) => (s?.principal_id === p.principal_id ? null : s));
                              },
                            });
                            setConfirmText("");
                          }}
                        >
                          <ShieldOff className="h-3.5 w-3.5" /> Revoke
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {selected && (
          <Panel>
            <div className="mb-2 flex items-center gap-2">
              <div className="text-[12px] font-medium text-foreground">
                Secrets for “{selected.name}”
              </div>
              <span className="font-mono text-[11px] text-muted-foreground">
                {selected.principal_id}
              </span>
              <button type="button" className="btn-ghost ml-auto" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>

            <table className="mb-3 w-full text-[11.5px]">
              <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
                <tr className="border-b border-outline-subtle">
                  <th className="px-2 py-1.5 text-left">Secret id</th>
                  <th className="px-2 py-1.5 text-left">Created</th>
                  <th className="px-2 py-1.5 text-left">Expires</th>
                  <th className="px-2 py-1.5 text-left">State</th>
                  <th className="px-2 py-1.5" />
                </tr>
              </thead>
              <tbody>
                {selected.secrets.map((s) => (
                  <tr key={s.secret_id} className="border-b border-outline-subtle/60">
                    <td className="px-2 py-1.5 font-mono text-muted-foreground">{s.secret_id}</td>
                    <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                      {fmtTime(s.created_at)}
                    </td>
                    <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                      {s.expires_at ? fmtTime(s.expires_at) : "never"}
                    </td>
                    <td className="px-2 py-1.5">
                      {s.live ? (
                        <StatusBadge variant="ok">live</StatusBadge>
                      ) : s.revoked_at ? (
                        <StatusBadge variant="neutral">revoked {fmtTime(s.revoked_at)}</StatusBadge>
                      ) : (
                        <StatusBadge variant="neutral">expired</StatusBadge>
                      )}
                    </td>
                    <td className="px-2 py-1.5 text-right">
                      {s.live && (
                        <button
                          type="button"
                          className="btn-danger"
                          onClick={() => {
                            setConfirming({
                              heading: `Revoke secret ${s.secret_id}?`,
                              word: s.secret_id,
                              run: async () => {
                                await adminApi.revokePrincipalSecret(selected.principal_id, s.secret_id);
                                setSelected(await adminApi.principal(selected.principal_id));
                              },
                            });
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

            {selected.live && (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    className="input w-72"
                    placeholder="Expires after, hours (blank: never)"
                    aria-label="New secret expiry in hours"
                    value={secretExpiresHours}
                    onChange={(e) => setSecretExpiresHours(e.target.value)}
                  />
                  <input
                    className="input w-72"
                    placeholder="Older stop after, hours (blank: keep)"
                    aria-label="Older secrets expiry in hours"
                    value={expireOldHours}
                    onChange={(e) => setExpireOldHours(e.target.value)}
                  />
                  <button
                    type="button"
                    className="btn-primary"
                    disabled={busy || secretExpiry === null || oldExpiry === null}
                    onClick={() => void addSecret(selected)}
                  >
                    <Plus className="h-3.5 w-3.5" /> Add secret
                  </button>
                </div>
                <p className="mt-1.5 text-[11px] text-muted-foreground">
                  The old secret keeps working until you revoke it or give it an end time here, so
                  the service can switch over whenever it is ready.
                </p>
              </>
            )}
          </Panel>
        )}

      </div>
    </div>
  );
}
