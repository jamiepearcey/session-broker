// Signing keys — the Ed25519 keys behind every token the broker issues
// (`docs/design/token-issuer-scope.md`).
//
// Rotation is optional and safe by default: the new key is published at once and
// starts signing after the lead, and the older keys stay published until nothing
// they signed can still be valid. So the normal rotate needs no confirmation.
//
// The emergency variant is the exception. "Now" stops publishing every older key
// immediately, so tokens already issued stop verifying; that is what an operator
// wants after a key leak and never otherwise. It is red and typed.
//
// The state column is derived from the timestamps in the browser, with the
// broker's own rule, so it stays right between refreshes.

import { useCallback, useEffect, useState } from "react";
import { Fingerprint, RefreshCw, RotateCw } from "lucide-react";

import { StatusBadge, type StateVariant } from "@/components/StatusBadge";
import {
  AdminError,
  adminApi,
  fmtTime,
  fmtUntil,
  signingKeyStates,
  type Rotation,
  type SigningKey,
  type SigningKeyState,
} from "@/lib/api";
import { ErrorNote, Panel, Toolbar } from "@/components/chrome";
import { hoursToSecs } from "@/lib/utils";

const NOW_WORD = "rotate now";

const BADGE: Record<SigningKeyState, StateVariant> = {
  signing: "ok",
  published: "info",
  pending: "active",
  retired: "neutral",
  removed: "neutral",
};

const MEANING: Record<SigningKeyState, string> = {
  signing: "signs new tokens",
  published: "verifies older tokens",
  pending: "published, not yet signing",
  retired: "no longer published",
  removed: "pruned",
};

export function SigningKeys() {
  const [keys, setKeys] = useState<SigningKey[] | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [actionError, setActionError] = useState<AdminError | Error | null>(null);
  const [rotation, setRotation] = useState<Rotation | null>(null);
  const [leadHours, setLeadHours] = useState("");
  const [emergency, setEmergency] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [busy, setBusy] = useState(false);
  // Re-derive on a tick so a pending key turns into the signing key on screen.
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));

  const load = useCallback(async () => {
    try {
      setKeys(await adminApi.signingKeys());
      setError(null);
    } catch (e) {
      setError(e as Error);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const id = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 15_000);
    return () => clearInterval(id);
  }, []);

  const lead = hoursToSecs(leadHours);

  const rotate = async (activateInSecs: number | undefined) => {
    setBusy(true);
    try {
      setRotation(await adminApi.rotateSigningKey(activateInSecs));
      setActionError(null);
      setEmergency(false);
      setConfirmText("");
      setNow(Math.floor(Date.now() / 1000));
      await load();
    } catch (e) {
      setActionError(e as Error);
    } finally {
      setBusy(false);
    }
  };

  const states = keys ? signingKeyStates(keys, now) : new Map<string, SigningKeyState>();
  const signing = keys?.find((k) => states.get(k.kid) === "signing");

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Toolbar
        title="Signing keys"
        blurb="The keys the broker signs tokens with. Verifiers fetch the public halves from the broker's key set and keep working from their cache if it is briefly unreachable. Rotation is optional; run it on whatever schedule suits you."
        icon={Fingerprint}
      >
        {signing && <StatusBadge variant="ok">signing: {signing.kid}</StatusBadge>}
        <button type="button" onClick={() => void load()} className="btn-ghost">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </Toolbar>

      <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
        {error && <ErrorNote error={error} />}

        {rotation && (
          <Panel>
            <div className="mb-1 text-[12px] font-medium text-foreground">
              Key <span className="font-mono">{rotation.kid}</span> added.
            </div>
            <p className="text-[11.5px] text-muted-foreground">{rotation.note}</p>
            <p className="mt-1 text-[11.5px] text-muted-foreground">
              Signs from {fmtTime(rotation.activate_at)} · older keys{" "}
              {rotation.immediate ? "stopped being published" : "stop being published"}{" "}
              {fmtTime(rotation.previous_retire_at)}
            </p>
            <button type="button" className="btn-ghost mt-2" onClick={() => setRotation(null)}>
              Dismiss
            </button>
          </Panel>
        )}

        {actionError && (
          <Panel tone="danger">
            <div className="text-[12px] font-medium text-foreground">The key was not rotated.</div>
            <p className="mt-1 text-[11.5px] text-warn-foreground/85">{actionError.message}</p>
            {actionError instanceof AdminError && (
              <StatusBadge variant="neutral" className="mt-1.5">
                {actionError.status || "network"} · {actionError.code}
              </StatusBadge>
            )}
          </Panel>
        )}

        <Panel>
          <div className="mb-2 text-[11px] font-medium text-foreground">Rotate</div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="input w-72"
              placeholder="Start signing after, hours (blank: broker default)"
              aria-label="Lead time in hours"
              value={leadHours}
              onChange={(e) => setLeadHours(e.target.value)}
            />
            <button
              type="button"
              className="btn-primary"
              disabled={busy || lead === null}
              onClick={() => void rotate(lead ?? undefined)}
            >
              <RotateCw className="h-3.5 w-3.5" /> Rotate
            </button>
            <button
              type="button"
              className="btn-danger"
              disabled={busy}
              onClick={() => {
                setEmergency(true);
                setConfirmText("");
              }}
            >
              Rotate now (emergency)
            </button>
          </div>
          <p className="mt-1.5 text-[11px] text-muted-foreground">
            The new key is published straight away, so verifiers pick it up before it signs
            anything. The lead is how long they have; the broker&apos;s default is a day, at most
            30 days.
          </p>
        </Panel>

        {emergency && (
          <Panel tone="danger">
            <div className="mb-1 text-[12px] font-medium text-foreground">
              Rotate now and stop publishing every older key?
            </div>
            <p className="mb-2 text-[11.5px] text-warn-foreground/85">
              Use this when a signing key may have leaked. The new key signs immediately and the
              old keys leave the key set, so every token issued so far stops verifying, and
              verifiers reject new tokens until they next refresh their key set. Type{" "}
              <span className="font-mono text-foreground">{NOW_WORD}</span> to confirm.
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
                disabled={busy || confirmText !== NOW_WORD}
                onClick={() => void rotate(0)}
              >
                Rotate now
              </button>
              <button type="button" className="btn-ghost" onClick={() => setEmergency(false)}>
                Cancel
              </button>
            </div>
          </Panel>
        )}

        {keys === null && !error && <p className="text-[12px] text-muted-foreground">Loading…</p>}

        {keys?.length === 0 && (
          <p className="text-[12px] text-muted-foreground">
            No signing keys. The broker creates one at start when the token issuer is configured.
          </p>
        )}

        {keys && keys.length > 0 && (
          <table className="w-full text-[11.5px]">
            <thead className="text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b border-outline-subtle">
                <th className="px-2 py-1.5 text-left">Key id</th>
                <th className="px-2 py-1.5 text-left">State</th>
                <th className="px-2 py-1.5 text-left">Created</th>
                <th className="px-2 py-1.5 text-left">Signs from</th>
                <th className="px-2 py-1.5 text-left">Retires</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => {
                const state = states.get(k.kid) ?? k.state;
                return (
                  <tr key={k.kid} className="border-b border-outline-subtle/60">
                    <td className="px-2 py-1.5 font-mono text-foreground">{k.kid}</td>
                    <td className="px-2 py-1.5">
                      <StatusBadge variant={BADGE[state]}>{state}</StatusBadge>
                      <span className="ml-2 text-muted-foreground">{MEANING[state]}</span>
                    </td>
                    <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                      {fmtTime(k.created_at)}
                    </td>
                    <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                      {fmtTime(k.activate_at)}
                      {k.activate_at > now && ` (${fmtUntil(k.activate_at, now * 1000)})`}
                    </td>
                    <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                      {k.retire_at ? fmtTime(k.retire_at) : "—"}
                      {k.retire_at && k.retire_at > now && ` (${fmtUntil(k.retire_at, now * 1000)})`}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
