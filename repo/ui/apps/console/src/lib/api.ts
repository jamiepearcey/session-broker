// The admin lane's client (`docs/openapi.yaml`, tag `admin`).
//
// ## Why this holds the admin key in memory only
//
// `/admin/*` lives on the broker's INTERNAL listener and is guarded by the
// admin key — the credential that can mint credentials. This console is a
// browser app, so that key would be in JS whatever we did; what it must never
// be is *persisted*. It is kept in a module-level variable and nowhere else:
// not `localStorage`, not `sessionStorage`, not a cookie. A closed tab forgets
// it, which is the correct amount of memory for the most powerful secret in the
// deployment.
//
// The console is therefore an operator tool run against a broker you can already
// reach on its internal address — not something to expose publicly. That is the
// same posture ArrowRef's console takes toward its own node.

export interface ApiKey {
  key_id: string;
  name: string;
  created_at: number;
  created_by: string | null;
  last_used_at: number | null;
  revoked_at: number | null;
  live: boolean;
}

export interface AdminSession {
  sid: string;
  sub: string;
  custody_id: string;
  current_gen: number;
  idle_exp: number;
  absolute_exp: number;
}

export interface Custody {
  custody_id: string;
  status: string;
  access_exp: number;
  next_refresh: number;
  fail_count: number;
}

export interface IssuedKey {
  key_id: string;
  name: string;
  /** Shown exactly once. The server cannot return it again. */
  secret: string;
  created_at: number;
}

/** Distinguishes "the broker said no" from "the broker is not there". */
export class AdminError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "AdminError";
  }

  /** True when the key is the problem, rather than the request. */
  get isAuth(): boolean {
    return this.status === 401 || this.status === 501;
  }
}

let adminKey: string | null = null;

export function setAdminKey(key: string | null): void {
  adminKey = key && key.trim() ? key.trim() : null;
}

export function hasAdminKey(): boolean {
  return adminKey !== null;
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  if (!adminKey) {
    throw new AdminError(401, "no_key", "No admin key has been entered.");
  }

  let response: Response;
  try {
    response = await fetch(`/admin${path}`, {
      ...init,
      headers: {
        ...(init?.body ? { "content-type": "application/json" } : {}),
        authorization: `Bearer ${adminKey}`,
        ...init?.headers,
      },
    });
  } catch (e) {
    // A network failure is not an authorisation failure, and showing the
    // "check your key" state here would send an operator hunting for the wrong
    // problem while the broker is simply down.
    throw new AdminError(0, "unreachable", e instanceof Error ? e.message : String(e));
  }

  if (response.status === 204) return undefined as T;

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new AdminError(
      response.status,
      body.error ?? "unknown",
      body.detail ?? `The broker answered ${response.status}.`,
    );
  }
  return (await response.json()) as T;
}

export const adminApi = {
  keys: () => call<ApiKey[]>("/api-keys"),
  createKey: (name: string) =>
    call<IssuedKey>("/api-keys", { method: "POST", body: JSON.stringify({ name }) }),
  revokeKey: (keyId: string) =>
    call<void>(`/api-keys/${encodeURIComponent(keyId)}`, { method: "DELETE" }),
  sessions: () => call<AdminSession[]>("/sessions"),
  revokeSession: (sid: string) =>
    call<void>(`/sessions/${encodeURIComponent(sid)}`, { method: "DELETE" }),
  custody: () => call<Custody[]>("/custody"),
};

/** Unix seconds → a short absolute time. Absolute, not relative: an operator
 *  correlating with logs needs a timestamp, not "3 hours ago". */
export function fmtTime(secs: number | null | undefined): string {
  if (!secs) return "—";
  return new Date(secs * 1000).toISOString().replace("T", " ").slice(0, 19);
}

/** How long until `secs`, signed. Negative means it has already passed, which
 *  is the case worth seeing at a glance on an expiry column. */
export function fmtUntil(secs: number | null | undefined, now = Date.now()): string {
  if (!secs) return "—";
  const delta = Math.round(secs - now / 1000);
  const abs = Math.abs(delta);
  const unit = abs < 60 ? `${abs}s` : abs < 3600 ? `${Math.round(abs / 60)}m` : `${Math.round(abs / 3600)}h`;
  return delta < 0 ? `${unit} ago` : `in ${unit}`;
}
