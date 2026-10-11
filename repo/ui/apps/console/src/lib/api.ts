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

export interface Tenant {
  tenant: string;
  display_name: string | null;
  created_at: number;
  disabled_at: number | null;
  live: boolean;
}

export interface Principal {
  principal_id: string;
  tenant: string;
  name: string;
  kind: "ingest" | "node" | "replica" | "reader" | "admin";
  scopes: string[];
  indexes: string[];
  audience: string;
  max_ttl_secs: number;
  created_at: number;
  created_by: string | null;
  last_used_at: number | null;
  revoked_at: number | null;
  live: boolean;
}

export interface PrincipalSecret {
  secret_id: string;
  created_at: number;
  expires_at: number | null;
  revoked_at: number | null;
  live: boolean;
}

export interface PrincipalDetail extends Principal {
  secrets: PrincipalSecret[];
}

/** A secret as returned by the call that made it. `secret` is shown exactly once. */
export interface IssuedSecret {
  secret_id: string;
  secret: string;
  created_at: number;
  expires_at: number | null;
}

export interface NewPrincipal {
  name: string;
  /** Defaults to `default`; created if nobody has used it yet. */
  tenant?: string;
  kind: Principal["kind"];
  scopes: string[];
  /** Defaults to `["*"]`. */
  indexes?: string[];
  audience: string;
  max_ttl_secs?: number;
  /** When the first secret stops working. Default: never. */
  expires_in_secs?: number;
}

export interface UserGrant {
  sub: string;
  tenant: string;
  roles: string[];
  indexes: string[];
  created_at: number;
  created_by: string | null;
  revoked_at: number | null;
  live: boolean;
}

export interface SigningKey {
  kid: string;
  /** The public key, base64url, as in the JWK Set. */
  x: string;
  created_at: number;
  activate_at: number;
  retire_at: number | null;
  removed_at: number | null;
  /** As the broker saw it when it answered; the console re-derives it from the timestamps. */
  state: "pending" | "signing" | "published" | "retired" | "removed";
}

export type SigningKeyState = SigningKey["state"];

/** `POST /admin/signing-keys/rotate`: what the new key will do and when. */
export interface Rotation {
  kid: string;
  activate_at: number;
  previous_retire_at: number;
  /** True when the older keys stopped being published at once. */
  immediate: boolean;
  note: string;
}

/**
 * A key's state at `now` (unix seconds), from its timestamps alone.
 *
 * Same rule as the broker: published keys are the ones neither removed nor past
 * `retire_at` (pending ones included), and the newest published key that has
 * started is the one signing. `keys` must be newest first, as the broker lists
 * them. Deriving it here keeps the column right between refreshes — a pending key
 * becomes the signing key at `activate_at` without anyone reloading.
 */
export function signingKeyStates(keys: SigningKey[], now: number): Map<string, SigningKeyState> {
  const states = new Map<string, SigningKeyState>();
  let signingTaken = false;
  for (const k of keys) {
    const published = k.removed_at === null && (k.retire_at === null || k.retire_at > now);
    if (k.removed_at !== null) states.set(k.kid, "removed");
    else if (!published) states.set(k.kid, "retired");
    else if (k.activate_at > now) states.set(k.kid, "pending");
    else if (!signingTaken) {
      signingTaken = true;
      states.set(k.kid, "signing");
    } else states.set(k.kid, "published");
  }
  return states;
}

/** One row of the durable audit record (ADR-0015). */
export interface AuditRow {
  seq: number;
  at: number;
  action: string;
  outcome: "success" | "failure";
  actor_kind: "admin" | "backend" | "user" | "system" | "anonymous";
  actor_id: string | null;
  subject: string | null;
  sid: string | null;
  custody_id: string | null;
  key_id: string | null;
  reason: string | null;
  client_ip_prefix: string | null;
  detail: Record<string, unknown> | null;
}

export interface AuditPage {
  rows: AuditRow[];
  /** Cursor for the next page; `null` at the end. */
  next_before_seq: number | null;
  retention_days: number;
  rows_total: number;
  oldest_at: number | null;
  newest_at: number | null;
  /** `audit.gap` rows in the window. Nonzero means the record is incomplete. */
  gaps: number;
}

// `| undefined` is explicit because the console builds these objects with every
// key present and some values `undefined` — under `exactOptionalPropertyTypes`,
// "absent" and "present but undefined" are different types, and the alternative
// is conditionally spreading eight keys at every call site.
export interface AuditFilters {
  since?: number | undefined;
  until?: number | undefined;
  action?: string | undefined;
  subject?: string | undefined;
  outcome?: string | undefined;
  actor_kind?: string | undefined;
  before_seq?: number | undefined;
  limit?: number | undefined;
}

/** What the diagnostics plane is currently doing (ADR-0014). */
export interface Observability {
  log_format: string;
  configured_filter: string;
  effective_filter: string;
  sinks: string[];
  log_file: string | null;
  log_file_rotation: string | null;
  override_active: boolean;
  override_expires_at: number | null;
  override_requested_by: string | null;
  override_max_secs: number;
  metrics_path: string | null;
  audit_retention_days: number;
  audit_queue_capacity: number;
  audit_queue_depth: number;
  audit_coalesce_secs: number;
  audit_subject_mode: string;
  audit_record_rotations: boolean;
  audit_rows: number;
  audit_oldest_at: number | null;
  audit_newest_at: number | null;
  audit_gaps: number;
  audit_dropped_total: number;
  audit_failed_total: number;
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
  tenants: () => call<Tenant[]>("/tenants"),
  createTenant: (tenant: string, displayName?: string) =>
    call<Tenant>("/tenants", {
      method: "POST",
      body: JSON.stringify({ tenant, display_name: displayName }),
    }),
  disableTenant: (tenant: string) =>
    call<void>(`/tenants/${encodeURIComponent(tenant)}`, { method: "DELETE" }),
  enableTenant: (tenant: string) =>
    call<void>(`/tenants/${encodeURIComponent(tenant)}/enable`, { method: "POST" }),
  principals: (tenant?: string) =>
    call<Principal[]>(`/principals${tenant ? `?tenant=${encodeURIComponent(tenant)}` : ""}`),
  principal: (principalId: string) =>
    call<PrincipalDetail>(`/principals/${encodeURIComponent(principalId)}`),
  createPrincipal: (body: NewPrincipal) =>
    call<Principal & { secret: IssuedSecret }>("/principals", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  revokePrincipal: (principalId: string) =>
    call<void>(`/principals/${encodeURIComponent(principalId)}`, { method: "DELETE" }),
  addPrincipalSecret: (
    principalId: string,
    options: { expires_in_secs?: number; expire_old_in_secs?: number } = {},
  ) =>
    call<IssuedSecret & { principal_id: string; old_secrets_expire_at: number | null }>(
      `/principals/${encodeURIComponent(principalId)}/secrets`,
      { method: "POST", body: JSON.stringify(options) },
    ),
  revokePrincipalSecret: (principalId: string, secretId: string) =>
    call<void>(
      `/principals/${encodeURIComponent(principalId)}/secrets/${encodeURIComponent(secretId)}`,
      { method: "DELETE" },
    ),
  userGrants: (tenant?: string) =>
    call<UserGrant[]>(`/user-grants${tenant ? `?tenant=${encodeURIComponent(tenant)}` : ""}`),
  createUserGrant: (grant: { sub: string; tenant?: string; roles: string[]; indexes?: string[] }) =>
    call<UserGrant>("/user-grants", { method: "POST", body: JSON.stringify(grant) }),
  revokeUserGrant: (sub: string, tenant: string) =>
    call<void>(`/user-grants/${encodeURIComponent(sub)}/${encodeURIComponent(tenant)}`, {
      method: "DELETE",
    }),
  signingKeys: () => call<SigningKey[]>("/signing-keys"),
  /** Omit `activateInSecs` for the broker's default lead; `0` retires the older keys now. */
  rotateSigningKey: (activateInSecs?: number) =>
    call<Rotation>("/signing-keys/rotate", {
      method: "POST",
      ...(activateInSecs === undefined
        ? {}
        : { body: JSON.stringify({ activate_in_secs: activateInSecs }) }),
    }),
  audit: (filters: AuditFilters = {}) => call<AuditPage>(`/audit${auditQuery(filters)}`),
  observability: () => call<Observability>("/observability"),
  setLogLevel: (filter: string, durationSecs: number) =>
    call<{ filter: string; expires_at: number }>("/observability", {
      method: "PUT",
      body: JSON.stringify({ filter, duration_secs: durationSecs }),
    }),
  restoreLogLevel: () => call<void>("/observability", { method: "DELETE" }),
};

function auditQuery(filters: AuditFilters): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    // `0` is a legitimate epoch and a legitimate cursor, so the test is
    // "supplied", not "truthy" — an `if (value)` here would silently drop them.
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

/**
 * The NDJSON export URL cannot be a plain link: the admin key lives in memory
 * and travels in an `Authorization` header, so the browser's own navigation
 * would arrive unauthenticated. Fetch it and hand the blob to a synthetic
 * anchor instead.
 */
export async function downloadAuditNdjson(filters: AuditFilters): Promise<void> {
  if (!adminKey) throw new AdminError(401, "no_key", "No admin key has been entered.");
  const response = await fetch(`/admin/audit${auditQuery({ ...filters, limit: 1000 })}&format=ndjson`, {
    headers: { authorization: `Bearer ${adminKey}` },
  });
  if (!response.ok) {
    throw new AdminError(response.status, "export_failed", "The export could not be produced.");
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "session-broker-audit.ndjson";
  anchor.click();
  URL.revokeObjectURL(url);
}

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
