#!/usr/bin/env bash
# Dev identity stack for the quant workbench: mock-idp (five canned people) + session-broker.
#
#   scripts/dev-quant-identity.sh start    build, wipe state, start both detached, seed grants
#   scripts/dev-quant-identity.sh stop
#   scripts/dev-quant-identity.sh status
#   scripts/dev-quant-identity.sh check    run scripts/dev-quant-identity-check.mjs against the running stack
#
# Topology (broker ADR-0012, single origin, path-mounted): the browser origin is APP_ORIGIN
# (vite, 18745). The broker's public listener is on BROKER_PUBLIC and its base_url/issuer is
# APP_ORIGIN, so a browser reaches it through a vite proxy of /auth /session /logout. With no
# vite running, the check script drives the broker directly (see its header).
#
# Everything below is a PUBLIC DEV FIXTURE value. None of it is a secret. Never reuse it.
#
# Root of trust: whoever holds DEV_ADMIN_KEY can mint or revoke a user_grant (the only source of
# tenant and roles in a user token, ADR-0017) via POST/DELETE /admin/user-grants on the INTERNAL
# listener. Each mutation commits an audit row (user_grant.created / user_grant.revoked, ADR-0017
# INV-13, "Each mutation's audit row ... commits in the same transaction"), readable at
# GET /admin/audit. The row records the grant but its actor is the single constant admin actor,
# not a named operator. The roles below are DEV FIXTURES for exercising the mechanism, not a
# proposed entitlement matrix.
set -euo pipefail

SB_REPO="${SB_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SB_DEV_DIR="${SB_DEV_DIR:-$HOME/tmp/qw-identity}"
SB_TARGET="${SB_TARGET:-$HOME/tmp/sb-target}"
APP_ORIGIN="http://127.0.0.1:18745"
MOCK_IDP_ADDR="127.0.0.1:18795"
BROKER_PUBLIC="127.0.0.1:18796"
BROKER_INTERNAL="127.0.0.1:18797"
AUDIENCE="quant-workbench"
TENANT="quant-workbench"

CLIENT_ID="session-broker-dev"
CLIENT_SECRET="dev-secret"
DEV_ADMIN_KEY="dev-admin-key-public-fixture-0000000000000000"   # >= 32 chars
USERS='alice|alice@example.test|Alice Preparer;bob|bob@example.test|Bob Risk Manager;carol|carol@example.test|Carol Head of Risk;dave|dave@example.test|Dave Second Approver;erin|erin@example.test|Erin No Grants'

# persona|roles (comma separated). erin has no grant on purpose.
GRANTS=(
  "alice|limits:view,limits:ack:fx"
  "bob|limits:view,limits:ack:fx,limits:waive:fx:soft"
  "carol|limits:view,limits:waive:fx:hard,limits:approve-change:fx,limits:signoff"
  "dave|limits:view,limits:waive:fx:hard,limits:approve-change:fx,limits:signoff"
)

cmd="${1:-start}"
alive() { [ -s "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

stop_one() {
  local pidfile="$1" name="$2"
  if alive "$pidfile"; then
    kill "$(cat "$pidfile")" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do alive "$pidfile" || break; sleep 0.3; done
    alive "$pidfile" && kill -9 "$(cat "$pidfile")" 2>/dev/null || true
    echo "stopped $name"
  fi
  rm -f "$pidfile"
}
do_stop() { stop_one "$SB_DEV_DIR/broker.pid" broker; stop_one "$SB_DEV_DIR/mock-idp.pid" mock-idp; }

wait_http() { # url, seconds
  local n=$(( $2 * 5 ))
  for _ in $(seq 1 "$n"); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.2; done
  return 1
}

case "$cmd" in
  stop) do_stop; exit 0 ;;
  status)
    for n in mock-idp broker; do
      if alive "$SB_DEV_DIR/$n.pid"; then echo "$n running (pid $(cat "$SB_DEV_DIR/$n.pid"))"; else echo "$n not running"; fi
    done
    exit 0 ;;
  check) exec node "$SB_REPO/scripts/dev-quant-identity-check.mjs" ;;
  start) ;;
  *) echo "usage: $0 start|stop|status|check" >&2; exit 2 ;;
esac

mkdir -p "$SB_DEV_DIR"
if alive "$SB_DEV_DIR/broker.pid" || alive "$SB_DEV_DIR/mock-idp.pid"; then
  echo "already running; '$0 stop' first" >&2; exit 1
fi

# Disk guard: other sessions write large target dirs, stop below 15 GiB free.
free_gib=$(df -g / | awk 'NR==2{print $4}')
if [ "${free_gib:-0}" -lt 15 ]; then
  echo "only ${free_gib} GiB free on /, need 15; stopping" >&2; exit 1
fi

# One fixed cargo invocation per target dir (see the global disk rules).
( cd "$SB_REPO" && CARGO_TARGET_DIR="$SB_TARGET" cargo build -p session-broker -p mock-idp )

# Fresh state every start: grants are immutable (revoke to change), so a reset is the
# simplest way to make the seeded set exactly the set above. Sessions do not survive a start.
rm -f "$SB_DEV_DIR"/session-broker.db* "$SB_DEV_DIR"/session-broker.key
cd "$SB_DEV_DIR"   # a stray ./session-broker.toml cannot be picked up

MOCK_IDP_BIND="$MOCK_IDP_ADDR" \
MOCK_IDP_CLIENT_ID="$CLIENT_ID" MOCK_IDP_CLIENT_SECRET="$CLIENT_SECRET" \
MOCK_IDP_REDIRECT_URIS="$APP_ORIGIN/auth/callback" \
MOCK_IDP_RSA_SEED="20261015" \
MOCK_IDP_USERS="$USERS" \
  "$SB_TARGET/debug/mock-idp" >"$SB_DEV_DIR/mock-idp.log" 2>&1 &
echo $! >"$SB_DEV_DIR/mock-idp.pid"

if ! wait_http "http://$MOCK_IDP_ADDR/.well-known/openid-configuration" 15; then
  echo "mock-idp did not come up; see $SB_DEV_DIR/mock-idp.log" >&2; do_stop; exit 1
fi

# BROKER_DEFAULT_USER_TENANT=none: a person with no grant gets no token (not_granted), rather
# than the default tenant with role "viewer". Entitlement needs that off.
BROKER_BASE_URL="$APP_ORIGIN" \
BROKER_BIND_ADDR="$BROKER_PUBLIC" \
BROKER_INTERNAL_BIND_ADDR="$BROKER_INTERNAL" \
BROKER_DB_PATH="$SB_DEV_DIR/session-broker.db" \
BROKER_KEYFILE_PATH="$SB_DEV_DIR/session-broker.key" \
BROKER_OIDC_ISSUER_URL="http://$MOCK_IDP_ADDR" \
BROKER_OIDC_CLIENT_ID="$CLIENT_ID" BROKER_OIDC_CLIENT_SECRET="$CLIENT_SECRET" \
BROKER_ADMIN_API_KEY="$DEV_ADMIN_KEY" \
BROKER_TOKEN_ISSUER="$APP_ORIGIN" BROKER_ISSUER_AUDIENCES="$AUDIENCE" \
BROKER_DEFAULT_USER_TENANT="none" \
  "$SB_TARGET/debug/session-broker" >"$SB_DEV_DIR/broker.log" 2>&1 &
echo $! >"$SB_DEV_DIR/broker.pid"

if ! wait_http "http://$BROKER_INTERNAL/readyz" 20; then
  echo "broker did not become ready; see $SB_DEV_DIR/broker.log" >&2; do_stop; exit 1
fi

for entry in "${GRANTS[@]}"; do
  sub="${entry%%|*}"; roles="${entry#*|}"
  roles_json=$(printf '%s' "$roles" | sed 's/[^,][^,]*/"&"/g')
  code=$(curl -sS -o "$SB_DEV_DIR/seed.out" -w '%{http_code}' -X POST "http://$BROKER_INTERNAL/admin/user-grants" \
    -H "Authorization: Bearer $DEV_ADMIN_KEY" -H 'Content-Type: application/json' \
    -d "{\"sub\":\"$sub\",\"tenant\":\"$TENANT\",\"roles\":[$roles_json]}")
  if [ "$code" != 201 ] && [ "$code" != 200 ]; then
    echo "seeding $sub failed: HTTP $code: $(cat "$SB_DEV_DIR/seed.out")" >&2; do_stop; exit 1
  fi
  echo "granted $sub in $TENANT: $roles"
done
rm -f "$SB_DEV_DIR/seed.out"

cat <<MSG
mock-idp  http://$MOCK_IDP_ADDR   (users: alice bob carol dave erin; /authorize?login_as=<sub>)
broker    public http://$BROKER_PUBLIC   internal/admin http://$BROKER_INTERNAL
origin    $APP_ORIGIN   issuer/audience: $APP_ORIGIN / $AUDIENCE   tenant: $TENANT
audit     curl -H 'Authorization: Bearer <dev admin key>' http://$BROKER_INTERNAL/admin/audit
logs      $SB_DEV_DIR/{broker,mock-idp}.log
stop      $0 stop        check  $0 check
MSG
