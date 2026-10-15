#!/usr/bin/env node
// Executable check for the dev identity stack started by scripts/dev-quant-identity.sh.
//
// For each persona it signs in through the broker with a plain HTTP client (no browser):
//   GET  broker /auth/login            -> 30x to mock-idp /authorize (+ txn cookie)
//   GET  mock-idp /authorize&login_as  -> 302 to <APP_ORIGIN>/auth/callback?code&state
//   GET  broker /auth/callback         -> 302 + broker_session cookie
//        (the redirect names APP_ORIGIN, where no vite is running here, so the script sends the
//         same path and query to the broker's public port instead; that is the only rewrite)
//   POST broker /session/token         -> EdDSA JWT (needs Origin: APP_ORIGIN, broker INV-2)
// then verifies the JWT offline against GET /auth/jwks.json by the rules in docs/verifier/README.md
// and asserts the persona's claims against the grants the launcher seeded.
//
// Negative checks (each must be REFUSED, and the script exits 1 if any is accepted):
//   tampered payload, tampered signature, alg=none, alg=HS256, wrong audience (verifier side and
//   broker side), expired token (clock moved past exp+300), and a session that has been logged out.
//
// No dependencies; node:crypto does Ed25519 from a JWK.
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

const ORIGIN = 'http://127.0.0.1:18745';
const BROKER = 'http://127.0.0.1:18796';
const AUDIENCE = 'quant-workbench';
const TENANT = 'quant-workbench';

// persona -> exact roles the launcher seeds; null = no grant, so no token.
const EXPECT = {
  alice: ['limits:view', 'limits:ack:fx'],
  bob: ['limits:view', 'limits:ack:fx', 'limits:waive:fx:soft'],
  carol: ['limits:view', 'limits:waive:fx:hard', 'limits:approve-change:fx', 'limits:signoff'],
  dave: ['limits:view', 'limits:waive:fx:hard', 'limits:approve-change:fx', 'limits:signoff'],
  erin: null,
};

let failures = 0;
const ok = (cond, what) => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`);
  if (!cond) failures += 1;
  return cond;
};

// ---- a minimal cookie jar and a no-redirect request helper ----
class Jar {
  #c = new Map();
  absorb(res) {
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const gone = attrs.some((a) => /^\s*max-age=0\s*$/i.test(a)) || value === '';
      if (gone) this.#c.delete(name);
      else this.#c.set(name, value);
    }
  }
  header() {
    return [...this.#c].map(([k, v]) => `${k}=${v}`).join('; ');
  }
  has(name) {
    return this.#c.has(name);
  }
}

async function call(jar, method, url, { headers = {}, body } = {}) {
  const res = await fetch(url, {
    method,
    redirect: 'manual',
    headers: { ...headers, ...(jar.header() ? { cookie: jar.header() } : {}) },
    body,
  });
  jar.absorb(res);
  return res;
}

async function signIn(sub) {
  const jar = new Jar();
  const login = await call(jar, 'GET', `${BROKER}/auth/login?return_to=/`);
  if (![302, 303].includes(login.status)) throw new Error(`/auth/login: HTTP ${login.status}`);
  const authorize = new URL(login.headers.get('location'));
  authorize.searchParams.set('login_as', sub);
  const idp = await call(new Jar(), 'GET', authorize);
  if (idp.status !== 302) throw new Error(`mock-idp /authorize: HTTP ${idp.status}`);
  const cb = new URL(idp.headers.get('location'));
  if (cb.origin !== ORIGIN || cb.pathname !== '/auth/callback') {
    throw new Error(`unexpected callback ${cb.origin}${cb.pathname}: ${cb.search}`);
  }
  const done = await call(jar, 'GET', `${BROKER}${cb.pathname}${cb.search}`);
  if (done.status !== 302 && done.status !== 303) throw new Error(`/auth/callback: HTTP ${done.status}`);
  if (!jar.has('broker_session')) throw new Error('no broker_session cookie after callback');
  return jar;
}

const postJson = (jar, path, body, extra = {}) =>
  call(jar, 'POST', `${BROKER}${path}`, {
    headers: { origin: ORIGIN, 'content-type': 'application/json', ...extra },
    body: JSON.stringify(body),
  });

// ---- offline JWT verification (docs/verifier/README.md checks 1-4) ----
const b64u = (s) => Buffer.from(s, 'base64url');
const REQUIRED = ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'tenant', 'kind'];

function verifyToken(token, jwks, { iss, aud, now }) {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return { err: 'malformed' };
  let header, claims;
  try {
    header = JSON.parse(b64u(parts[0]).toString());
  } catch {
    return { err: 'malformed' };
  }
  if (header.alg !== 'EdDSA') return { err: 'alg' }; // before any key lookup
  if (header.typ !== undefined && header.typ !== 'JWT') return { err: 'typ' };
  if ('crit' in header || typeof header.kid !== 'string') return { err: 'malformed' };
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) return { err: 'unknown_kid' };
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  if (!cryptoVerify(null, Buffer.from(`${parts[0]}.${parts[1]}`), key, b64u(parts[2]))) return { err: 'signature' };
  try {
    claims = JSON.parse(b64u(parts[1]).toString());
  } catch {
    return { err: 'malformed' };
  }
  if (REQUIRED.some((c) => claims[c] === undefined)) return { err: 'claims' };
  if (claims.iss !== iss) return { err: 'issuer' };
  if (typeof claims.aud !== 'string' || claims.aud !== aud) return { err: 'audience' };
  if (!(claims.exp > now - 300)) return { err: 'expired' };
  if (!(claims.iat <= now + 300)) return { err: 'not_yet_valid' };
  return { claims, header };
}

const flip = (b64) => {
  const buf = Buffer.from(b64, 'base64url');
  buf[0] ^= 0x01;
  return buf.toString('base64url');
};
const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

async function main() {
  const jwksRes = await fetch(`${BROKER}/auth/jwks.json`);
  if (!ok(jwksRes.status === 200, `GET /auth/jwks.json -> ${jwksRes.status}`)) process.exit(1);
  const jwks = await jwksRes.json();
  ok(jwks.keys?.length >= 1 && jwks.keys.every((k) => k.kty === 'OKP' && k.crv === 'Ed25519'), `jwks holds ${jwks.keys?.length} Ed25519 key(s)`);
  const vopts = () => ({ iss: ORIGIN, aud: AUDIENCE, now: Math.floor(Date.now() / 1000) });

  const sessions = {};
  console.log('\npersona  sub     tenant            exp (utc)             roles');
  for (const [sub, expected] of Object.entries(EXPECT)) {
    const jar = await signIn(sub);
    sessions[sub] = jar;
    const res = await postJson(jar, '/session/token', { audience: AUDIENCE, tenant: TENANT });
    const body = await res.json().catch(() => ({}));
    if (expected === null) {
      ok(res.status >= 400 && body.access_token === undefined, `${sub}: no grant -> no token (HTTP ${res.status} ${body.error ?? body.code ?? ''})`);
      ok(JSON.stringify(body).includes('not_granted'), `${sub}: refusal is not_granted`);
      continue;
    }
    if (!ok(res.status === 200 && typeof body.access_token === 'string', `${sub}: POST /session/token -> ${res.status}`)) {
      console.log('     ', JSON.stringify(body));
      continue;
    }
    const v = verifyToken(body.access_token, jwks, vopts());
    if (!ok(v.claims, `${sub}: token verifies offline against jwks (${v.err ?? 'kid ' + v.header.kid})`)) continue;
    const c = v.claims;
    console.log(`         ${c.sub.padEnd(7)} ${c.tenant.padEnd(17)} ${new Date(c.exp * 1000).toISOString()}  ${c.roles.join(' ')}`);
    ok(c.sub === sub && c.tenant === TENANT && c.kind === 'user' && c.aud === AUDIENCE && c.iss === ORIGIN, `${sub}: sub/tenant/kind/aud/iss as expected`);
    ok(JSON.stringify([...c.roles].sort()) === JSON.stringify([...expected].sort()), `${sub}: roles are exactly the seeded grant`);
    ok(c.exp - c.iat <= 3600, `${sub}: lifetime ${c.exp - c.iat}s <= 3600s`);
    sessions[sub] = { jar, token: body.access_token, claims: c };
  }

  // alice must not hold any waive role; erin none at all
  const alice = sessions.alice?.claims;
  ok(alice && !alice.roles.some((r) => r.startsWith('limits:waive:')), 'alice holds no limits:waive:* role');
  ok(!sessions.erin?.token, 'erin holds no token (and therefore no role)');

  // ---- negative checks, all on bob's token ----
  const bob = sessions.bob;
  if (bob?.token) {
    const [h, p, s] = bob.token.split('.');
    const refused = (token, what, want, opts = vopts()) => {
      const r = verifyToken(token, jwks, opts);
      ok(r.err === want, `refused: ${what} (${r.err ?? 'ACCEPTED'}, wanted ${want})`);
    };
    const claims = JSON.parse(b64u(p).toString());
    refused(`${h}.${enc({ ...claims, roles: [...claims.roles, 'limits:waive:fx:hard'] })}.${s}`, 'payload tampered to add a waive role', 'signature');
    refused(`${h}.${flip(p)}.${s}`, 'payload byte flipped', 'signature');
    refused(`${h}.${p}.${flip(s)}`, 'signature byte flipped', 'signature');
    refused(`${enc({ alg: 'none', typ: 'JWT', kid: JSON.parse(b64u(h).toString()).kid })}.${p}.${s}`, 'alg=none', 'alg');
    refused(`${enc({ alg: 'HS256', typ: 'JWT', kid: JSON.parse(b64u(h).toString()).kid })}.${p}.${s}`, 'alg=HS256', 'alg');
    refused(bob.token, 'token checked by a verifier whose audience is another product', 'audience', { ...vopts(), aud: 'other-product' });
    refused(bob.token, 'token checked by a verifier with another issuer', 'issuer', { ...vopts(), iss: 'http://127.0.0.1:1' });
    refused(bob.token, 'token checked 301s past exp', 'expired', { ...vopts(), now: claims.exp + 301 });
    const edge = verifyToken(bob.token, jwks, { ...vopts(), now: claims.exp + 299 });
    ok(edge.claims, 'accepted: 299s past exp (inside the 300s allowance)');

    const wrongAud = await postJson(bob.jar, '/session/token', { audience: 'other-product', tenant: TENANT });
    const wrongBody = await wrongAud.text();
    ok(wrongAud.status >= 400 && wrongBody.includes('bad_audience') && !wrongBody.includes('access_token'), `broker refuses an unlisted audience (HTTP ${wrongAud.status} bad_audience)`);

    const noOrigin = await call(bob.jar, 'POST', `${BROKER}/session/token`, {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ audience: AUDIENCE, tenant: TENANT }),
    });
    ok(noOrigin.status >= 400, `broker refuses /session/token without Origin (INV-2) (HTTP ${noOrigin.status})`);

    // logout, then the very same cookie must not mint another token
    const cookieBefore = bob.jar.header();
    const out = await postJson(bob.jar, '/logout', {});
    ok(out.status < 400, `bob: POST /logout -> ${out.status}`);
    const replay = await call(new Jar(), 'POST', `${BROKER}/session/token`, {
      headers: { origin: ORIGIN, 'content-type': 'application/json', cookie: cookieBefore },
      body: JSON.stringify({ audience: AUDIENCE, tenant: TENANT }),
    });
    const replayBody = await replay.text();
    ok(replay.status === 401 && !replayBody.includes('access_token'), `logged-out session cookie is refused (HTTP ${replay.status} ${replayBody.slice(0, 80)})`);
  }
  console.log(failures ? `\n${failures} check(s) FAILED` : '\nall checks passed');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error('check could not run:', e.message);
  process.exit(2);
});
