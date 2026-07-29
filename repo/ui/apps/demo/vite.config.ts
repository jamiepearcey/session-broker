import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev-only same-origin fronting for the broker + its mock IdP fixture.
// Everything the SDK talks to (`/session/*`, `/auth/*`, `/logout`) must be
// same-origin — there is no CORS mode (INV-10) — so the dev server proxies
// it here instead of the app calling a different origin directly.
// `/__test__/*` belongs to `mock-idp`, not the broker itself (it is the
// mock IdP's own control surface — see `crates/mock-idp`), so it proxies to
// a different target.
// Use 127.0.0.1, not localhost: Node >=17 resolves `localhost` to IPv6 `::1`
// by default (Happy Eyeballs / DNS ordering changed in Node 17), but the
// broker and mock-idp bind IPv4-only. A `localhost` target here silently
// hangs every proxied request instead of failing fast.
const BROKER_BASE_URL = process.env['SESSION_BROKER_BASE_URL'] ?? 'http://127.0.0.1:8080';
const MOCK_IDP_BASE_URL = process.env['MOCK_IDP_BASE_URL'] ?? 'http://127.0.0.1:8090';

export default defineConfig({
  plugins: [react()],
  server: {
    // Bind IPv4 explicitly, for the same reason the proxy targets above do.
    // Vite defaults to `localhost`, which resolves to `::1` on macOS and on
    // Node >=17 — so the dev server ends up somewhere the broker's own
    // redirect URLs do not point (the SDK follows the broker's `login_url`, which is built from `base_url`), and a login bounces off
    // ERR_CONNECTION_REFUSED at 127.0.0.1 while the same page loads fine over
    // `localhost`. Matching the broker's family removes the whole class.
    host: '127.0.0.1',
    port: 5180,
    proxy: {
      '/session': { target: BROKER_BASE_URL, changeOrigin: true },
      '/auth': { target: BROKER_BASE_URL, changeOrigin: true },
      '/logout': { target: BROKER_BASE_URL, changeOrigin: true },
      '/__test__': { target: MOCK_IDP_BASE_URL, changeOrigin: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
