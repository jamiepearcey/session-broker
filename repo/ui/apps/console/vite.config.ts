import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// The console talks to the broker's INTERNAL listener, not its public one.
//
// `/admin/*` and `/internal/token` are operator surfaces that must not be
// internet-reachable, so they live on `internal_bind_addr`. Proxying here keeps
// the console same-origin (no CORS surface to configure) while still pointing
// at the right listener — and makes it obvious in one place that this app is a
// tool run against a broker you can already reach privately, not something to
// deploy publicly.
const BROKER_INTERNAL_URL = process.env['SESSION_BROKER_INTERNAL_URL'] ?? 'http://127.0.0.1:8090';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  server: {
    // Distinct from the demo app's 5180 so both can run at once.
    port: 5181,
    proxy: {
      '/admin': { target: BROKER_INTERNAL_URL, changeOrigin: true },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
});
