import type { Config } from 'tailwindcss';
import tailwindcssAnimate from 'tailwindcss-animate';

// Ported from the ArrowRef console's token set
// (infrastructure/query-cache/repo/ui), the same way this repo's own
// `apps/console` already did: keep the CSS-variable palette verbatim so
// `src/index.css` renders unchanged, but drop ArrowRef's `grid-react`
// Tailwind-config import. ArrowRef merges that config because it embeds the
// CubeCanvas data grid from source; this app has no grid, so importing it
// would add a cross-repo path dependency (a build failure the moment this
// repo is checked out without `analytics/CubeCanvas` beside it) for tokens
// nothing here emits.
//
// `spacing["0.25"/"0.75"/"1.25"]` is kept anyway: it is one of the token
// extensions grid-react's config supplied, and the ported chrome
// (StatusBadge, PlaneHeader, Select) uses `px-1.25`-style utilities from
// that scale. Without it those utilities compile to nothing.

const config = {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    container: { center: true, padding: '2rem', screens: { '2xl': '1400px' } },
    extend: {
      spacing: {
        '0.25': '1px',
        '0.75': '3px',
        '1.25': '5px',
      },
      fontFamily: {
        sans: ['Inter', 'SF Pro Text', 'Segoe UI', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: { DEFAULT: 'hsl(var(--primary))', foreground: 'hsl(var(--primary-foreground))' },
        secondary: { DEFAULT: 'hsl(var(--secondary))', foreground: 'hsl(var(--secondary-foreground))' },
        muted: { DEFAULT: 'hsl(var(--muted))', foreground: 'hsl(var(--muted-foreground))' },
        accent: { DEFAULT: 'hsl(var(--accent))', foreground: 'hsl(var(--accent-foreground))' },
        destructive: { DEFAULT: 'hsl(var(--destructive))', foreground: 'hsl(var(--destructive-foreground))' },
        card: { DEFAULT: 'hsl(var(--card))', foreground: 'hsl(var(--card-foreground))' },
        ok: { DEFAULT: 'hsl(var(--ok))', foreground: 'hsl(var(--ok-foreground))' },
        warn: { DEFAULT: 'hsl(var(--warn))', foreground: 'hsl(var(--warn-foreground))' },
        info: { DEFAULT: 'hsl(var(--info))', foreground: 'hsl(var(--info-foreground))' },
        surface: {
          app: 'hsl(var(--surface-app))',
          sidebar: 'hsl(var(--surface-sidebar))',
          panel: 'hsl(var(--surface-panel))',
          header: 'hsl(var(--surface-header))',
          toolbar: 'hsl(var(--surface-toolbar))',
          input: 'hsl(var(--surface-input))',
          hover: 'hsl(var(--surface-hover))',
          active: 'hsl(var(--surface-active))',
          warn: 'hsl(var(--surface-warn))',
          danger: 'hsl(var(--surface-danger))',
        },
        outline: {
          subtle: 'hsl(var(--outline-subtle))',
          strong: 'hsl(var(--outline-strong))',
        },
        icon: {
          muted: 'hsl(var(--icon-muted))',
          active: 'hsl(var(--icon-active))',
          tile: 'hsl(var(--icon-tile))',
          'tile-foreground': 'hsl(var(--icon-tile-foreground))',
        },
        // Only the four planes this app actually uses (Session/Race/Refresh/
        // Failures) — see src/lib/planes.ts. The full ten-plane set lives in
        // the CSS tokens below (copied verbatim) but is otherwise unused here.
        plane: {
          signals: 'hsl(var(--plane-signals))',
          compute: 'hsl(var(--plane-compute))',
          messaging: 'hsl(var(--plane-messaging))',
          budget: 'hsl(var(--plane-budget))',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
    },
  },
  plugins: [tailwindcssAnimate],
} satisfies Config;

export default config;
