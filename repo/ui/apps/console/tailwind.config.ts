import type { Config } from "tailwindcss";
import tailwindcssAnimate from "tailwindcss-animate";

// The ArrowRef console's token set, minus its CubeCanvas dependency.
//
// ArrowRef's own config merges `grid-react`'s Tailwind theme because it embeds
// the CubeCanvas grid from source. This console has no grid — it renders three
// dense tables — so importing that config would add a cross-repo path
// dependency (and a build failure the moment this repo is checked out without
// `analytics/CubeCanvas` beside it) in exchange for tokens nothing here emits.
//
// What IS kept is the part that matters for the copy: the same CSS-variable
// palette, so `src/index.css` is usable verbatim and the console reads as the
// same product family — `surface-*`, `outline-*`, and the ok/warn/info state
// colours the shared `StatusBadge` resolves against.

const config = {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    container: { center: true, padding: "2rem", screens: { "2xl": "1400px" } },
    extend: {
      fontFamily: {
        sans: ["Inter", "SF Pro Text", "Segoe UI", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        ok: { DEFAULT: "hsl(var(--ok))", foreground: "hsl(var(--ok-foreground))" },
        warn: { DEFAULT: "hsl(var(--warn))", foreground: "hsl(var(--warn-foreground))" },
        info: { DEFAULT: "hsl(var(--info))", foreground: "hsl(var(--info-foreground))" },
        surface: {
          app: "hsl(var(--surface-app))",
          sidebar: "hsl(var(--surface-sidebar))",
          panel: "hsl(var(--surface-panel))",
          header: "hsl(var(--surface-header))",
          toolbar: "hsl(var(--surface-toolbar))",
          input: "hsl(var(--surface-input))",
          hover: "hsl(var(--surface-hover))",
          active: "hsl(var(--surface-active))",
          warn: "hsl(var(--surface-warn))",
          danger: "hsl(var(--surface-danger))",
        },
        outline: {
          subtle: "hsl(var(--outline-subtle))",
          strong: "hsl(var(--outline-strong))",
        },
        icon: {
          muted: "hsl(var(--icon-muted))",
          active: "hsl(var(--icon-active))",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [tailwindcssAnimate],
} satisfies Config;

export default config;
