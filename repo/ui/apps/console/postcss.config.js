// Tailwind 4 ships its PostCSS integration as its own package, and folds
// autoprefixer in — so both changes here are the v4 shape, not a preference.
export default {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};
