/// <reference types="vite/client" />

// Vite's ambient types: `*.css` side-effect imports, asset imports, and
// `import.meta.env`.
//
// Not needed before TypeScript 7, which stopped inferring a type for
// side-effect imports of non-code modules — so `import "./index.css"` became an
// error rather than a no-op. Every Vite app wants this file; ours had been
// getting by without one.
