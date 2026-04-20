import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// Vite dev server runs on 5173 and proxies /api/* to the Rust server on
// 5174 — that's the dev split documented in dashboard/README.md. In
// release builds (Phase 4b) the Rust binary embeds the bundled assets
// and serves them itself, so the proxy isn't needed in production.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:5174",
    },
  },
});
