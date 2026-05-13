import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// Vite produces a static SPA bundle that is served from `internal/web/static`
// by the Go server. We keep the bundle file names stable (`app.js` /
// `style.css`) so the existing embed path and CI checks (`node --check
// internal/web/static/app.js`) keep working.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  build: {
    outDir: path.resolve(__dirname, "../internal/web/static"),
    emptyOutDir: true,
    target: "es2020",
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: (asset) => {
          if (asset.name && asset.name.endsWith(".css")) return "style.css";
          return "assets/[name]-[hash][extname]";
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: (() => {
      const target = process.env.VITE_API_TARGET || "http://localhost:8080";
      const wsTarget = target.replace(/^http/, "ws");
      return {
        "/api": target,
        "/ws": { target: wsTarget, ws: true },
        "/uploads": target,
      };
    })(),
  },
});
