import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built files go into the Python package so the API container serves them.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "../backend/dmarc/static", emptyOutDir: true, sourcemap: false, chunkSizeWarningLimit: 1200 },
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:8080", "/auth": "http://localhost:8080" },
  },
});
