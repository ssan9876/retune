/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  // The Go binary embeds the build, and go:embed can only reach files inside
  // its own package directory, so build straight into that package. The
  // directory is not emptied because it holds a tracked .gitkeep that keeps
  // go:embed working before the console has ever been built; the prebuild
  // script clears the old hashed assets instead.
  build: { outDir: "../internal/server/console/dist", emptyOutDir: false },
  server: {
    proxy: {
      // `npm run dev` talks to a locally running retune-server.
      "/api": {
        // RETUNE_DEV_PROXY points at a locally running retune-server.
        target: process.env.RETUNE_DEV_PROXY ?? "https://localhost:8443",
        changeOrigin: true,
        secure: false, // the server uses its own self-signed certificate
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    css: false,
  },
});
