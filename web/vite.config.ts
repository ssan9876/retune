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
      "/api": { target: "https://localhost:8443", changeOrigin: true, secure: false },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    css: false,
  },
});
