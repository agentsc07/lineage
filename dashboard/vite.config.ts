import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// Real bench output lives in ../bench; serve it at /bench-data/<file> in dev and ship it with the build.
const BENCH_FILES = ["results.json", "weightspace.json", "reviewer.json"];
const benchData = (): Plugin => ({
  name: "lineage-bench-data",
  configureServer(server) {
    server.middlewares.use("/bench-data", (req, res, next) => {
      const name = (req.url ?? "").replace(/^\//, "").split("?")[0];
      const file = resolve(__dirname, "../bench", name);
      if (!BENCH_FILES.includes(name) || !existsSync(file)) return next();
      res.setHeader("Content-Type", "application/json");
      res.end(readFileSync(file));
    });
  },
  generateBundle() {
    for (const name of BENCH_FILES) {
      const file = resolve(__dirname, "../bench", name);
      if (existsSync(file)) this.emitFile({ type: "asset", fileName: `bench-data/${name}`, source: readFileSync(file) });
    }
  },
});

// The dev server proxies /api to the Lineage server so the browser never hits CORS.
export default defineConfig({
  plugins: [react(), benchData()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.LINEAGE_API ?? "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ""),
      },
    },
  },
});
