import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// Real bench output lives in ../bench; serve it at /bench-data/<file> in dev and ship it with the build.
const BENCH_FILES = ["results.json", "results_final.json", "weightspace.json", "reviewer.json", "cost_log.csv"];
const benchData = (): Plugin => ({
  name: "lineage-bench-data",
  configureServer(server) {
    server.middlewares.use("/bench-data", (req, res, next) => {
      const name = (req.url ?? "").replace(/^\//, "").split("?")[0];
      const file = resolve(__dirname, "../bench", name);
      if (!BENCH_FILES.includes(name) || !existsSync(file)) return next();
      res.setHeader("Content-Type", name.endsWith(".csv") ? "text/csv" : "application/json");
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

// The "Load sample" menu: examples/make_dashboard_samples.py writes the files, LINEAGE_SAMPLES_DIR points here (dev only).
const samples = (): Plugin => ({
  name: "lineage-samples",
  configureServer(server) {
    server.middlewares.use("/samples", (req, res, next) => {
      const dir = process.env.LINEAGE_SAMPLES_DIR;
      const name = decodeURIComponent((req.url ?? "").replace(/^\//, "").split("?")[0]);
      if (!dir || name.includes("..") || name.includes("/")) return next();
      const file = resolve(dir, name);
      if (!existsSync(file)) return next();
      res.setHeader("Content-Type", name.endsWith(".json") ? "application/json" : "application/octet-stream");
      res.end(readFileSync(file));
    });
  },
});

// Demo only: examples/run_dashboard_demo.sh sets LINEAGE_DEMO_TOKENS to its tokens file so the page can offer "switch user" without pasting tokens.
const demoUsers = (): Plugin => ({
  name: "lineage-demo-users",
  configureServer(server) {
    server.middlewares.use("/demo-users.json", (_req, res, next) => {
      const f = process.env.LINEAGE_DEMO_TOKENS;
      if (!f || !existsSync(f)) return next();
      res.setHeader("Content-Type", "application/json");
      res.end(readFileSync(f));
    });
  },
});

// The dev server proxies /api to the Lineage server so the browser never hits CORS.
export default defineConfig({
  plugins: [react(), benchData(), samples(), demoUsers()],
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
