# Dashboard

Vite + React + TypeScript + Tailwind + react-flow + Recharts. Talks to the Lineage server through a dev proxy (`/api` → `http://127.0.0.1:8000`; override with `LINEAGE_API`).

```bash
npm install
npm run dev        # http://localhost:5173
npm run build      # type-check + production build
```

Pages: Overview, Catalogue, Intake (SSE), Artifact detail, Lineage (revoke + blast radius), Policy (2-of-3), Approvals, Bench.
Bench reads `public/bench-results.json` (ships as labelled sample data; replace with Track D's results).
