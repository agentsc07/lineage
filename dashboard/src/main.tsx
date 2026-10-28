import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "@fontsource-variable/inter-tight";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./index.css";
import Layout from "./components/Layout";
import Overview from "./pages/Overview";
import Catalogue from "./pages/Catalogue";
import Intake from "./pages/Intake";
import ArtifactPage from "./pages/ArtifactDetail";
import GraphPage from "./pages/LineageGraph";
import Policy from "./pages/Policy";
import Approvals from "./pages/Approvals";
import Bench from "./pages/Bench";
import TrustedPublishers from "./pages/TrustedPublishers";
import Federated from "./pages/Federated";
import NotFound from "./pages/NotFound";
import Monitor from "./pages/Monitor";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="catalogue" element={<Catalogue />} />
          <Route path="intake/:jobId?" element={<Intake />} />
          <Route path="artifacts/:id" element={<ArtifactPage />} />
          <Route path="graph" element={<GraphPage />} />
          <Route path="graph/:id" element={<GraphPage />} />
          <Route path="policy" element={<Policy />} />
          <Route path="approvals" element={<Approvals />} />
          <Route path="bench" element={<Bench />} />
          <Route path="publishers" element={<TrustedPublishers />} />
          <Route path="federated" element={<Federated />} />
          <Route path="monitor" element={<Monitor />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);
