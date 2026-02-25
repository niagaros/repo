import React, { useEffect, useState } from "react";
import "./App.css";

type HealthResponse = {
  ok: boolean;
  service: string;
  time: string;
};

type RuntimeConfig = {
  REACT_APP_API_BASE_URL?: string;
  REACT_APP_REGION?: string;
};

function App() {
  const [cfg, setCfg] = useState<RuntimeConfig | null>(null);
  const [status, setStatus] = useState<"loading" | "ok" | "error">("loading");
  const [data, setData] = useState<HealthResponse | null>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    const run = async () => {
      setStatus("loading");
      setErr("");

      try {
        // 1) Load runtime config generated in Amplify build (public/config.json -> /config.json)
        const cfgRes = await fetch("/config.json", { cache: "no-store" });
        if (!cfgRes.ok) {
          setStatus("error");
          setErr(`Config not found: /config.json (HTTP ${cfgRes.status})`);
          return;
        }

        const loadedCfg = (await cfgRes.json()) as RuntimeConfig;
        setCfg(loadedCfg);

        const apiBase = (loadedCfg.REACT_APP_API_BASE_URL || "").trim();
        if (!apiBase || apiBase.includes("<")) {
          setStatus("error");
          setErr("API not configured (REACT_APP_API_BASE_URL missing in /config.json).");
          return;
        }

        // 2) Call API health
        const res = await fetch(`${apiBase}/health`, { cache: "no-store" });
        if (!res.ok) {
          setStatus("error");
          setErr(`API returned HTTP ${res.status}`);
          return;
        }

        const json = (await res.json()) as HealthResponse;
        setData(json);
        setStatus("ok");
      } catch (e: any) {
        setStatus("error");
        setErr(e?.message || "Unknown error");
      }
    };

    run();
  }, []);

  const apiBaseShown =
    cfg?.REACT_APP_API_BASE_URL ? cfg.REACT_APP_API_BASE_URL : "(loaded cfg: no api url)";

  return (
    <div className="App">
      <header className="App-header">
        <h2>Niagaros CSPM Dashboard</h2>

        <p>
          <b>Frontend:</b> Amplify (branch-based CI/CD)
        </p>

        <p>
          <b>Runtime config:</b> /config.json
        </p>

        <p>
          <b>API Base URL:</b> {apiBaseShown}
        </p>

        {status === "loading" && <p>Checking API health...</p>}

        {status === "ok" && data && (
          <div style={{ marginTop: 20 }}>
            <h3 style={{ color: "lime" }}>API STATUS: OK</h3>
            <pre style={{ textAlign: "left" }}>{JSON.stringify(data, null, 2)}</pre>
          </div>
        )}

        {status === "error" && (
          <div style={{ marginTop: 20 }}>
            <h3 style={{ color: "red" }}>API STATUS: ERROR</h3>
            <p>{err}</p>
          </div>
        )}
      </header>
    </div>
  );
}

export default App;
