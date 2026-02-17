import React, { useEffect, useState } from "react";
import "./App.css";

type HealthResponse = {
  ok: boolean;
  service: string;
  time: string;
};

function App() {
  const apiBase = process.env.REACT_APP_API_BASE_URL || "";

  const [status, setStatus] = useState<"loading" | "ok" | "error">("loading");
  const [data, setData] = useState<HealthResponse | null>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    const run = async () => {
      if (!apiBase || apiBase.includes("<")) {
        setStatus("error");
        setErr("API not configured (REACT_APP_API_BASE_URL missing).");
        return;
      }

      try {
        const res = await fetch(`${apiBase}/health`);

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
  }, [apiBase]);

  return (
    <div className="App">
      <header className="App-header">
        <h2>Niagaros CSPM Dashboard</h2>

        <p>
          <b>Frontend:</b> Amplify (branch-based CI/CD)
        </p>

        <p>
          <b>API Base URL:</b> {apiBase || "(not set)"}
        </p>

        {status === "loading" && <p>Checking API health...</p>}

        {status === "ok" && data && (
          <div style={{ marginTop: 20 }}>
            <h3 style={{ color: "lime" }}>API STATUS: OK</h3>
            <pre style={{ textAlign: "left" }}>
              {JSON.stringify(data, null, 2)}
            </pre>
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
