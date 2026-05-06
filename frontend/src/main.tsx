import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Amplify } from "aws-amplify";
import "./index.css";
import App from "./App";
import SettingsIndex  from "./settings/SettingsIndex";
import PersonalData   from "./settings/PersonalData";
import Company        from "./settings/Company";
import Plans          from "./settings/Plans";
import GitHub         from "./settings/GitHub";

async function bootstrap() {
  try {
    const resp = await fetch("/config.json", { cache: "no-store" });
    const cfg = await resp.json();

    // Make config globally available to App.tsx and settings pages
    (window as any).__NIAGAROS_CONFIG__ = cfg;

    const poolId   = cfg.COGNITO_USER_POOL_ID as string | undefined;
    const clientId = cfg.COGNITO_CLIENT_ID    as string | undefined;

    if (poolId && clientId) {
      Amplify.configure({
        Auth: {
          Cognito: {
            userPoolId: poolId,
            userPoolClientId: clientId,
            loginWith: { email: true },
          },
        },
      });
    }
  } catch (e) {
    console.warn("Could not load /config.json or configure Amplify Auth:", e);
  }

  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <BrowserRouter>
        <Routes>
          {/* ── Settings module ─────────────────────── */}
          <Route path="/settings"                element={<SettingsIndex />} />
          <Route path="/settings/personal-data"  element={<PersonalData  />} />
          <Route path="/settings/company"        element={<Company       />} />
          <Route path="/settings/plans"          element={<Plans         />} />
          <Route path="/settings/github"         element={<GitHub        />} />

          {/* ── Existing app (login / onboarding / dashboard redirect) ── */}
          <Route path="/*" element={<App />} />
        </Routes>
      </BrowserRouter>
    </React.StrictMode>
  );
}

bootstrap();
