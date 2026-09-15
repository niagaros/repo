import React, { useEffect, useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";
import AwsConnectWizard from "./shared/AwsConnectWizard";

// /settings/infrastructure — issue #269 "Integrate Cloud Infrastructure".
//
// Scope for this MVP pass (per stage plan, agreed 10 sept 2026):
//   - AWS is the only provider that actually connects.
//   - Other providers are shown as "In progress" so the page reflects the
//     intended multi-cloud shape of the epic without pretending they work.
//   - Reuses the existing POST /onboard backend (no backend changes yet —
//     that Lambda still lives outside this repo, see docs/internal/architecture/aws/api_inventory.md).

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

type Status = "loading" | "connected" | "disconnected" | "not_connected" | "connecting";

interface Provider {
  id: string;
  name: string;
  icon: string;
  available: boolean;
}

const PROVIDERS: Provider[] = [
  { id: "aws",   name: "AWS",              icon: "☁️", available: true },
  { id: "azure", name: "Azure",            icon: "🔷", available: false },
  { id: "gcp",   name: "Google Cloud",     icon: "🌐", available: false },
  { id: "oci",   name: "Oracle Cloud",     icon: "🟥", available: false },
  { id: "ibm",   name: "IBM Cloud",        icon: "🔵", available: false },
  { id: "eu",    name: "EU Sovereign Cloud", icon: "🇪🇺", available: false },
];

export default function Infrastructure() {
  const { loading: authLoading, email } = useRequireAuth();
  const [status, setStatus]           = useState<Status>("loading");
  const [awsAccountId, setAwsAccountId] = useState("");

  const token = () => localStorage.getItem("niagaros_token") || "";
  const authHeader = () => ({ Authorization: `Bearer ${token()}` });

  useEffect(() => {
    if (authLoading || !email) return;
    (async () => {
      try {
        const resp = await fetch(`${getApiBase()}/get-dashboard-data?email=${encodeURIComponent(email)}`, {
          cache: "no-store",
          headers: authHeader(),
        });
        const data = await resp.json();
        if (data.needs_onboarding) {
          setStatus("not_connected");
        } else {
          setAwsAccountId(data.aws_account_id || data.accounts?.[0]?.aws_account_id || "");
          // issue #269, acceptance criterion #4: a scan that hit a revoked/
          // deleted cross-account role flips cloud_accounts.status to
          // 'disconnected' server-side (see api/lambda_handler.py). Surface
          // that here instead of silently claiming everything is fine.
          setStatus(data.status === "disconnected" ? "disconnected" : "connected");
        }
      } catch {
        setStatus("not_connected");
      }
    })();
  }, [authLoading, email]);

  if (authLoading || status === "loading") return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  // The connect flow re-uses the exact same full-screen wizard as first-login
  // onboarding — same steps, same backend call. On completion we just flip
  // back to the settings view instead of redirecting to the dashboard.
  if (status === "connecting") {
    return <AwsConnectWizard email={email} onComplete={() => setStatus("connected")} />;
  }

  const ProviderGrid = () => (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(150px, 1fr))", gap: 10, marginBottom: 24 }}>
      {PROVIDERS.map(p => {
        const isAws = p.id === "aws";
        const connected = isAws && status === "connected";
        const disconnected = isAws && status === "disconnected";
        return (
          <div
            key={p.id}
            onClick={() => { if (isAws && (status === "not_connected" || status === "disconnected")) setStatus("connecting"); }}
            style={{
              background: "#111827",
              border: `1px solid ${connected ? "rgba(22,163,74,0.35)" : disconnected ? "rgba(239,68,68,0.4)" : "#1e2433"}`,
              borderRadius: 10, padding: "14px 12px", textAlign: "center",
              cursor: isAws && (status === "not_connected" || status === "disconnected") ? "pointer" : "default",
              opacity: p.available ? 1 : 0.5,
            }}
          >
            <div style={{ fontSize: 22, marginBottom: 6 }}>{p.icon}</div>
            <div style={{ color: "#e2e8f0", fontSize: 12.5, fontWeight: 600, marginBottom: 4 }}>{p.name}</div>
            {connected ? (
              <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4, background: "rgba(22,163,74,0.12)", color: "#4ade80", border: "1px solid rgba(22,163,74,0.3)" }}>Connected</span>
            ) : disconnected ? (
              <span style={{ fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4, background: "rgba(239,68,68,0.12)", color: "#f87171", border: "1px solid rgba(239,68,68,0.3)" }}>Reconnect needed</span>
            ) : p.available ? (
              <span style={{ fontSize: 10, color: "#ef4444", fontWeight: 600 }}>Click to connect</span>
            ) : (
              <span style={{ fontSize: 10, color: "#4e627a" }}>In progress</span>
            )}
          </div>
        );
      })}
    </div>
  );

  return (
    <SettingsLayout
      title="Cloud Infrastructure"
      subtitle="Connect your cloud accounts so Niagaros can continuously scan for misconfigurations and compliance gaps."
      breadcrumb="Cloud Infrastructure"
      email={email}
    >
      <ProviderGrid />

      {status === "not_connected" && (
        <div style={{ background: "#111827", border: "1px solid #1e2433", borderRadius: 14, padding: "24px 28px", maxWidth: 600 }}>
          <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 15, marginBottom: 8 }}>No cloud account connected yet</div>
          <p style={{ color: "#4e627a", fontSize: 13, lineHeight: 1.7, marginBottom: 16 }}>
            Connect an AWS account to start scanning for CIS AWS Benchmark, SOC 2, ISO 27001 and other
            framework compliance. Niagaros only requests read-only access via a cross-account IAM role —
            no credentials are ever shared directly.
          </p>
          <button
            onClick={() => setStatus("connecting")}
            style={{ background: "#ef4444", color: "#fff", border: "none", borderRadius: 8, padding: "10px 22px", fontSize: 13, fontWeight: 600, cursor: "pointer" }}
          >
            Connect AWS Account
          </button>
        </div>
      )}

      {status === "disconnected" && (
        <div style={{ background: "#111827", border: "1px solid rgba(239,68,68,0.4)", borderRadius: 14, padding: "24px 28px", maxWidth: 600 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
            <span style={{ fontSize: 20 }}>⚠️</span>
            <div>
              <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14 }}>AWS Account</div>
              {awsAccountId && <div style={{ color: "#4e627a", fontSize: 12 }}>{awsAccountId}</div>}
            </div>
            <span style={{ marginLeft: "auto", fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 4, background: "rgba(239,68,68,0.12)", color: "#f87171", border: "1px solid rgba(239,68,68,0.3)" }}>
              Disconnected
            </span>
          </div>
          <p style={{ color: "#4e627a", fontSize: 12.5, lineHeight: 1.7, marginBottom: 16 }}>
            Niagaros could no longer access this account — the cross-account IAM role may have been
            deleted or its trust policy changed. Scanning has been paused so no stale results are shown.
            We've emailed the account owner; you can also reconnect right away below.
          </p>
          <button
            onClick={() => setStatus("connecting")}
            style={{ background: "#ef4444", color: "#fff", border: "none", borderRadius: 8, padding: "10px 22px", fontSize: 13, fontWeight: 600, cursor: "pointer" }}
          >
            Reconnect AWS Account
          </button>
        </div>
      )}

      {status === "connected" && (
        <div style={{ background: "#111827", border: "1px solid #1e2433", borderRadius: 14, padding: "24px 28px", maxWidth: 600 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
            <span style={{ fontSize: 20 }}>☁️</span>
            <div>
              <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14 }}>AWS Account</div>
              {awsAccountId && <div style={{ color: "#4e627a", fontSize: 12 }}>{awsAccountId}</div>}
            </div>
            <span style={{ marginLeft: "auto", fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 4, background: "rgba(22,163,74,0.12)", color: "#4ade80", border: "1px solid rgba(22,163,74,0.3)" }}>
              Connected
            </span>
          </div>
          <p style={{ color: "#4e627a", fontSize: 12.5, lineHeight: 1.7, margin: 0 }}>
            Niagaros accesses this account through a read-only, cross-account IAM role (SecurityAudit +
            ReadOnlyAccess). To disconnect or rotate access, contact support — self-service management
            isn't available yet.
          </p>
        </div>
      )}
    </SettingsLayout>
  );
}
