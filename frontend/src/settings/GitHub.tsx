import React, { useEffect, useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

function getGitHubClientId(): string {
  return (window as any).__NIAGAROS_CONFIG__?.GITHUB_CLIENT_ID || "";
}

const GitHubMark = ({ size = 20, fill = "currentColor" }: { size?: number; fill?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={fill}>
    <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
  </svg>
);

type Status = "loading" | "connected" | "not_connected" | "connecting" | "picking_org";

export default function GitHub() {
  const { loading: authLoading, email } = useRequireAuth();
  const [status, setStatus]         = useState<Status>("loading");
  const [connectedOrg, setConnectedOrg] = useState("");
  const [connectedAt, setConnectedAt]   = useState("");
  const [orgs, setOrgs]             = useState<string[]>([]);
  const [selectedOrg, setSelectedOrg]   = useState("");
  const [error, setError]           = useState("");
  const [saving, setSaving]         = useState(false);

  const token = () => localStorage.getItem("niagaros_token") || "";
  const authHeader = () => ({ Authorization: `Bearer ${token()}` });

  // ── On mount: check existing connection or handle OAuth callback ──────────
  useEffect(() => {
    if (authLoading || !email) return;
    (async () => {
      try {
        const resp = await fetch(`${getApiBase()}/github-integration`, {
          headers: authHeader(),
        });
        const data = await resp.json();

        if (data.connected) {
          setConnectedOrg(data.org_name);
          setConnectedAt(data.connected_at || "");
          setStatus("connected");
          return;
        }

        // GitHub OAuth callback: URL contains ?code=...
        const params = new URLSearchParams(window.location.search);
        const code = params.get("code");
        if (code) {
          window.history.replaceState({}, "", "/settings/github");
          setStatus("connecting");
          await exchangeCode(code);
        } else {
          setStatus("not_connected");
        }
      } catch {
        setStatus("not_connected");
      }
    })();
  }, [authLoading, email]);

  // ── Exchange OAuth code for token, get org list ───────────────────────────
  const exchangeCode = async (code: string) => {
    try {
      const resp = await fetch(`${getApiBase()}/github-connect`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({ code }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "GitHub connection failed");

      const orgList: string[] = data.orgs || [];
      if (orgList.length === 0) {
        setError("No GitHub organizations found. On the GitHub authorization screen, make sure to click \"Grant\" next to your organization — or create one at github.com/organizations/new first.");
        setStatus("not_connected");
      } else if (orgList.length === 1) {
        await saveIntegration(orgList[0]);
      } else {
        setOrgs(orgList);
        setSelectedOrg(orgList[0]);
        setStatus("picking_org");
      }
    } catch (e: any) {
      setError(e.message || "Could not connect to GitHub.");
      setStatus("not_connected");
    }
  };

  // ── Save the chosen org to the database ──────────────────────────────────
  const saveIntegration = async (orgName: string) => {
    setSaving(true);
    try {
      const resp = await fetch(`${getApiBase()}/github-integration`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({ org_name: orgName }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Failed to save");
      setConnectedOrg(orgName);
      setConnectedAt(new Date().toISOString());
      setStatus("connected");
    } catch (e: any) {
      setError(e.message);
      setStatus("not_connected");
    } finally {
      setSaving(false);
    }
  };

  // ── Start GitHub OAuth flow ───────────────────────────────────────────────
  const handleConnect = () => {
    const clientId = getGitHubClientId();
    if (!clientId) {
      setError("GitHub integration is not configured yet. Contact support.");
      return;
    }
    const redirectUri = encodeURIComponent(window.location.origin + "/settings/github");
    const scope = encodeURIComponent("read:org");
    window.location.href =
      `https://github.com/login/oauth/authorize?client_id=${clientId}&scope=${scope}&redirect_uri=${redirectUri}`;
  };

  // ── Disconnect ────────────────────────────────────────────────────────────
  const handleDisconnect = async () => {
    if (!confirm("Disconnect GitHub? Existing scan results will remain in the dashboard.")) return;
    try {
      await fetch(`${getApiBase()}/github-integration`, {
        method: "DELETE",
        headers: authHeader(),
      });
      setConnectedOrg("");
      setStatus("not_connected");
    } catch (e: any) {
      setError(e.message);
    }
  };

  if (authLoading || status === "loading") return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  return (
    <SettingsLayout
      title="GitHub Integration"
      subtitle="Connect your GitHub organization to scan for CIS GitHub Benchmark v1.0.0 compliance."
      breadcrumb="GitHub"
      email={email}
    >
      {error && (
        <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, padding: "10px 14px", marginBottom: 20, color: "#fca5a5", fontSize: 13 }}>
          {error}
          <button onClick={() => setError("")} style={{ float: "right", background: "none", border: "none", color: "#fca5a5", cursor: "pointer", fontSize: 14, lineHeight: 1 }}>×</button>
        </div>
      )}

      {/* ── Main card ───────────────────────────────────────────────────────── */}
      <div style={{ background: "#111827", border: "1px solid #1e2433", borderRadius: 14, padding: "28px 32px", maxWidth: 600, marginBottom: 16 }}>

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 24 }}>
          <div style={{ width: 44, height: 44, borderRadius: 10, background: "#0d1117", border: "1px solid #30363d", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <GitHubMark size={24} fill="#f0f6fc" />
          </div>
          <div>
            <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 15 }}>GitHub</div>
            <div style={{ color: "#4e627a", fontSize: 12 }}>CIS GitHub Benchmark v1.0.0 — 22 automated checks</div>
          </div>
          {status === "connected" && (
            <span style={{ marginLeft: "auto", fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 4, background: "rgba(22,163,74,0.12)", color: "#4ade80", border: "1px solid rgba(22,163,74,0.3)" }}>
              Connected
            </span>
          )}
        </div>

        {/* ── Connected state ──────────────────────────────────────────────── */}
        {status === "connected" && (
          <>
            <div style={{ background: "#0d0f14", border: "1px solid #1e2433", borderRadius: 8, padding: "14px 16px", marginBottom: 20 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#4e627a", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 8 }}>Connected Organization</div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <GitHubMark size={15} fill="#6b7280" />
                <span style={{ color: "#f1f5f9", fontSize: 14, fontWeight: 600 }}>{connectedOrg}</span>
              </div>
              {connectedAt && (
                <div style={{ fontSize: 11, color: "#374151", marginTop: 6 }}>
                  Connected {new Date(connectedAt).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
                </div>
              )}
            </div>
            <div style={{ background: "rgba(22,163,74,0.06)", border: "1px solid rgba(22,163,74,0.15)", borderRadius: 8, padding: "10px 14px", marginBottom: 20, fontSize: 12.5, color: "#4ade80" }}>
              Findings from <strong>{connectedOrg}</strong> will appear in your dashboard on the next scan. Click "Scan Now" on the dashboard to run immediately.
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button
                onClick={handleDisconnect}
                style={{ background: "transparent", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, color: "#ef4444", fontSize: 13, fontWeight: 600, padding: "8px 18px", cursor: "pointer" }}
              >
                Disconnect GitHub
              </button>
            </div>
          </>
        )}

        {/* ── Not connected state ──────────────────────────────────────────── */}
        {status === "not_connected" && (
          <>
            <p style={{ color: "#4e627a", fontSize: 13, lineHeight: 1.7, marginBottom: 20 }}>
              Connect your GitHub organization to scan all repositories against the CIS GitHub Benchmark.
              Findings will appear in your dashboard alongside your AWS security posture.
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 24 }}>
              {["Branch protection", "MFA enforcement", "Secret scanning", "Dependabot alerts", "Org permissions"].map(f => (
                <span key={f} style={{ fontSize: 11, padding: "3px 10px", borderRadius: 20, background: "rgba(239,68,68,0.06)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.18)" }}>
                  {f}
                </span>
              ))}
            </div>
            <button
              onClick={handleConnect}
              style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: 8, color: "#f0f6fc", fontSize: 13, fontWeight: 600, padding: "10px 20px", cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 8, transition: "border-color 0.15s" }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = "#6e7681")}
              onMouseLeave={e => (e.currentTarget.style.borderColor = "#30363d")}
            >
              <GitHubMark size={16} />
              Connect GitHub Organization
            </button>
          </>
        )}

        {/* ── Connecting (exchanging code) ─────────────────────────────────── */}
        {status === "connecting" && (
          <div style={{ color: "#9ca3af", fontSize: 13, padding: "16px 0", display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 16, height: 16, borderRadius: "50%", border: "2px solid #374151", borderTopColor: "#ef4444", animation: "spin 0.8s linear infinite" }} />
            Connecting to GitHub…
          </div>
        )}

        {/* ── Org picker (multiple orgs) ───────────────────────────────────── */}
        {status === "picking_org" && (
          <>
            <p style={{ color: "#9ca3af", fontSize: 13, marginBottom: 14 }}>
              Select which organization to connect:
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 20 }}>
              {orgs.map(org => (
                <div
                  key={org}
                  onClick={() => setSelectedOrg(org)}
                  style={{
                    background: selectedOrg === org ? "rgba(239,68,68,0.08)" : "#0d0f14",
                    border: `1px solid ${selectedOrg === org ? "rgba(239,68,68,0.4)" : "#1e2433"}`,
                    borderRadius: 8, padding: "10px 14px", cursor: "pointer",
                    display: "flex", alignItems: "center", gap: 10,
                    transition: "all 0.12s",
                  }}
                >
                  <GitHubMark size={14} fill={selectedOrg === org ? "#ef4444" : "#6b7280"} />
                  <span style={{ color: selectedOrg === org ? "#f1f5f9" : "#9ca3af", fontSize: 13, fontWeight: selectedOrg === org ? 600 : 400 }}>{org}</span>
                  {selectedOrg === org && <span style={{ marginLeft: "auto", color: "#ef4444", fontSize: 16 }}>✓</span>}
                </div>
              ))}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button
                onClick={() => selectedOrg && saveIntegration(selectedOrg)}
                disabled={!selectedOrg || saving}
                style={{ background: "#ef4444", border: "none", borderRadius: 8, color: "#fff", fontSize: 13, fontWeight: 600, padding: "10px 24px", cursor: (!selectedOrg || saving) ? "not-allowed" : "pointer", opacity: (!selectedOrg || saving) ? 0.6 : 1, transition: "opacity 0.15s" }}
              >
                {saving ? "Connecting…" : "Connect Organization"}
              </button>
            </div>
          </>
        )}
      </div>

      {/* ── What gets scanned ───────────────────────────────────────────────── */}
      {status !== "connected" && (
        <div style={{ background: "#111827", border: "1px solid #1e2433", borderRadius: 14, padding: "20px 28px", maxWidth: 600 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#374151", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 14 }}>
            What gets scanned (22 checks)
          </div>
          {[
            ["Branch protection", "Force push prevention, 2+ reviewers required, admin enforcement, linear history"],
            ["Code review", "CODEOWNERS required, stale review dismissal, conversation resolution"],
            ["MFA enforcement", "Two-factor auth for all members and outside collaborators"],
            ["Secret scanning", "Automatic detection of credentials committed to repositories"],
            ["Dependency alerts", "Dependabot vulnerability alerts on all repositories"],
            ["Org governance", "Repository creation/deletion controls, default permissions, verified domain"],
          ].map(([title, desc]) => (
            <div key={title} style={{ display: "flex", gap: 10, padding: "7px 0", borderBottom: "1px solid #1a2030" }}>
              <span style={{ color: "#16a34a", fontSize: 12, flexShrink: 0, marginTop: 2 }}>✓</span>
              <div>
                <span style={{ color: "#d1d5db", fontSize: 12.5, fontWeight: 600 }}>{title}</span>
                <span style={{ color: "#4e627a", fontSize: 12 }}> — {desc}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </SettingsLayout>
  );
}
