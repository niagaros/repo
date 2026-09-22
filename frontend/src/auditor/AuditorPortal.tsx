import React, { useEffect, useState } from "react";
import { useRequireAuth } from "../settings/useRequireAuth";

// /auditor — the auditor's own view of issue #266 "Invite Auditors".
//
// Deliberately NOT under /settings and NOT using SettingsLayout: an
// auditor is not a member of the audited organization (see the comment
// at the top of migrations/007_audit_engagements.sql), so the team-facing
// sidebar (Personal Data, Company, Team, ...) makes no sense here. This
// is a standalone page for whoever is currently logged in via the same
// Cognito pool, scoped entirely to their own active engagement.
//
// Known MVP limitation, not a bug: requesting evidence for an account
// outside the current scope requires knowing that account's internal id
// (shared out-of-band by the audited organization's contact) rather than
// browsing a catalog — there is no "all accounts this org might have"
// listing exposed to an auditor, by design (that would leak organization
// structure to someone who isn't a member of it).

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

interface ScopeAccount {
  id: string;
  account_name: string | null;
  account_id: string;
}

interface Engagement {
  id: string;
  organization_id: string;
  name: string;
  end_date: string;
}

interface Evidence {
  account_name: string | null;
  compliance_score: unknown;
  last_scan_at: string | null;
}

export default function AuditorPortal() {
  const { loading: authLoading, email } = useRequireAuth();
  const [loadState, setLoadState] = useState<"loading" | "loaded" | "no_engagement" | "error">("loading");
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [scope, setScope] = useState<ScopeAccount[]>([]);
  const [evidenceByAccount, setEvidenceByAccount] = useState<Record<string, Evidence>>({});
  const [downloadError, setDownloadError] = useState<Record<string, string>>({});

  const [requestAccountId, setRequestAccountId] = useState("");
  const [requesting, setRequesting] = useState(false);
  const [requestMessage, setRequestMessage] = useState("");

  const token = () => localStorage.getItem("niagaros_token") || "";
  const authHeader = () => ({ Authorization: `Bearer ${token()}` });

  const load = async () => {
    try {
      const resp = await fetch(`${getApiBase()}/auditor/scope`, { headers: authHeader(), cache: "no-store" });
      if (resp.status === 401) { setLoadState("no_engagement"); return; }
      if (!resp.ok) throw new Error(String(resp.status));
      const data = await resp.json();
      setEngagement(data.engagement);
      setScope(data.scope || []);
      setLoadState("loaded");
    } catch {
      setLoadState("error");
    }
  };

  useEffect(() => {
    if (authLoading || !email) return;
    load();
  }, [authLoading, email]);

  const downloadEvidence = async (accountId: string) => {
    setDownloadError(prev => ({ ...prev, [accountId]: "" }));
    try {
      const resp = await fetch(`${getApiBase()}/auditor/evidence/${accountId}`, { headers: authHeader(), cache: "no-store" });
      const data = await resp.json();
      if (!resp.ok) {
        setDownloadError(prev => ({ ...prev, [accountId]: data.error || "Could not retrieve evidence." }));
        return;
      }
      setEvidenceByAccount(prev => ({ ...prev, [accountId]: data.compliance_score }));
    } catch {
      setDownloadError(prev => ({ ...prev, [accountId]: "Could not reach the server." }));
    }
  };

  const requestEvidence = async () => {
    setRequestMessage("");
    if (!requestAccountId.trim()) { setRequestMessage("Enter a cloud account id."); return; }
    setRequesting(true);
    try {
      const resp = await fetch(`${getApiBase()}/auditor/evidence-requests`, {
        method: "POST",
        headers: { ...authHeader(), "Content-Type": "application/json" },
        body: JSON.stringify({ cloud_account_id: requestAccountId.trim() }),
      });
      if (!resp.ok) {
        const data = await resp.json();
        setRequestMessage(data.error || "Could not submit the request.");
        return;
      }
      setRequestAccountId("");
      setRequestMessage("Request submitted — you'll see the account here once it's approved.");
    } catch {
      setRequestMessage("Could not reach the server.");
    } finally {
      setRequesting(false);
    }
  };

  if (authLoading || loadState === "loading") return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  const cardStyle: React.CSSProperties = {
    background: "#111827", border: "1px solid #1e2433", borderRadius: 14,
    padding: "20px 24px", marginBottom: 20,
  };

  return (
    <div style={{ minHeight: "100vh", background: "#080b12", fontFamily: "system-ui,-apple-system,sans-serif", padding: "48px 24px" }}>
      <div style={{ maxWidth: 720, margin: "0 auto" }}>
        <div style={{ marginBottom: 8 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: "#ef4444", letterSpacing: "0.15em" }}>AUDITOR PORTAL</span>
        </div>
        <h1 style={{ fontSize: 26, fontWeight: 700, color: "#f1f5f9", margin: "0 0 8px" }}>
          {loadState === "loaded" && engagement ? engagement.name : "Auditor access"}
        </h1>
        {loadState === "loaded" && engagement && (
          <p style={{ fontSize: 13.5, color: "#64748b", margin: "0 0 28px" }}>
            Signed in as {email} — access ends {engagement.end_date}.
          </p>
        )}

        {loadState === "no_engagement" && (
          <div style={{ ...cardStyle, color: "#9ca3af", fontSize: 13.5 }}>
            You don't have an active audit engagement. Access is either not yet granted,
            or the engagement you were assigned to has already ended — in both cases
            there's nothing further to do here.
          </div>
        )}

        {loadState === "error" && (
          <div style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13 }}>
            Couldn't load your access — the backend for this page isn't deployed yet.
          </div>
        )}

        {loadState === "loaded" && (
          <>
            <div style={cardStyle}>
              <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 14 }}>
                Cloud accounts in your scope ({scope.length})
              </div>
              {scope.length === 0 ? (
                <div style={{ color: "#4e627a", fontSize: 12.5 }}>Nothing in scope yet.</div>
              ) : (
                scope.map(a => (
                  <div key={a.id} style={{ borderTop: "1px solid #1a2030", padding: "10px 0" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                      <span style={{ flex: 1, color: "#e2e8f0", fontSize: 13 }}>{a.account_name || a.account_id}</span>
                      <button
                        onClick={() => downloadEvidence(a.id)}
                        style={{ background: "none", border: "1px solid #374151", color: "#9ca3af", borderRadius: 6, padding: "4px 10px", fontSize: 11, cursor: "pointer" }}
                      >
                        View compliance evidence
                      </button>
                    </div>
                    {downloadError[a.id] && (
                      <div style={{ color: "#f87171", fontSize: 12, marginTop: 6 }}>{downloadError[a.id]}</div>
                    )}
                    {evidenceByAccount[a.id] !== undefined && (
                      <pre style={{ background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: 10, marginTop: 8, fontSize: 11.5, color: "#9ca3af", overflowX: "auto" }}>
                        {JSON.stringify(evidenceByAccount[a.id], null, 2)}
                      </pre>
                    )}
                  </div>
                ))
              )}
            </div>

            <div style={cardStyle}>
              <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 4 }}>Request additional evidence</div>
              <div style={{ color: "#4e627a", fontSize: 12, marginBottom: 14 }}>
                Ask the organization for the cloud account id you need, then submit it here
                for approval.
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <input
                  type="text" value={requestAccountId} onChange={e => setRequestAccountId(e.target.value)}
                  placeholder="Cloud account id"
                  style={{ flex: 1, background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: "8px 12px", color: "#e2e8f0", fontSize: 13 }}
                />
                <button
                  onClick={requestEvidence}
                  disabled={requesting}
                  style={{ background: "#ef4444", color: "#fff", border: "none", borderRadius: 8, padding: "8px 18px", fontSize: 13, fontWeight: 600, cursor: requesting ? "default" : "pointer", opacity: requesting ? 0.6 : 1 }}
                >
                  Request
                </button>
              </div>
              {requestMessage && <div style={{ color: "#9ca3af", fontSize: 12, marginTop: 10 }}>{requestMessage}</div>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
