import React, { useEffect, useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

// /settings/auditor — issue #266 "Invite Auditors".
//
// Scope for this MVP pass (matching the acceptance-criteria-first approach
// used for #269 and #265): the 5 literal Given/When/Then criteria are
// built and tested here. Auditor profiles/types, watermarked downloads,
// document version control, comment threads, SSO for auditors, and the
// Trust Center / Questionnaire Automation / Ticketing integrations from
// the PVA's broader "Proposed Solution" list are explicitly out of scope
// — see the Eindverslag's afbakening.
//
// Calls a NEW /auditors endpoint (api/auditor_handler.py) that is not yet
// registered on API Gateway — this page won't work against production
// until that backend is deployed, same gap as /settings/team.

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

interface CloudAccount {
  id: string;
  account_name: string | null;
  account_id: string;
}

interface Engagement {
  id: string;
  name: string;
  start_date: string;
  end_date: string;
  active: boolean;
}

interface EvidenceRequest {
  id: string;
  auditor_email: string;
  cloud_account_id: string;
  status: string;
  created_at: string;
}

interface ActivityEntry {
  auditor_email: string;
  action: string;
  details: Record<string, unknown>;
  created_at: string;
}

const describeAction = (action: string) => action.replace(/_/g, " ");

export default function Auditors() {
  const { loading: authLoading, email } = useRequireAuth();
  const [loadState, setLoadState] = useState<"loading" | "loaded" | "error">("loading");
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [orgCloudAccounts, setOrgCloudAccounts] = useState<CloudAccount[]>([]);

  const [name, setName] = useState("");
  const [endDate, setEndDate] = useState("");
  const [selectedAccountIds, setSelectedAccountIds] = useState<string[]>([]);
  const [auditorEmails, setAuditorEmails] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [requestsByEngagement, setRequestsByEngagement] = useState<Record<string, EvidenceRequest[]>>({});
  const [activityByEngagement, setActivityByEngagement] = useState<Record<string, ActivityEntry[]>>({});

  const token = () => localStorage.getItem("niagaros_token") || "";
  const authHeader = () => ({ Authorization: `Bearer ${token()}` });

  const loadEngagements = async () => {
    try {
      const resp = await fetch(`${getApiBase()}/auditors/engagements`, { headers: authHeader(), cache: "no-store" });
      if (!resp.ok) throw new Error(String(resp.status));
      const data = await resp.json();
      setEngagements(data.engagements || []);
      setLoadState("loaded");
    } catch {
      setLoadState("error");
    }
  };

  const loadOrgCloudAccounts = async () => {
    try {
      const resp = await fetch(`${getApiBase()}/team/cloud-accounts`, { headers: authHeader(), cache: "no-store" });
      if (!resp.ok) return;
      const data = await resp.json();
      setOrgCloudAccounts(data.accounts || []);
    } catch {
      // Leave it empty — the picker just has nothing to offer.
    }
  };

  useEffect(() => {
    if (authLoading || !email) return;
    loadEngagements();
    loadOrgCloudAccounts();
  }, [authLoading, email]);

  const toggleAccount = (id: string) => {
    setSelectedAccountIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  };

  const createEngagement = async () => {
    setFormError("");
    if (!name.trim()) { setFormError("Name is required."); return; }
    if (!endDate) { setFormError("End date is required."); return; }
    if (selectedAccountIds.length === 0) { setFormError("Select at least one cloud account."); return; }
    const emails = auditorEmails.split(/[\n,]/).map(e => e.trim()).filter(Boolean);
    if (emails.length === 0) { setFormError("At least one auditor email is required."); return; }

    setSubmitting(true);
    try {
      const resp = await fetch(`${getApiBase()}/auditors/engagements`, {
        method: "POST",
        headers: { ...authHeader(), "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(), end_date: endDate,
          cloud_account_ids: selectedAccountIds, auditor_emails: emails,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) { setFormError(data.error || "Could not create engagement."); return; }
      setName(""); setEndDate(""); setSelectedAccountIds([]); setAuditorEmails("");
      await loadEngagements();
    } catch {
      setFormError("Could not reach the server.");
    } finally {
      setSubmitting(false);
    }
  };

  const loadRequestsAndActivity = async (engagementId: string) => {
    try {
      const [reqResp, actResp] = await Promise.all([
        fetch(`${getApiBase()}/auditors/engagements/${engagementId}/requests`, { headers: authHeader(), cache: "no-store" }),
        fetch(`${getApiBase()}/auditors/engagements/${engagementId}/activity`, { headers: authHeader(), cache: "no-store" }),
      ]);
      const reqData = reqResp.ok ? await reqResp.json() : { requests: [] };
      const actData = actResp.ok ? await actResp.json() : { entries: [] };
      setRequestsByEngagement(prev => ({ ...prev, [engagementId]: reqData.requests || [] }));
      setActivityByEngagement(prev => ({ ...prev, [engagementId]: actData.entries || [] }));
    } catch {
      // Leave whatever was there — the sections just show nothing new.
    }
  };

  const toggleExpand = (engagementId: string) => {
    if (expandedId === engagementId) { setExpandedId(null); return; }
    setExpandedId(engagementId);
    loadRequestsAndActivity(engagementId);
  };

  const resolveRequest = async (engagementId: string, requestId: string, approve: boolean) => {
    await fetch(`${getApiBase()}/auditors/engagements/${engagementId}/requests/${requestId}`, {
      method: "PATCH",
      headers: { ...authHeader(), "Content-Type": "application/json" },
      body: JSON.stringify({ approve }),
    });
    await loadRequestsAndActivity(engagementId);
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
  const badgeStyle = (color: string, bg: string): React.CSSProperties => ({
    fontSize: 10.5, fontWeight: 700, padding: "2px 9px", borderRadius: 4,
    background: bg, color, textTransform: "capitalize",
  });

  return (
    <SettingsLayout
      title="Auditors"
      subtitle="Give auditors time-limited, scoped access to evidence for a specific engagement."
      breadcrumb="Auditors"
      email={email}
    >
      {loadState === "error" && (
        <div style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13 }}>
          Couldn't load audit engagements — the backend for this page isn't deployed yet
          (see docs/internal/architecture/aws/api_inventory.md).
        </div>
      )}

      {/* Create engagement */}
      <div style={cardStyle}>
        <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 14 }}>Create an audit engagement</div>
        <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label style={{ display: "block", fontSize: 11, color: "#6b7280", marginBottom: 5 }}>Name</label>
            <input
              type="text" value={name} onChange={e => setName(e.target.value)}
              placeholder="e.g. Q4 SOC 2 Audit"
              style={{ width: "100%", background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: "9px 12px", color: "#e2e8f0", fontSize: 13 }}
            />
          </div>
          <div>
            <label style={{ display: "block", fontSize: 11, color: "#6b7280", marginBottom: 5 }}>End date</label>
            <input
              type="date" value={endDate} onChange={e => setEndDate(e.target.value)}
              style={{ background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: "9px 12px", color: "#e2e8f0", fontSize: 13 }}
            />
          </div>
        </div>

        <label style={{ display: "block", fontSize: 11, color: "#6b7280", marginBottom: 5 }}>Cloud accounts in scope</label>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
          {orgCloudAccounts.length === 0 ? (
            <span style={{ color: "#4e627a", fontSize: 12.5 }}>No connected cloud accounts yet.</span>
          ) : (
            orgCloudAccounts.map(a => {
              const checked = selectedAccountIds.includes(a.id);
              return (
                <label
                  key={a.id}
                  style={{
                    display: "flex", alignItems: "center", gap: 6, cursor: "pointer",
                    background: checked ? "rgba(239,68,68,0.12)" : "#0d1017",
                    border: `1px solid ${checked ? "rgba(239,68,68,0.4)" : "#1e2433"}`,
                    borderRadius: 8, padding: "6px 12px", fontSize: 12.5, color: "#e2e8f0",
                  }}
                >
                  <input type="checkbox" checked={checked} onChange={() => toggleAccount(a.id)} />
                  {a.account_name || a.account_id}
                </label>
              );
            })
          )}
        </div>

        <label style={{ display: "block", fontSize: 11, color: "#6b7280", marginBottom: 5 }}>
          Auditor emails (one per line or comma-separated)
        </label>
        <textarea
          value={auditorEmails}
          onChange={e => setAuditorEmails(e.target.value)}
          placeholder="auditor@bigfour.com"
          rows={2}
          style={{ width: "100%", background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: "9px 12px", color: "#e2e8f0", fontSize: 13, marginBottom: 12, resize: "vertical" }}
        />

        <button
          onClick={createEngagement}
          disabled={submitting}
          style={{ background: "#ef4444", color: "#fff", border: "none", borderRadius: 8, padding: "9px 20px", fontSize: 13, fontWeight: 600, cursor: submitting ? "default" : "pointer", opacity: submitting ? 0.6 : 1 }}
        >
          {submitting ? "Creating…" : "Create engagement"}
        </button>
        {formError && <div style={{ color: "#f87171", fontSize: 12, marginTop: 10 }}>{formError}</div>}
      </div>

      {/* Engagements list */}
      <div style={cardStyle}>
        <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 14 }}>Engagements ({engagements.length})</div>
        {engagements.length === 0 ? (
          <div style={{ color: "#4e627a", fontSize: 12.5 }}>No audit engagements yet.</div>
        ) : (
          engagements.map(en => (
            <div key={en.id} style={{ borderTop: "1px solid #1a2030", padding: "10px 0" }}>
              <div
                onClick={() => toggleExpand(en.id)}
                style={{ display: "flex", alignItems: "center", gap: 12, cursor: "pointer" }}
              >
                <div style={{ flex: 1 }}>
                  <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 500 }}>{en.name}</div>
                  <div style={{ color: "#4e627a", fontSize: 11.5 }}>ends {en.end_date}</div>
                </div>
                {en.active ? (
                  <span style={badgeStyle("#4ade80", "rgba(22,163,74,0.12)")}>active</span>
                ) : (
                  <span style={badgeStyle("#f87171", "rgba(239,68,68,0.12)")}>closed</span>
                )}
              </div>

              {expandedId === en.id && (
                <div style={{ marginTop: 12, paddingLeft: 4 }}>
                  <div style={{ color: "#9ca3af", fontSize: 12, fontWeight: 700, marginBottom: 6 }}>Evidence requests</div>
                  {(requestsByEngagement[en.id] || []).length === 0 ? (
                    <div style={{ color: "#4e627a", fontSize: 12, marginBottom: 12 }}>No requests yet.</div>
                  ) : (
                    (requestsByEngagement[en.id] || []).map(r => (
                      <div key={r.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 0", fontSize: 12.5 }}>
                        <span style={{ flex: 1, color: "#e2e8f0" }}>{r.auditor_email} — account {r.cloud_account_id.slice(0, 8)}…</span>
                        <span style={badgeStyle(
                          r.status === "approved" ? "#4ade80" : r.status === "denied" ? "#f87171" : "#fbbf24",
                          r.status === "approved" ? "rgba(22,163,74,0.12)" : r.status === "denied" ? "rgba(239,68,68,0.12)" : "rgba(251,191,36,0.12)",
                        )}>{r.status}</span>
                        {r.status === "pending" && (
                          <>
                            <button
                              onClick={() => resolveRequest(en.id, r.id, true)}
                              style={{ background: "none", border: "1px solid rgba(22,163,74,0.4)", color: "#4ade80", borderRadius: 6, padding: "3px 9px", fontSize: 11, cursor: "pointer" }}
                            >Approve</button>
                            <button
                              onClick={() => resolveRequest(en.id, r.id, false)}
                              style={{ background: "none", border: "1px solid #374151", color: "#9ca3af", borderRadius: 6, padding: "3px 9px", fontSize: 11, cursor: "pointer" }}
                            >Deny</button>
                          </>
                        )}
                      </div>
                    ))
                  )}

                  <div style={{ color: "#9ca3af", fontSize: 12, fontWeight: 700, margin: "12px 0 6px" }}>Activity</div>
                  {(activityByEngagement[en.id] || []).length === 0 ? (
                    <div style={{ color: "#4e627a", fontSize: 12 }}>No activity yet.</div>
                  ) : (
                    (activityByEngagement[en.id] || []).map((a, i) => (
                      <div key={i} style={{ fontSize: 12, color: "#4e627a", padding: "3px 0" }}>
                        <span style={{ color: "#e2e8f0" }}>{a.auditor_email}</span> {describeAction(a.action)}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </SettingsLayout>
  );
}
