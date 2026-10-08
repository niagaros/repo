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

// Issue #265, criterion 6: role and permission changes with timestamps and
// actor information. The admin side was built with #265; this is the
// auditor-facing half, which had to wait until the auditor role existed.
interface AuditLogEntry {
  action: string;
  created_at: string;
  actor_email: string | null;
  target_email: string | null;
  details: Record<string, unknown> | null;
}

interface Evidence {
  account_name: string | null;
  compliance_score: unknown;
  last_scan_at: string | null;
}

// What an auditor actually does with this screen is write it down: which
// account, measured when, retrieved when, by whom. So it is laid out as a
// record to be cited rather than a dashboard to be skimmed — labelled rows,
// one value each, in a fixed order.
//
// The score bar is deliberately NOT colour-coded by how good the number is.
// Nobody has defined what counts as a passing score, so colouring 77 green or
// red would be the interface inventing a verdict the data does not support.
// It uses the same accent as the onboarding progress bar, so it reads as a
// measurement. The number is always written out beside it, never colour alone.
const ACCENT = "#ef4444";

interface ComplianceScore {
  score?: number;
  total?: number;
  passed?: number;
  failed?: number;
}

function asScore(value: unknown): ComplianceScore | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  const num = (x: unknown) => (typeof x === "number" ? x : undefined);
  return { score: num(v.score), total: num(v.total), passed: num(v.passed), failed: num(v.failed) };
}

// The database stores last_scan_at without a timezone, so it is shown as
// recorded rather than converted — a converted timestamp in an evidence
// record is a claim about a timezone nobody verified.
function tidyTimestamp(value: string | null): string {
  if (!value) return "not recorded";
  return value.replace("T", " ").replace(/\.\d+$/, "");
}

function RecordRow({ label, value, strong }: { label: string; value: React.ReactNode; strong?: boolean }) {
  return (
    <div style={{ display: "flex", gap: 16, padding: "7px 0", borderTop: "1px solid #151b28" }}>
      <span style={{ flex: "0 0 170px", color: "#6b7280", fontSize: 12 }}>{label}</span>
      <span style={{ color: strong ? "#f1f5f9" : "#cbd5e1", fontSize: 12.5, fontWeight: strong ? 700 : 400 }}>
        {value}
      </span>
    </div>
  );
}

function EvidenceRecord({ account, evidence, retrievedBy, retrievedAt }: {
  account: ScopeAccount;
  evidence: Evidence;
  retrievedBy: string;
  retrievedAt: string;
}) {
  const s = asScore(evidence.compliance_score);
  const pct = typeof s?.score === "number" ? Math.max(0, Math.min(100, s.score)) : null;

  return (
    <div style={{ background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: "14px 16px", marginTop: 10 }}>
      <div style={{ color: "#f1f5f9", fontSize: 12.5, fontWeight: 700, marginBottom: 12 }}>
        Compliance evidence — {evidence.account_name || account.account_name || "unnamed account"}
        <span style={{ color: "#4e627a", fontWeight: 400 }}> · {account.account_id}</span>
      </div>

      {pct === null ? (
        <div style={{ color: "#6b7280", fontSize: 12.5, paddingBottom: 10 }}>
          No compliance score has been recorded for this account yet.
        </div>
      ) : (
        <div style={{ marginBottom: 14 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 7 }}>
            <span style={{ color: "#f1f5f9", fontSize: 26, fontWeight: 700, lineHeight: 1 }}>{pct}</span>
            <span style={{ color: "#6b7280", fontSize: 12 }}>/ 100 compliance score</span>
          </div>
          <div
            role="img"
            aria-label={`Compliance score ${pct} out of 100`}
            style={{ height: 6, background: "#1a2030", borderRadius: 3, overflow: "hidden", maxWidth: 320 }}
          >
            <div style={{ height: "100%", width: `${pct}%`, background: ACCENT, borderRadius: 3 }} />
          </div>
        </div>
      )}

      {s && (
        <>
          <RecordRow label="Checks performed" value={s.total ?? "—"} />
          <RecordRow label="Passed" value={s.passed ?? "—"} />
          <RecordRow label="Failed" value={s.failed ?? "—"} strong={!!s.failed} />
        </>
      )}

      <div style={{ height: 10 }} />
      <RecordRow label="Measured at" value={tidyTimestamp(evidence.last_scan_at)} />
      <RecordRow label="Retrieved by" value={retrievedBy} />
      <RecordRow label="Retrieved at" value={retrievedAt} />

      <div style={{ color: "#4e627a", fontSize: 11, marginTop: 10, lineHeight: 1.5 }}>
        This retrieval has been recorded in the audited organization's activity log.
      </div>
    </div>
  );
}

export default function AuditorPortal() {
  const { loading: authLoading, email } = useRequireAuth();
  const [loadState, setLoadState] = useState<"loading" | "loaded" | "no_engagement" | "error">("loading");
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [scope, setScope] = useState<ScopeAccount[]>([]);
  const [evidenceByAccount, setEvidenceByAccount] = useState<Record<string, Evidence>>({});
  const [downloadError, setDownloadError] = useState<Record<string, string>>({});
  const [auditLog, setAuditLog] = useState<AuditLogEntry[] | null>(null);
  const [auditLogError, setAuditLogError] = useState("");
  // Shown in the record itself: an auditor cites when they obtained
  // evidence, not just when it was measured.
  const [retrievedAt, setRetrievedAt] = useState<Record<string, string>>({});

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

  // Fetched on demand rather than on load: reading it is recorded as an
  // auditor action, so it should happen because the auditor asked, not
  // because the page opened.
  const loadAuditLog = async () => {
    setAuditLogError("");
    try {
      const resp = await fetch(`${getApiBase()}/auditor/audit-log`, { headers: authHeader(), cache: "no-store" });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setAuditLogError(data.error || "Could not retrieve the access log.");
        return;
      }
      const data = await resp.json();
      setAuditLog(data.entries || []);
    } catch {
      setAuditLogError("Could not reach the server.");
    }
  };

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
      setRetrievedAt(prev => ({ ...prev, [accountId]: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC" }));
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
            We couldn't load your access. Please try again, or get in touch with
            the organization that invited you.
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
                      <EvidenceRecord
                        account={a}
                        evidence={evidenceByAccount[a.id]}
                        retrievedBy={email}
                        retrievedAt={retrievedAt[a.id] || ""}
                      />
                    )}
                  </div>
                ))
              )}
            </div>

            <div style={cardStyle}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14 }}>Access log</div>
                  <div style={{ color: "#4e627a", fontSize: 12, marginTop: 4 }}>
                    Every role, permission and membership change in this organization, with
                    who made it and when.
                  </div>
                </div>
                {auditLog === null && (
                  <button
                    onClick={loadAuditLog}
                    style={{ background: "none", border: "1px solid #374151", color: "#9ca3af", borderRadius: 6, padding: "4px 10px", fontSize: 11, cursor: "pointer", whiteSpace: "nowrap" }}
                  >
                    View access log
                  </button>
                )}
              </div>

              {auditLogError && (
                <div style={{ color: "#f87171", fontSize: 12, marginTop: 8 }}>{auditLogError}</div>
              )}

              {auditLog !== null && (
                auditLog.length === 0 ? (
                  <div style={{ color: "#4e627a", fontSize: 12.5, marginTop: 10 }}>
                    Nothing has been changed in this organization yet.
                  </div>
                ) : (
                  <div style={{ marginTop: 10 }}>
                    {auditLog.map((e, i) => (
                      <div key={i} style={{ display: "flex", gap: 14, padding: "7px 0", borderTop: "1px solid #151b28", fontSize: 12.5 }}>
                        <span style={{ flex: "0 0 150px", color: "#6b7280", fontSize: 12 }}>
                          {e.created_at.replace("T", " ").replace(/\.\d+.*$/, "")}
                        </span>
                        <span style={{ flex: "0 0 150px", color: "#f1f5f9", fontWeight: 500 }}>
                          {e.action.replace(/_/g, " ")}
                        </span>
                        <span style={{ flex: 1, color: "#cbd5e1" }}>
                          {e.actor_email || "unknown"}
                          {e.target_email && <span style={{ color: "#4e627a" }}> &rarr; {e.target_email}</span>}
                        </span>
                      </div>
                    ))}
                    <div style={{ color: "#4e627a", fontSize: 11, marginTop: 10, lineHeight: 1.5 }}>
                      Opening this log has been recorded in the organization's activity log.
                    </div>
                  </div>
                )
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
