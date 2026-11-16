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
  total_checks: number | null;
  passed: number | null;
  failed: number | null;
  by_severity: Record<string, { passed?: number; failed?: number }> | null;
  measured_at: string | null;
  snapshot_type: string | null;
}

// What an auditor actually does with this screen is write it down: which
// account, measured when, retrieved when, by whom. So it is laid out as a
// record to be cited rather than a dashboard to be skimmed — labelled rows,
// one value each, in a fixed order.
//
// There is deliberately no single score here any more. The record used to
// open with a number out of 100, taken from a column that turned out to hold
// whatever the last collector wrote. On 20 October that produced a record
// stating "no compliance score has been recorded" directly above a count of
// 76 checks with 8 failures — two answers on one screen.
//
// Counts come from one scan and mean one thing, and a derived percentage
// would add nothing: nobody has defined what a passing score is, so putting
// one at the top would have the interface deliver a verdict the data does not
// support. What an auditor needs is how many checks ran, how many failed, and
// how serious those failures were.
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#64748b",
};

// The record is built for the screen but has to survive leaving it. Filing
// evidence is the whole job, so the one thing an auditor will do with this
// card is keep a copy of it — and a screenshot of a dark web page is a poor
// thing to put in a dossier.
//
// Rather than a second rendering path on the server (a PDF library in the
// Lambda package, a second endpoint, its own tests, and a second copy of this
// layout to keep in step), the card prints itself. The rules below hide the
// rest of the portal, turn the dark palette into ink on white, and drop the
// button from the page. What comes out of Ctrl+P — or of "Save as PDF", which
// every current browser offers in that same dialog — is the record the auditor
// just read, on one sheet, carrying the account, both timestamps and who
// retrieved it.
//
// !important throughout, because every colour on this page is an inline style
// and a stylesheet only outranks those when it is marked.
const PRINT_STYLES = `
@media print {
  @page { margin: 18mm; }
  body { background: #fff !important; }
  body * { visibility: hidden !important; }
  .ev-printing, .ev-printing * { visibility: visible !important; }
  .ev-printing {
    position: absolute !important; left: 0 !important; top: 0 !important;
    width: 100% !important; margin: 0 !important; padding: 0 !important;
    background: #fff !important; border: none !important;
  }
  .ev-printing .ev-ink { color: #000 !important; }
  .ev-printing .ev-muted { color: #3f3f46 !important; }
  .ev-printing .ev-rule { border-top-color: #d4d4d8 !important; }
  .ev-printing .ev-track { background: #e4e4e7 !important; }
  .ev-printing .ev-track, .ev-printing .ev-bar {
    -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important;
  }
  .ev-noprint { display: none !important; }
}
`;

// Shown as recorded, never converted: a converted timestamp in an evidence
// record is a claim about a timezone nobody verified.
//
// generated_at is a timestamptz, so it arrives as "2026-10-15 12:58:46.095272+00:00".
// Only the microseconds are dropped — the offset stays, because it is what
// makes the moment unambiguous to whoever reads the record later. The earlier
// version stripped a fraction only at the end of the string, which silently
// did nothing once the offset was there.
function tidyTimestamp(value: string | null): string {
  if (!value) return "not recorded";
  return value.replace("T", " ").replace(/\.\d+/, "");
}

function RecordRow({ label, value, strong }: { label: string; value: React.ReactNode; strong?: boolean }) {
  return (
    <div className="ev-rule" style={{ display: "flex", gap: 16, padding: "7px 0", borderTop: "1px solid #151b28" }}>
      <span className="ev-muted" style={{ flex: "0 0 170px", color: "#6b7280", fontSize: 12 }}>{label}</span>
      <span className={strong ? "ev-ink" : "ev-muted"} style={{ color: strong ? "#f1f5f9" : "#cbd5e1", fontSize: 12.5, fontWeight: strong ? 700 : 400 }}>
        {value}
      </span>
    </div>
  );
}

// Bars are scaled against the worst severity rather than against the total,
// because the counts that matter here are small: one critical failure out of
// 118 checks is invisible on a bar drawn to scale, and it is the single most
// important line on the card. Scaled this way the rows still read in order of
// seriousness, and the exact number sits beside every bar, so nothing has to
// be judged by eye.
function SeverityBar({ level, failed, widest }: { level: string; failed: number; widest: number }) {
  const pct = widest > 0 && failed > 0 ? Math.max(8, (failed / widest) * 100) : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "3.5px 0" }}>
      <span className="ev-muted" style={{ flex: "0 0 76px", color: "#6b7280", fontSize: 10, letterSpacing: "0.09em", fontWeight: 700 }}>
        {level}
      </span>
      <div className="ev-track" style={{ flex: 1, height: 7, background: "#151b28", borderRadius: 4, overflow: "hidden" }}>
        {failed > 0 && (
          <div className="ev-bar" style={{ width: `${pct}%`, height: "100%", background: SEVERITY_COLOR[level], borderRadius: 4 }} />
        )}
      </div>
      <span className={failed > 0 ? "ev-ink" : "ev-muted"} style={{ flex: "0 0 26px", textAlign: "right", color: failed > 0 ? "#f1f5f9" : "#4e627a", fontSize: 12.5, fontWeight: failed > 0 ? 700 : 400 }}>
        {failed}
      </span>
    </div>
  );
}

// What an auditor actually does with this screen is write it down: which
// account, measured when, retrieved when, by whom. So it is laid out as a
// record to be cited rather than a dashboard to be skimmed — labelled rows,
// one value each, in a fixed order.
//
// There is deliberately no compliance score here any more. The record used to
// open with a number out of 100, taken from a column that turned out to hold
// whatever the last collector wrote. On 20 October that produced a record
// stating "no compliance score has been recorded" directly above a count of
// 76 checks with 8 failures — two answers on one screen.
//
// The percentage under the bar is not that number returning. It is the two
// counts printed above it, divided, and it is labelled as such: no threshold
// for "compliant" has ever been defined, so the card states the share of
// checks that passed and stops short of calling it a grade.
function EvidenceRecord({ account, evidence, retrievedBy, retrievedAt }: {
  account: ScopeAccount;
  evidence: Evidence;
  retrievedBy: string;
  retrievedAt: string;
}) {
  // The class has to be on the node before the print dialog reads the page,
  // so the call waits a tick instead of going out with the click.
  const [printing, setPrinting] = useState(false);
  useEffect(() => {
    if (!printing) return;
    const id = window.setTimeout(() => {
      window.print();
      setPrinting(false);
    }, 0);
    return () => window.clearTimeout(id);
  }, [printing]);

  // Either there is a scan to cite or there is not. Never both at once.
  const scanned = evidence.total_checks !== null && evidence.total_checks !== undefined;

  const bySev = evidence.by_severity || {};
  const failedAt = (level: string) => bySev[level]?.failed ?? 0;
  const widest = Math.max(0, ...SEVERITY_ORDER.map(failedAt));
  const total = evidence.total_checks || 0;
  const passedPct = total > 0 ? ((evidence.passed || 0) / total) * 100 : 0;

  return (
    <div
      className={`ev-sheet${printing ? " ev-printing" : ""}`}
      style={{ background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: "16px 18px", marginTop: 10 }}
    >
      <div className="ev-muted" style={{ color: "#ef4444", fontSize: 9.5, fontWeight: 700, letterSpacing: "0.18em", marginBottom: 8 }}>
        COMPLIANCE EVIDENCE
      </div>
      <div className="ev-ink" style={{ color: "#f1f5f9", fontSize: 14.5, fontWeight: 700 }}>
        {evidence.account_name || account.account_name || "unnamed account"}
      </div>
      <div className="ev-muted" style={{ color: "#4e627a", fontSize: 11.5, marginBottom: 16 }}>
        AWS account {account.account_id}
      </div>

      {!scanned ? (
        <div className="ev-muted" style={{ color: "#6b7280", fontSize: 12.5, paddingBottom: 10 }}>
          This account has not been scanned yet, so there is no evidence to show.
        </div>
      ) : (
        <>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
            <span className="ev-ink" style={{ color: "#f1f5f9", fontSize: 30, fontWeight: 700, lineHeight: 1 }}>
              {evidence.passed}
            </span>
            <span className="ev-muted" style={{ color: "#6b7280", fontSize: 13 }}>
              of {evidence.total_checks} checks passed
            </span>
          </div>
          <div className="ev-track" style={{ height: 8, background: "#151b28", borderRadius: 5, overflow: "hidden", margin: "12px 0 7px" }}>
            <div className="ev-bar" style={{ width: `${passedPct}%`, height: "100%", background: "#22c55e", borderRadius: 5 }} />
          </div>
          <div className="ev-muted" style={{ color: "#4e627a", fontSize: 11, marginBottom: 20, lineHeight: 1.5 }}>
            {passedPct.toFixed(1)}% of the checks that ran — a proportion, not a grade:
            no passing threshold has been defined.
          </div>

          <div className="ev-muted" style={{ color: "#6b7280", fontSize: 10, fontWeight: 700, letterSpacing: "0.13em", marginBottom: 7 }}>
            FAILURES BY SEVERITY
          </div>
          {SEVERITY_ORDER.map(level => (
            <SeverityBar key={level} level={level} failed={failedAt(level)} widest={widest} />
          ))}
          {widest === 0 && (
            <div className="ev-muted" style={{ color: "#4e627a", fontSize: 11, marginTop: 7 }}>
              Nothing failed in this scan.
            </div>
          )}

          <div style={{ height: 18 }} />
          <RecordRow label="Checks performed" value={evidence.total_checks} />
          <RecordRow label="Passed" value={evidence.passed} />
          <RecordRow label="Failed" value={evidence.failed} strong={!!evidence.failed} />
        </>
      )}

      <div style={{ height: 10 }} />
      <RecordRow label="Measured at" value={tidyTimestamp(evidence.measured_at)} />
      <RecordRow label="Retrieved by" value={retrievedBy} />
      <RecordRow label="Retrieved at" value={retrievedAt} />

      <div style={{ display: "flex", alignItems: "flex-end", gap: 14, marginTop: 12 }}>
        <div className="ev-muted" style={{ flex: 1, color: "#4e627a", fontSize: 11, lineHeight: 1.5 }}>
          This retrieval has been recorded in the audited organization's activity log.
        </div>
        <button
          className="ev-noprint"
          onClick={() => setPrinting(true)}
          style={{ background: "none", border: "1px solid #374151", color: "#9ca3af", borderRadius: 6, padding: "5px 11px", fontSize: 11, cursor: "pointer", whiteSpace: "nowrap" }}
        >
          Print / save as PDF
        </button>
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
      <style>{PRINT_STYLES}</style>
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
