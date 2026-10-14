import React, { useCallback, useEffect, useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";
import {
  api, Badge, Button, cardStyle, ErrorBox, ExpiryBadge, Field, fmtDate, fmtDateTime, inputStyle, rowStyle,
  sectionHint, sectionTitle, StepBanner, tone,
} from "./shared/setupUi";

// /settings/governance — onboarding step 6, issue #282 "Configure Governance".
//
// Built: policies with owner, approver, review date and versioned text; an
// approval step where the author can never approve their own version
// (separation of duties, enforced by the backend and the database); policy
// exceptions that always carry a justification, risk, owner and end date and
// only count as active while approved and unexpired; and one audit trail for
// compliance, governance and training changes.
//
// Not built (listed at the bottom of the page): standards and controls as
// separate objects, RACI ownership, inheritance across business units,
// multi-step approval chains, and risk/framework mappings.

interface Version {
  version: number;
  content: string;
  change_summary: string | null;
  status: "draft" | "pending_approval" | "approved" | "rejected";
  author_email: string | null;
  author_id: string;
  decided_by_email: string | null;
  decided_at: string | null;
  decision_note: string | null;
  created_at: string;
}

interface Policy {
  id: string;
  name: string;
  category: string;
  owner_email: string;
  approver_email: string;
  review_date: string | null;
  review_in_days: number | null;
  requires_acknowledgement: boolean;
  published_version: number | null;
  retired: boolean;
  versions: Version[];
}

interface PolicyException {
  id: string;
  policy_id: string | null;
  policy_name: string | null;
  requirement: string;
  justification: string;
  risk: "low" | "medium" | "high" | "critical";
  compensating_controls: string | null;
  scope: string | null;
  owner_email: string;
  requested_by_email: string | null;
  requested_by: string;
  status: "requested" | "approved" | "rejected" | "revoked";
  start_date: string;
  expiration_date: string;
  expires_in_days: number;
  expired: boolean;
  active: boolean;
  decided_by_email: string | null;
  decision_note: string | null;
}

interface AuditEntry {
  action: string;
  details: Record<string, any>;
  created_at: string;
  actor_email: string | null;
}

interface GovernanceData {
  policies: Policy[];
  exceptions: PolicyException[];
  audit: AuditEntry[];
  categories: string[];
  members: { email: string; role: string }[];
  me: { id: string; email: string; role: string };
  reminder_days: number;
  can_author: boolean;
  step_complete: boolean;
}

const VERSION_STATUS: Record<Version["status"], string> = {
  draft: "draft", pending_approval: "awaiting approval", approved: "approved", rejected: "rejected",
};

const RISK_TONE = { low: tone.grey, medium: tone.amber, high: tone.red, critical: tone.red };

const AUDIT_LABEL: Record<string, string> = {
  compliance_framework_saved: "Framework updated",
  compliance_certification_added: "Certification added",
  compliance_certification_removed: "Certification removed",
  governance_policy_created: "Policy created",
  governance_policy_version_submitted: "New policy version submitted",
  governance_policy_approved: "Policy version approved",
  governance_policy_rejected: "Policy version rejected",
  governance_policy_retired: "Policy retired",
  governance_exception_requested: "Exception requested",
  governance_exception_approved: "Exception approved",
  governance_exception_rejected: "Exception rejected",
  governance_exception_revoked: "Exception revoked",
  training_policy_acknowledged: "Policy acknowledged",
};

function auditSubject(e: AuditEntry): string {
  const d = e.details || {};
  const parts = [d.name || d.framework || d.requirement || ""];
  if (d.version) parts.push(`v${d.version}`);
  if (d.note) parts.push(`“${d.note}”`);
  return parts.filter(Boolean).join(" · ");
}

const EMPTY_POLICY = { name: "", category: "", owner_email: "", approver_email: "", review_date: "", requires_acknowledgement: true, content: "" };
const EMPTY_EXCEPTION = { policy_id: "", requirement: "", justification: "", risk: "", compensating_controls: "", scope: "", owner_email: "", start_date: "", expiration_date: "" };

export default function Governance() {
  const { loading: authLoading, email } = useRequireAuth();
  const [data, setData] = useState<GovernanceData | null>(null);
  const [loadError, setLoadError] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [viewVersion, setViewVersion] = useState<{ policyId: string; version: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<{ key: string; message: string } | null>(null);
  const [showPolicyForm, setShowPolicyForm] = useState(false);
  const [policy, setPolicy] = useState({ ...EMPTY_POLICY });
  const [policyError, setPolicyError] = useState("");
  const [versionDraft, setVersionDraft] = useState<{ policyId: string; content: string; change_summary: string } | null>(null);
  const [showExceptionForm, setShowExceptionForm] = useState(false);
  const [exc, setExc] = useState({ ...EMPTY_EXCEPTION });
  const [excError, setExcError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await api<GovernanceData>("/governance"));
      setLoadError("");
    } catch (e: any) {
      setLoadError(e.message);
    }
  }, []);

  useEffect(() => { if (!authLoading) load(); }, [authLoading, load]);

  // Runs an action, shows its error next to the thing that was clicked, reloads on success.
  const run = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await load();
      return true;
    } catch (e: any) {
      setActionError({ key, message: e.message });
      return false;
    } finally {
      setBusy(false);
    }
  };

  const errorFor = (key: string) => (actionError?.key === key ? actionError.message : "");

  const createPolicy = async () => {
    setPolicyError("");
    setBusy(true);
    try {
      await api("/governance/policies", "POST", { ...policy, review_date: policy.review_date || null });
      setPolicy({ ...EMPTY_POLICY });
      setShowPolicyForm(false);
      await load();
    } catch (e: any) {
      setPolicyError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const decide = (p: Policy, version: number, approve: boolean) => {
    let note: string | null = null;
    if (!approve) {
      note = window.prompt("Why is this version rejected? The author will see this.");
      if (!note) return;
    }
    // The version is sent so a stale screen can never approve a newer version nobody here has read.
    run(p.id, () => api(`/governance/policies/${p.id}/decision`, "POST", { approve, note, version }));
  };

  const submitVersion = async () => {
    if (!versionDraft) return;
    const ok = await run(versionDraft.policyId, () => api(`/governance/policies/${versionDraft.policyId}/versions`, "POST", {
      content: versionDraft.content, change_summary: versionDraft.change_summary,
    }));
    if (ok) setVersionDraft(null);
  };

  const retire = (p: Policy) => {
    if (!window.confirm(`Retire "${p.name}"? It will no longer count as an active policy or need acknowledging.`)) return;
    run(p.id, () => api(`/governance/policies/${p.id}/retire`, "POST"));
  };

  const requestException = async () => {
    setExcError("");
    setBusy(true);
    try {
      await api("/governance/exceptions", "POST", {
        ...exc,
        policy_id: exc.policy_id || null,
        compensating_controls: exc.compensating_controls || null,
        scope: exc.scope || null,
        start_date: exc.start_date || null,
      });
      setExc({ ...EMPTY_EXCEPTION });
      setShowExceptionForm(false);
      await load();
    } catch (e: any) {
      setExcError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const decideException = (x: PolicyException, approve: boolean) => {
    let note: string | null = null;
    if (!approve) {
      note = window.prompt("Why is this exception rejected?");
      if (!note) return;
    }
    run(x.id, () => api(`/governance/exceptions/${x.id}/decision`, "POST", { approve, note }));
  };

  const revokeException = (x: PolicyException) => {
    const note = window.prompt("Why is this exception revoked?");
    if (!note) return;
    run(x.id, () => api(`/governance/exceptions/${x.id}/revoke`, "POST", { note }));
  };

  if (authLoading || (!data && !loadError)) {
    return <SettingsLayout title="Governance" email={email}><div style={{ color: "#64748b", fontSize: 13 }}>Loading…</div></SettingsLayout>;
  }
  if (!data) {
    return (
      <SettingsLayout title="Governance" email={email}>
        <div style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13 }}>
          {loadError} <Button kind="ghost" onClick={load}>Try again</Button>
        </div>
      </SettingsLayout>
    );
  }

  const me = data.me;
  const isAdmin = me.role === "admin";
  const published = data.policies.filter(p => p.published_version && !p.retired).length;
  const otherMembers = data.members.filter(m => m.email.toLowerCase() !== me.email.toLowerCase());

  return (
    <SettingsLayout
      title="Governance"
      subtitle="Policies with owners and approvals, controlled exceptions, and one audit trail."
      email={email}
    >
      {data && loadError && (
        <div role="alert" style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13, display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ flex: 1 }}>Could not refresh this page, so what you see may be out of date. {loadError}</span>
          <Button kind="ghost" onClick={load}>Reload</Button>
        </div>
      )}
      <StepBanner
        step={6}
        done={data.step_complete}
        doneText={`${published} published polic${published === 1 ? "y" : "ies"}. Team members acknowledge these in Security Training.`}
        todoText="Write your first policy and have a second person approve it."
      />

      {/* ── Policies ─────────────────────────────────────────────────── */}
      <div style={cardStyle}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={sectionTitle}>Policies</div>
            <div style={sectionHint}>
              Each version is written by one person and approved by another. Older versions stay available for audits.
            </div>
          </div>
          {data.can_author && !showPolicyForm && <Button onClick={() => setShowPolicyForm(true)}>New policy</Button>}
        </div>

        {showPolicyForm && (
          <div style={{ padding: 14, background: "#0d1017", borderRadius: 10, border: "1px solid #1e2433", marginBottom: 12 }}>
            {otherMembers.length === 0 && (
              <div style={{ color: "#fbbf24", fontSize: 12.5, marginBottom: 12 }}>
                A policy needs a second person to approve it. <a href="/settings/team" style={{ color: "#ef4444" }}>Invite a team member</a> first.
              </div>
            )}
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <Field label="Policy name *"><input style={inputStyle} value={policy.name} placeholder="e.g. Access Control Policy" onChange={e => setPolicy({ ...policy, name: e.target.value })} /></Field>
              <Field label="Category *">
                <select style={inputStyle} value={policy.category} onChange={e => setPolicy({ ...policy, category: e.target.value })}>
                  <option value="">Choose…</option>
                  {data.categories.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              </Field>
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12 }}>
              <Field label="Owner *">
                <select style={inputStyle} value={policy.owner_email} onChange={e => setPolicy({ ...policy, owner_email: e.target.value })}>
                  <option value="">Choose…</option>
                  {data.members.map(m => <option key={m.email} value={m.email}>{m.email}</option>)}
                </select>
              </Field>
              <Field label="Approver * (not you)">
                <select style={inputStyle} value={policy.approver_email} onChange={e => setPolicy({ ...policy, approver_email: e.target.value })}>
                  <option value="">Choose…</option>
                  {otherMembers.map(m => <option key={m.email} value={m.email}>{m.email}</option>)}
                </select>
              </Field>
              <Field label="Next review"><input type="date" style={inputStyle} value={policy.review_date} onChange={e => setPolicy({ ...policy, review_date: e.target.value })} /></Field>
            </div>
            <div style={{ marginTop: 12 }}>
              <Field label="Policy text *">
                <textarea style={{ ...inputStyle, minHeight: 140, resize: "vertical" }} value={policy.content}
                  placeholder="What the policy requires, who it applies to, and how it is enforced."
                  onChange={e => setPolicy({ ...policy, content: e.target.value })} />
              </Field>
            </div>
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10, color: "#9ca3af", fontSize: 12.5 }}>
              <input type="checkbox" checked={policy.requires_acknowledgement} onChange={e => setPolicy({ ...policy, requires_acknowledgement: e.target.checked })} />
              Every team member must read and acknowledge this policy (Security Training)
            </label>
            <ErrorBox message={policyError} />
            <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
              <Button onClick={createPolicy} disabled={busy}>{busy ? "Submitting…" : "Submit for approval"}</Button>
              <Button kind="ghost" onClick={() => { setShowPolicyForm(false); setPolicyError(""); }}>Cancel</Button>
            </div>
          </div>
        )}

        {data.policies.length === 0 && !showPolicyForm && <div style={{ color: "#6b7280", fontSize: 12.5 }}>No policies yet.</div>}

        {data.policies.map(p => {
          const pending = p.versions.find(v => v.status === "pending_approval");
          const current = p.versions.find(v => v.version === p.published_version);
          const canDecide = !!pending && !p.retired && pending.author_id !== me.id
            && (isAdmin || p.approver_email.toLowerCase() === me.email.toLowerCase());
          const isOpen = open === p.id;
          const shown = (viewVersion?.policyId === p.id && p.versions.find(v => v.version === viewVersion.version))
            || pending || current || p.versions[0];
          return (
            <div key={p.id} style={{ borderTop: "1px solid #1a2030", padding: "12px 0", opacity: p.retired ? 0.6 : 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", cursor: "pointer" }} onClick={() => setOpen(isOpen ? null : p.id)}>
                <span style={{ color: "#6b7280", fontSize: 11, width: 10 }}>{isOpen ? "▾" : "▸"}</span>
                <div style={{ flex: 1, minWidth: 180 }}>
                  <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 600 }}>{p.name}</div>
                  <div style={{ color: "#6b7280", fontSize: 11.5 }}>{p.category} · owner {p.owner_email} · approver {p.approver_email}</div>
                </div>
                {p.retired && <Badge {...tone.grey}>Retired</Badge>}
                {!p.retired && p.published_version && <Badge {...tone.green}>Published v{p.published_version}</Badge>}
                {!p.retired && pending && <Badge {...tone.amber}>v{pending.version} awaiting approval</Badge>}
                {!p.retired && <ExpiryBadge days={p.review_in_days} reminderDays={data.reminder_days} label="Review" />}
              </div>
              {canDecide && (
                <div style={{ display: "flex", gap: 8, marginTop: 10, marginLeft: 20, flexWrap: "wrap", alignItems: "center" }}>
                  <span style={{ color: "#fbbf24", fontSize: 12 }}>Your approval is needed for v{pending!.version} by {pending!.author_email}.</span>
                  <Button kind="ghost" onClick={() => { setOpen(p.id); setViewVersion({ policyId: p.id, version: pending!.version }); }}>Read it</Button>
                  <Button kind="ghost" onClick={() => decide(p, pending!.version, true)} disabled={busy}>Approve & publish v{pending!.version}</Button>
                  <Button kind="danger" onClick={() => decide(p, pending!.version, false)} disabled={busy}>Reject</Button>
                </div>
              )}
              <div style={{ marginLeft: 20 }}><ErrorBox message={errorFor(p.id)} /></div>

              {isOpen && (
                <div style={{ marginTop: 12, marginLeft: 20 }}>
                  {shown && (
                    <div style={{ whiteSpace: "pre-wrap", color: "#cbd5e1", fontSize: 13, lineHeight: 1.6, background: "#0d1017", border: "1px solid #1e2433", borderRadius: 10, padding: 14 }}>
                      <div style={{ color: "#6b7280", fontSize: 11, marginBottom: 8 }}>
                        Version {shown.version} · {VERSION_STATUS[shown.status]}{shown.version === p.published_version ? " · currently published" : ""}
                      </div>
                      {shown.content}
                    </div>
                  )}

                  <div style={{ color: "#9ca3af", fontSize: 12, fontWeight: 600, margin: "14px 0 6px" }}>Version history</div>
                  {p.versions.map(v => (
                    <div key={v.version} style={{ display: "flex", gap: 10, fontSize: 12, color: "#9ca3af", padding: "4px 0", flexWrap: "wrap", alignItems: "center" }}>
                      <button
                        onClick={() => setViewVersion({ policyId: p.id, version: v.version })}
                        aria-label={`Show the text of version ${v.version}`}
                        style={{ background: shown?.version === v.version ? "#1e2433" : "none", border: "1px solid #374151", borderRadius: 5, color: "#e2e8f0", fontSize: 11.5, padding: "1px 7px", cursor: "pointer" }}
                      >v{v.version}</button>
                      <span style={{ flex: 1, minWidth: 160 }}>{v.change_summary || "—"} · by {v.author_email} · {fmtDate(v.created_at)}</span>
                      <span>
                        {v.status === "approved" && `approved by ${v.decided_by_email} · ${fmtDate(v.decided_at)}`}
                        {v.status === "rejected" && `rejected by ${v.decided_by_email}${v.decision_note ? ` — “${v.decision_note}”` : ""}`}
                        {v.status === "pending_approval" && "awaiting approval"}
                      </span>
                    </div>
                  ))}

                  {!p.retired && data.can_author && !pending && versionDraft?.policyId !== p.id && (
                    <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                      <Button kind="ghost" onClick={() => setVersionDraft({ policyId: p.id, content: (current || p.versions[0])?.content || "", change_summary: "" })}>Write new version</Button>
                      {isAdmin && <Button kind="danger" onClick={() => retire(p)} disabled={busy}>Retire policy</Button>}
                    </div>
                  )}
                  {versionDraft?.policyId === p.id && (
                    <div style={{ marginTop: 12 }}>
                      <Field label="New policy text">
                        <textarea style={{ ...inputStyle, minHeight: 140, resize: "vertical" }} value={versionDraft.content}
                          onChange={e => setVersionDraft({ ...versionDraft, content: e.target.value })} />
                      </Field>
                      <div style={{ marginTop: 10 }}>
                        <Field label="What changed? *">
                          <input style={inputStyle} value={versionDraft.change_summary} onChange={e => setVersionDraft({ ...versionDraft, change_summary: e.target.value })} />
                        </Field>
                      </div>
                      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                        <Button onClick={submitVersion} disabled={busy}>Submit for approval</Button>
                        <Button kind="ghost" onClick={() => setVersionDraft(null)}>Cancel</Button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Exceptions ───────────────────────────────────────────────── */}
      <div style={cardStyle}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={sectionTitle}>Exceptions</div>
            <div style={sectionHint}>
              A temporary, approved deviation from a requirement. It needs a reason, a risk level, an owner and an end
              date, and stops counting the moment it expires. Admins decide; never the person who asked.
            </div>
          </div>
          {data.can_author && !showExceptionForm && <Button onClick={() => setShowExceptionForm(true)}>Request exception</Button>}
        </div>

        {showExceptionForm && (
          <div style={{ padding: 14, background: "#0d1017", borderRadius: 10, border: "1px solid #1e2433", marginBottom: 12 }}>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <Field label="Requirement *"><input style={inputStyle} value={exc.requirement} placeholder="e.g. MFA on the break-glass account" onChange={e => setExc({ ...exc, requirement: e.target.value })} /></Field>
              <Field label="Related policy">
                <select style={inputStyle} value={exc.policy_id} onChange={e => setExc({ ...exc, policy_id: e.target.value })}>
                  <option value="">— None —</option>
                  {data.policies.filter(p => !p.retired).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </Field>
            </div>
            <div style={{ marginTop: 12 }}>
              <Field label="Business justification *">
                <textarea style={{ ...inputStyle, minHeight: 70 }} value={exc.justification} onChange={e => setExc({ ...exc, justification: e.target.value })} />
              </Field>
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12 }}>
              <Field label="Risk *">
                <select style={inputStyle} value={exc.risk} onChange={e => setExc({ ...exc, risk: e.target.value })}>
                  <option value="">Choose…</option>
                  <option value="low">Low</option><option value="medium">Medium</option>
                  <option value="high">High</option><option value="critical">Critical</option>
                </select>
              </Field>
              <Field label="Owner *">
                <select style={inputStyle} value={exc.owner_email} onChange={e => setExc({ ...exc, owner_email: e.target.value })}>
                  <option value="">Choose…</option>
                  {data.members.map(m => <option key={m.email} value={m.email}>{m.email}</option>)}
                </select>
              </Field>
              <Field label="Start"><input type="date" style={inputStyle} value={exc.start_date} onChange={e => setExc({ ...exc, start_date: e.target.value })} /></Field>
              <Field label="Ends * (max 1 year)"><input type="date" style={inputStyle} value={exc.expiration_date} onChange={e => setExc({ ...exc, expiration_date: e.target.value })} /></Field>
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12 }}>
              <Field label="Compensating controls"><input style={inputStyle} value={exc.compensating_controls} onChange={e => setExc({ ...exc, compensating_controls: e.target.value })} /></Field>
              <Field label="Scope"><input style={inputStyle} value={exc.scope} placeholder="e.g. production AWS account" onChange={e => setExc({ ...exc, scope: e.target.value })} /></Field>
            </div>
            <ErrorBox message={excError} />
            <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
              <Button onClick={requestException} disabled={busy}>{busy ? "Submitting…" : "Submit request"}</Button>
              <Button kind="ghost" onClick={() => { setShowExceptionForm(false); setExcError(""); }}>Cancel</Button>
            </div>
          </div>
        )}

        {data.exceptions.length === 0 && !showExceptionForm && <div style={{ color: "#6b7280", fontSize: 12.5 }}>No exceptions.</div>}
        {data.exceptions.map(x => {
          const label = x.status === "approved" ? (x.expired ? "Expired" : x.active ? "Active" : "Approved (not started)")
            : x.status === "requested" ? "Awaiting decision" : x.status === "rejected" ? "Rejected" : "Revoked";
          const t = x.active ? tone.amber : x.status === "requested" ? tone.blue : tone.grey;
          const canDecide = isAdmin && x.status === "requested" && x.requested_by !== me.id;
          return (
            <div key={x.id} style={{ ...rowStyle, alignItems: "flex-start" }}>
              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 600 }}>{x.requirement}{x.policy_name ? <span style={{ color: "#6b7280", fontWeight: 400 }}> · {x.policy_name}</span> : null}</div>
                <div style={{ color: "#9ca3af", fontSize: 12, marginTop: 2 }}>{x.justification}</div>
                <div style={{ color: "#6b7280", fontSize: 11.5, marginTop: 4 }}>
                  owner {x.owner_email} · requested by {x.requested_by_email} · {fmtDate(x.start_date)} – {fmtDate(x.expiration_date)}
                  {x.scope ? ` · scope: ${x.scope}` : ""}
                  {x.compensating_controls ? ` · compensating: ${x.compensating_controls}` : ""}
                  {x.decided_by_email ? ` · decided by ${x.decided_by_email}` : ""}
                  {x.decision_note ? ` — “${x.decision_note}”` : ""}
                </div>
                <ErrorBox message={errorFor(x.id)} />
              </div>
              <Badge {...RISK_TONE[x.risk]}>{x.risk} risk</Badge>
              <Badge {...t}>{label}</Badge>
              {x.active && <ExpiryBadge days={x.expires_in_days} reminderDays={data.reminder_days} />}
              {canDecide && <Button kind="ghost" onClick={() => decideException(x, true)} disabled={busy}>Approve</Button>}
              {canDecide && <Button kind="danger" onClick={() => decideException(x, false)} disabled={busy}>Reject</Button>}
              {isAdmin && x.status === "approved" && !x.expired && <Button kind="danger" onClick={() => revokeException(x)} disabled={busy}>Revoke</Button>}
            </div>
          );
        })}
      </div>

      {/* ── Audit trail ──────────────────────────────────────────────── */}
      <div style={cardStyle}>
        <div style={sectionTitle}>Audit trail</div>
        <div style={sectionHint}>Every compliance, governance and training change, with who made it and when.</div>
        {data.audit.length === 0 && <div style={{ color: "#6b7280", fontSize: 12.5 }}>Nothing recorded yet.</div>}
        {data.audit.map((a, i) => (
          <div key={i} style={{ display: "flex", gap: 12, fontSize: 12, padding: "6px 0", borderTop: "1px solid #1a2030", flexWrap: "wrap" }}>
            <span style={{ color: "#6b7280", width: 150 }}>{fmtDateTime(a.created_at)}</span>
            <span style={{ color: "#e2e8f0", width: 210 }}>{AUDIT_LABEL[a.action] || a.action.replace(/_/g, " ")}</span>
            <span style={{ color: "#9ca3af", flex: 1, minWidth: 160 }}>{auditSubject(a)}</span>
            <span style={{ color: "#6b7280" }}>{a.actor_email || "—"}</span>
          </div>
        ))}
      </div>

      <div style={{ ...cardStyle, background: "transparent", borderStyle: "dashed" }}>
        <div style={sectionTitle}>Coming later</div>
        <div style={{ ...sectionHint, marginBottom: 0 }}>
          Standards and controls as separate objects, RACI ownership, inheritance across business units,
          multi-step approval chains, and links from policies to risks and framework controls are not available yet.
        </div>
      </div>
    </SettingsLayout>
  );
}
