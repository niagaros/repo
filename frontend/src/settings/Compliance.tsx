import React, { useCallback, useEffect, useMemo, useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";
import {
  api, Badge, Button, cardStyle, ErrorBox, ExpiryBadge, Field, fmtDate, inputStyle, rowStyle,
  sectionHint, sectionTitle, StepBanner, tone,
} from "./shared/setupUi";

// /settings/compliance — onboarding step 5, issue #281 "Configure Compliance".
//
// Built: choosing frameworks (only the ones Niagaros really checks — the
// backend refuses anything else), with owner, version, certification status
// and validity dates; and tracking certifications with expiry warnings.
// Every change lands in the organization's audit trail (shown on the
// Governance page).
//
// Not built, and listed as such at the bottom of the page instead of being
// imitated: business-unit scoping, document storage, evidence retention and
// scheduled reminder emails.

type FrameworkStatus = "not_started" | "in_progress" | "certified" | "expired";

interface Framework {
  id: string;
  framework_name: string;
  enabled: boolean;
  version: string | null;
  owner_email: string | null;
  certification_status: FrameworkStatus;
  effective_date: string | null;
  expiration_date: string | null;
  expires_in_days: number | null;
}

interface Certification {
  id: string;
  name: string;
  standard: string;
  status: string;
  certification_body: string | null;
  issue_date: string | null;
  expiration_date: string | null;
  renewal_date: string | null;
  expires_in_days: number | null;
}

interface ComplianceData {
  catalog: string[];
  frameworks: Framework[];
  certifications: Certification[];
  members: string[];
  reminder_days: number;
  can_edit: boolean;
  step_complete: boolean;
}

const STATUS_LABEL: Record<FrameworkStatus, string> = {
  not_started: "Not started", in_progress: "In progress", certified: "Certified", expired: "Expired",
};
const STATUS_TONE: Record<FrameworkStatus, { color: string; bg: string }> = {
  not_started: tone.grey, in_progress: tone.blue, certified: tone.green, expired: tone.red,
};

const EMPTY_CERT = { name: "", standard: "", certification_body: "", issue_date: "", expiration_date: "", renewal_date: "", status: "active" };

export default function Compliance() {
  const { loading: authLoading, email } = useRequireAuth();
  const [data, setData] = useState<ComplianceData | null>(null);
  const [loadError, setLoadError] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState<Partial<Framework>>({});
  const [saving, setSaving] = useState(false);
  const [rowError, setRowError] = useState("");
  const [search, setSearch] = useState("");
  const [cert, setCert] = useState({ ...EMPTY_CERT });
  const [certError, setCertError] = useState("");
  const [certSaving, setCertSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api<ComplianceData>("/compliance"));
      setLoadError("");
    } catch (e: any) {
      setLoadError(e.message);
    }
  }, []);

  useEffect(() => { if (!authLoading) load(); }, [authLoading, load]);

  const byName = useMemo(() => {
    const m: Record<string, Framework> = {};
    (data?.frameworks || []).forEach(f => { m[f.framework_name] = f; });
    return m;
  }, [data]);

  const startEdit = (name: string) => {
    const f = byName[name];
    setRowError("");
    setEditing(name);
    setDraft(f ? { ...f } : { framework_name: name, enabled: true, certification_status: "not_started" });
  };

  const [toggleError, setToggleError] = useState<{ name: string; message: string } | null>(null);

  const putFramework = (name: string, f: Partial<Framework>) =>
    api("/compliance/frameworks", "PUT", {
      framework_name: name,
      enabled: f.enabled ?? true,
      version: f.version || null,
      owner_email: f.owner_email || null,
      certification_status: f.certification_status || "not_started",
      effective_date: f.effective_date || null,
      expiration_date: f.expiration_date || null,
    });

  const save = async (name: string) => {
    setSaving(true);
    setRowError("");
    try {
      await putFramework(name, draft);
      setEditing(null);
      await load();
    } catch (e: any) {
      setRowError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const toggle = async (name: string) => {
    const f = byName[name];
    setSaving(true);
    setToggleError(null);
    try {
      await putFramework(name, { ...(f || {}), enabled: !(f?.enabled) });
      if (editing === name) setEditing(null);
      await load();
    } catch (e: any) {
      setToggleError({ name, message: e.message });
    } finally {
      setSaving(false);
    }
  };

  const addCert = async () => {
    setCertError("");
    if (!cert.name.trim() || !cert.standard.trim()) { setCertError("Name and standard are required."); return; }
    setCertSaving(true);
    try {
      await api("/compliance/certifications", "POST", {
        ...cert,
        certification_body: cert.certification_body || null,
        issue_date: cert.issue_date || null,
        expiration_date: cert.expiration_date || null,
        renewal_date: cert.renewal_date || null,
      });
      setCert({ ...EMPTY_CERT });
      await load();
    } catch (e: any) {
      setCertError(e.message);
    } finally {
      setCertSaving(false);
    }
  };

  const removeCert = async (c: Certification) => {
    if (!window.confirm(`Remove the certification "${c.name}"? This is recorded in the audit trail.`)) return;
    try {
      await api(`/compliance/certifications/${c.id}`, "DELETE");
      await load();
    } catch (e: any) {
      setCertError(e.message);
    }
  };

  if (authLoading || (!data && !loadError)) {
    return <SettingsLayout title="Compliance" email={email}><div style={{ color: "#64748b", fontSize: 13 }}>Loading…</div></SettingsLayout>;
  }
  if (!data) {
    return (
      <SettingsLayout title="Compliance" email={email}>
        <div style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13 }}>
          {loadError} <Button kind="ghost" onClick={load}>Try again</Button>
        </div>
      </SettingsLayout>
    );
  }

  const enabled = data.frameworks.filter(f => f.enabled);
  // Selected frameworks first, then the rest alphabetically.
  const visibleCatalog = data.catalog
    .filter(n => n.toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => Number(!!byName[b]?.enabled) - Number(!!byName[a]?.enabled) || a.localeCompare(b));

  return (
    <SettingsLayout
      title="Compliance"
      subtitle="Choose the frameworks your organization follows, who owns them, and track your certifications."
      email={email}
    >
      {data && loadError && (
        <div role="alert" style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13, display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ flex: 1 }}>Could not refresh this page, so what you see may be out of date. {loadError}</span>
          <Button kind="ghost" onClick={load}>Reload</Button>
        </div>
      )}
      <StepBanner
        step={5}
        done={data.step_complete}
        doneText={`${enabled.length} framework${enabled.length === 1 ? "" : "s"} selected for your compliance program.`}
        todoText="Select at least one framework your organization needs to comply with."
      />

      {/* ── Frameworks ───────────────────────────────────────────────── */}
      <div style={cardStyle}>
        <div style={sectionTitle}>Frameworks</div>
        <div style={sectionHint}>
          These are the frameworks Niagaros maps your findings to. Turn on the ones your organization has to comply
          with, then add an owner, version and certification dates.
          {!data.can_edit && " Only admins and compliance members can change this."}
        </div>
        <input
          style={{ ...inputStyle, marginBottom: 8 }}
          placeholder="Search frameworks…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          aria-label="Search frameworks"
        />
        {visibleCatalog.map(name => {
          const f = byName[name];
          const on = !!f?.enabled;
          const isEditing = editing === name && data.can_edit;
          return (
            <div key={name} style={{ borderTop: "1px solid #1a2030", padding: "10px 0" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <button
                  onClick={() => data.can_edit && !saving && toggle(name)}
                  disabled={!data.can_edit || saving}
                  aria-pressed={on}
                  aria-label={`${on ? "Turn off" : "Turn on"} ${name}`}
                  style={{
                    width: 38, height: 22, borderRadius: 11, border: "none", position: "relative", flexShrink: 0,
                    background: on ? "#16a34a" : "#374151", cursor: data.can_edit ? "pointer" : "default",
                  }}
                >
                  <span style={{ position: "absolute", top: 3, left: on ? 19 : 3, width: 16, height: 16, borderRadius: "50%", background: "#fff", transition: "left .15s" }} />
                </button>
                <span style={{ flex: 1, minWidth: 160, color: on ? "#f1f5f9" : "#9ca3af", fontSize: 13, fontWeight: on ? 600 : 400 }}>{name}</span>
                {f && on && <Badge {...STATUS_TONE[f.certification_status]}>{STATUS_LABEL[f.certification_status]}</Badge>}
                {f && on && <ExpiryBadge days={f.expires_in_days} reminderDays={data.reminder_days} />}
                {f && on && f.owner_email && <span style={{ color: "#6b7280", fontSize: 11.5 }}>{f.owner_email}</span>}
                {on && data.can_edit && !isEditing && <Button kind="ghost" onClick={() => startEdit(name)}>Details</Button>}
              </div>
              {isEditing && (
                <div style={{ marginTop: 12, padding: 14, background: "#0d1017", borderRadius: 10, border: "1px solid #1e2433" }}>
                  <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                    <Field label="Version">
                      <input style={inputStyle} value={draft.version || ""} placeholder="e.g. 2022"
                        onChange={e => setDraft({ ...draft, version: e.target.value })} />
                    </Field>
                    <Field label="Owner">
                      <select style={inputStyle} value={draft.owner_email || ""}
                        onChange={e => setDraft({ ...draft, owner_email: e.target.value || null })}>
                        <option value="">— No owner —</option>
                        {data.members.map(m => <option key={m} value={m}>{m}</option>)}
                      </select>
                    </Field>
                    <Field label="Certification status">
                      <select style={inputStyle} value={draft.certification_status || "not_started"}
                        onChange={e => setDraft({ ...draft, certification_status: e.target.value as FrameworkStatus })}>
                        {(Object.keys(STATUS_LABEL) as FrameworkStatus[]).map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
                      </select>
                    </Field>
                  </div>
                  <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12 }}>
                    <Field label="Effective date">
                      <input type="date" style={inputStyle} value={draft.effective_date || ""}
                        onChange={e => setDraft({ ...draft, effective_date: e.target.value })} />
                    </Field>
                    <Field label="Expiration date">
                      <input type="date" style={inputStyle} value={draft.expiration_date || ""}
                        onChange={e => setDraft({ ...draft, expiration_date: e.target.value })} />
                    </Field>
                  </div>
                  <ErrorBox message={rowError} />
                  <div style={{ display: "flex", gap: 8, marginTop: 14 }}>
                    <Button onClick={() => save(name)} disabled={saving}>{saving ? "Saving…" : "Save"}</Button>
                    <Button kind="ghost" onClick={() => { setEditing(null); setRowError(""); }}>Cancel</Button>
                  </div>
                </div>
              )}
              {toggleError?.name === name && <ErrorBox message={toggleError.message} />}
            </div>
          );
        })}
        {visibleCatalog.length === 0 && <div style={{ color: "#6b7280", fontSize: 12.5, paddingTop: 8 }}>No framework matches “{search}”.</div>}
      </div>

      {/* ── Certifications ───────────────────────────────────────────── */}
      <div style={cardStyle}>
        <div style={sectionTitle}>Certifications</div>
        <div style={sectionHint}>
          Certificates your organization holds. Niagaros flags them from {data.reminder_days} days before they expire.
        </div>
        {data.certifications.length === 0 && <div style={{ color: "#6b7280", fontSize: 12.5, marginBottom: 12 }}>No certifications added yet.</div>}
        {data.certifications.map(c => (
          <div key={c.id} style={rowStyle}>
            <div style={{ flex: 1, minWidth: 180 }}>
              <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 600 }}>{c.name}</div>
              <div style={{ color: "#6b7280", fontSize: 11.5 }}>
                {c.standard}{c.certification_body ? ` · ${c.certification_body}` : ""} · issued {fmtDate(c.issue_date)} · expires {fmtDate(c.expiration_date)}
                {c.renewal_date ? ` · renewal ${fmtDate(c.renewal_date)}` : ""}
              </div>
            </div>
            <Badge {...(c.status === "active" ? tone.green : c.status === "expired" ? tone.red : tone.amber)}>{c.status.replace("_", " ")}</Badge>
            <ExpiryBadge days={c.expires_in_days} reminderDays={data.reminder_days} />
            {data.can_edit && <Button kind="danger" onClick={() => removeCert(c)}>Remove</Button>}
          </div>
        ))}
        {data.can_edit && (
          <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid #1a2030" }}>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              <Field label="Certification name *">
                <input style={inputStyle} value={cert.name} placeholder="e.g. ISO 27001 certificate" onChange={e => setCert({ ...cert, name: e.target.value })} />
              </Field>
              <Field label="Standard *">
                <input style={inputStyle} value={cert.standard} placeholder="e.g. ISO 27001:2022" list="niagaros-standards" onChange={e => setCert({ ...cert, standard: e.target.value })} />
                <datalist id="niagaros-standards">{data.catalog.map(n => <option key={n} value={n} />)}</datalist>
              </Field>
              <Field label="Certification body">
                <input style={inputStyle} value={cert.certification_body} placeholder="e.g. BSI" onChange={e => setCert({ ...cert, certification_body: e.target.value })} />
              </Field>
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12 }}>
              <Field label="Issue date"><input type="date" style={inputStyle} value={cert.issue_date} onChange={e => setCert({ ...cert, issue_date: e.target.value })} /></Field>
              <Field label="Expiration date"><input type="date" style={inputStyle} value={cert.expiration_date} onChange={e => setCert({ ...cert, expiration_date: e.target.value })} /></Field>
              <Field label="Renewal date"><input type="date" style={inputStyle} value={cert.renewal_date} onChange={e => setCert({ ...cert, renewal_date: e.target.value })} /></Field>
              <Field label="Status">
                <select style={inputStyle} value={cert.status} onChange={e => setCert({ ...cert, status: e.target.value })}>
                  <option value="active">Active</option>
                  <option value="in_renewal">In renewal</option>
                  <option value="suspended">Suspended</option>
                  <option value="expired">Expired</option>
                </select>
              </Field>
            </div>
            <ErrorBox message={certError} />
            <div style={{ marginTop: 14 }}>
              <Button onClick={addCert} disabled={certSaving}>{certSaving ? "Adding…" : "Add certification"}</Button>
            </div>
          </div>
        )}
        {!data.can_edit && <ErrorBox message={certError} />}
      </div>

      <div style={{ ...cardStyle, background: "transparent", borderStyle: "dashed" }}>
        <div style={sectionTitle}>Coming later</div>
        <div style={{ ...sectionHint, marginBottom: 0 }}>
          Scoping frameworks per business unit, a compliance document library, evidence retention rules and
          reminder emails are not available yet. Policies, ownership and exceptions are managed under{" "}
          <a href="/settings/governance" style={{ color: "#ef4444" }}>Governance</a>.
        </div>
      </div>
    </SettingsLayout>
  );
}
