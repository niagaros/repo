import React, { useCallback, useEffect, useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";
import { api, Badge, Button, cardStyle, ErrorBox, rowStyle, sectionHint, sectionTitle, StepBanner, tone } from "./shared/setupUi";

// /settings/training — onboarding step 7, "Complete Security Training".
//
// Niagaros has no course content of its own, and inventing modules or
// certificates would be fake. What it can measure honestly is whether every
// team member has read and acknowledged the security policies the
// organization published under Governance. Each acknowledgement is stored
// per person and per policy version, so publishing a new version asks
// everyone to read it again. The step is complete when everyone is done.

interface TrainingPolicy {
  policy_id: string;
  name: string;
  category: string;
  version: number;
  content: string;
  acknowledged_count: number;
  acknowledged_by_me: boolean;
}

interface Progress {
  email: string;
  role: string;
  done: number;
  total: number;
}

interface TrainingData {
  policies: TrainingPolicy[];
  progress: Progress[] | null;
  member_count: number;
  step_complete: boolean;
}

export default function Training() {
  const { loading: authLoading, email } = useRequireAuth();
  const [data, setData] = useState<TrainingData | null>(null);
  const [loadError, setLoadError] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [read, setRead] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<{ id: string; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api<TrainingData>("/training"));
      setLoadError("");
    } catch (e: any) {
      setLoadError(e.message);
    }
  }, []);

  useEffect(() => { if (!authLoading) load(); }, [authLoading, load]);

  const acknowledge = async (p: TrainingPolicy) => {
    setBusy(p.policy_id);
    setError(null);
    try {
      await api("/training/acknowledge", "POST", { policy_id: p.policy_id, version: p.version });
      setOpen(null);
      await load();
    } catch (e: any) {
      setError({ id: p.policy_id, message: e.message });
      if (e.status === 409) await load();
    } finally {
      setBusy(null);
    }
  };

  if (authLoading || (!data && !loadError)) {
    return <SettingsLayout title="Security Training" email={email}><div style={{ color: "#64748b", fontSize: 13 }}>Loading…</div></SettingsLayout>;
  }
  if (!data) {
    return (
      <SettingsLayout title="Security Training" email={email}>
        <div style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13 }}>
          {loadError} <Button kind="ghost" onClick={load}>Try again</Button>
        </div>
      </SettingsLayout>
    );
  }

  const mine = data.policies.filter(p => p.acknowledged_by_me).length;
  const total = data.policies.length;
  const everyoneDone = data.progress ? data.progress.filter(p => p.done === p.total).length : null;

  return (
    <SettingsLayout
      title="Security Training"
      subtitle="Read and acknowledge your organization's security policies."
      email={email}
    >
      {data && loadError && (
        <div role="alert" style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13, display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ flex: 1 }}>Could not refresh this page, so what you see may be out of date. {loadError}</span>
          <Button kind="ghost" onClick={load}>Reload</Button>
        </div>
      )}
      <StepBanner
        step={7}
        done={data.step_complete}
        doneText="Every team member has acknowledged the current version of every policy."
        todoText={total === 0
          ? "There is nothing to acknowledge yet: publish a policy under Governance first."
          : "Complete when every team member has acknowledged every published policy."}
      />

      <div style={cardStyle}>
        <div style={sectionTitle}>Your policies</div>
        <div style={sectionHint}>
          {total === 0
            ? <>No published policies require acknowledgement yet. They are written and approved under <a href="/settings/governance" style={{ color: "#ef4444" }}>Governance</a>.</>
            : `You have acknowledged ${mine} of ${total}. When a policy changes, you'll be asked to read the new version.`}
        </div>
        {data.policies.map(p => {
          const isOpen = open === p.policy_id;
          return (
            <div key={p.policy_id} style={{ borderTop: "1px solid #1a2030", padding: "12px 0" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: 180 }}>
                  <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 600 }}>{p.name} <span style={{ color: "#6b7280", fontWeight: 400 }}>v{p.version}</span></div>
                  <div style={{ color: "#6b7280", fontSize: 11.5 }}>{p.category}</div>
                </div>
                {p.acknowledged_by_me
                  ? <Badge {...tone.green}>Acknowledged</Badge>
                  : <Badge {...tone.amber}>To read</Badge>}
                <Button kind="ghost" onClick={() => setOpen(isOpen ? null : p.policy_id)}>{isOpen ? "Close" : p.acknowledged_by_me ? "View" : "Read"}</Button>
              </div>
              {isOpen && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ whiteSpace: "pre-wrap", color: "#cbd5e1", fontSize: 13, lineHeight: 1.65, background: "#0d1017", border: "1px solid #1e2433", borderRadius: 10, padding: 16, maxHeight: 420, overflowY: "auto" }}>
                    {p.content}
                  </div>
                  {!p.acknowledged_by_me && (
                    <>
                      <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12, color: "#cbd5e1", fontSize: 13 }}>
                        <input type="checkbox" checked={!!read[`${p.policy_id}:${p.version}`]} onChange={e => setRead({ ...read, [`${p.policy_id}:${p.version}`]: e.target.checked })} />
                        I have read and understood this policy (version {p.version}) and will follow it.
                      </label>
                      <div style={{ marginTop: 12 }}>
                        <Button onClick={() => acknowledge(p)} disabled={!read[`${p.policy_id}:${p.version}`] || busy === p.policy_id}>
                          {busy === p.policy_id ? "Saving…" : "Acknowledge"}
                        </Button>
                      </div>
                    </>
                  )}
                </div>
              )}
              {error?.id === p.policy_id && <ErrorBox message={error.message} />}
            </div>
          );
        })}
      </div>

      {data.progress && (
        <div style={cardStyle}>
          <div style={sectionTitle}>Team progress</div>
          <div style={sectionHint}>
            {total === 0 ? "Progress appears here once a policy is published."
              : `${everyoneDone} of ${data.member_count} team member${data.member_count === 1 ? "" : "s"} completed.`}
          </div>
          {total > 0 && data.progress.map(m => (
            <div key={m.email} style={rowStyle}>
              <span style={{ flex: 1, color: "#e2e8f0", fontSize: 13 }}>{m.email}</span>
              <span style={{ color: "#6b7280", fontSize: 11.5, textTransform: "capitalize" }}>{m.role}</span>
              <div style={{ width: 120, height: 6, borderRadius: 3, background: "#1a2030", overflow: "hidden" }}>
                <div style={{ width: `${m.total ? (m.done / m.total) * 100 : 0}%`, height: "100%", background: m.done === m.total ? "#16a34a" : "#ef4444" }} />
              </div>
              <span style={{ color: m.done === m.total ? "#4ade80" : "#9ca3af", fontSize: 12, width: 40, textAlign: "right" }}>{m.done}/{m.total}</span>
            </div>
          ))}
        </div>
      )}
    </SettingsLayout>
  );
}
