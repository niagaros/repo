import React, { useEffect, useMemo, useState } from "react";
import SettingsLayout from "../settings/SettingsLayout";
import { useRequireAuth } from "../settings/useRequireAuth";
import { useAnalyticsAccess } from "./useAnalyticsAccess";

// /analytics/onboarding — the drop-off dashboard from DV5.
//
// Three things set this page apart from everything else under /settings.
//
// It is for Niagaros, not for the customer. Every other page in this app
// shows one organization its own data; this one reads across all of them.
// That is why it is not in the settings sidebar and why the backend refuses
// anyone who is not an admin of Niagaros itself. The page does not decide
// that — it renders whatever the endpoint allows, and shows the refusal
// plainly when it is refused.
//
// It computes nothing. Every figure here arrives from the handler. A
// percentage recalculated in the browser is a second definition of the same
// indicator, and the funnel exists precisely so there is one.
//
// It never shows a percentage alone. The design document is blunt about the
// size of this dataset: "a drop-off over a handful of organizations is not a
// statistic but an anecdote with a decimal point in it". So the absolute
// numbers stand next to every percentage, at the same weight.

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

interface FunnelStep {
  step: string;
  reached: number;
  completed: number;
  dropoff_pct: number | null;
  median_days: number | null;
  blocked_reason: string | null;
}

interface OrgRow {
  organization_id: string;
  name: string;
  created_at: string;
  completed_steps: number;
  measured_steps: number;
  progress_pct: number;
  current_step: string | null;
  idle_days: number;
  elapsed_days: number;
  status: "not_started" | "in_progress" | "stuck" | "finished";
}

interface Analytics {
  generated_at: string;
  steps: string[];
  funnel: FunnelStep[];
  summary: {
    organizations: number;
    by_status: Record<string, number>;
    median_total_days: number | null;
    measured_steps: number;
    total_steps: number;
  };
  organizations: OrgRow[];
  stuck_after_days: Record<string, number>;
}

const STEP_LABELS: Record<string, string> = {
  infrastructure: "Cloud Infrastructure",
  team: "Team",
  auditor: "Auditors",
  workspace: "Workspace",
  compliance: "Compliance",
  governance: "Governance",
  training: "Security Training",
};

const STATUS_LABELS: Record<string, string> = {
  not_started: "Not started",
  in_progress: "In progress",
  stuck: "Stuck",
  finished: "Finished",
};

const STATUS_COLORS: Record<string, string> = {
  not_started: "#64748b",
  in_progress: "#38bdf8",
  stuck: "#f59e0b",
  finished: "#4ade80",
};

const label = (step: string) => STEP_LABELS[step] || step;
const days = (n: number | null) => (n === null ? "—" : `${n} ${n === 1 ? "day" : "days"}`);

const card: React.CSSProperties = {
  background: "#0d1017",
  border: "1px solid #1a2030",
  borderRadius: 10,
  padding: "18px 20px",
};

export default function OnboardingAnalytics() {
  const { loading: authLoading, email } = useRequireAuth();
  // Asked before any data is fetched, so someone who may not look is told
  // so plainly instead of watching a loading state turn into an error. The
  // backend refuses the data endpoint on the same rule either way — this is
  // the courtesy, not the guard.
  const mayView = useAnalyticsAccess(Boolean(email));
  const [data, setData] = useState<Analytics | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (authLoading || !email || mayView !== true) return;
    (async () => {
      try {
        const resp = await fetch(`${getApiBase()}/analytics/onboarding`, {
          cache: "no-store",
          headers: { Authorization: `Bearer ${localStorage.getItem("niagaros_token") || ""}` },
        });
        const body = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          setError(body.error || `The dashboard could not be loaded (HTTP ${resp.status}).`);
          return;
        }
        setData(body);
      } catch {
        setError("The dashboard could not be reached.");
      }
    })();
  }, [authLoading, email, mayView]);

  // The widest bar in the funnel sets the scale, so the drop between two
  // steps is visible as a shape and not only as a number.
  const widest = useMemo(
    () => Math.max(1, ...(data?.funnel || []).map(f => f.reached)),
    [data],
  );

  const body = () => {
    if (mayView === false) {
      return (
        <div style={{ ...card, maxWidth: 560 }}>
          <h2 style={{ fontSize: 14, color: "#e2e8f0", margin: "0 0 8px", fontWeight: 600 }}>
            Not available on this account
          </h2>
          <p style={{ fontSize: 13, color: "#94a3b8", margin: 0, lineHeight: 1.7 }}>
            This page reads the onboarding progress of every organization on the platform, so it is
            open to Niagaros administrators only. Your own organization's progress is on the{" "}
            <a href="/onboarding" style={{ color: "#38bdf8" }}>onboarding overview</a>.
          </p>
        </div>
      );
    }
    if (mayView === null) {
      return <div style={{ color: "#64748b", fontSize: 13.5 }}>Loading…</div>;
    }
    if (error) {
      return (
        <div style={{ ...card, borderColor: "#7f1d1d", color: "#fca5a5", fontSize: 13.5, lineHeight: 1.6 }}>
          {error}
        </div>
      );
    }
    if (!data) {
      return <div style={{ color: "#64748b", fontSize: 13.5 }}>Loading…</div>;
    }

    const { summary } = data;
    const partial = summary.measured_steps < summary.total_steps;

    return (
      <>
        {/* ── 1. The funnel — this is the answer to the research question ── */}
        <section style={{ marginBottom: 28 }}>
          <h2 style={{ fontSize: 14, color: "#e2e8f0", margin: "0 0 4px", fontWeight: 600 }}>
            Where customers stop
          </h2>
          <p style={{ fontSize: 12, color: "#64748b", margin: "0 0 14px", lineHeight: 1.6, maxWidth: 620 }}>
            Each step is measured against the step before it, not against the total. A funnel that
            compares everything to the total moves the blame forward: a late step looks bad for
            customers who already left at the first.
          </p>

          <div style={{ ...card, padding: "6px 20px 14px" }}>
            {data.funnel.map(f => (
              <div key={f.step} style={{ padding: "14px 0", borderBottom: "1px solid #141a26" }}>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "baseline", marginBottom: 8 }}>
                  <span style={{ fontSize: 13.5, color: "#e2e8f0", fontWeight: 600, minWidth: 150 }}>
                    {label(f.step)}
                  </span>
                  <span style={{ fontSize: 12.5, color: "#94a3b8" }}>
                    {f.completed} of {f.reached} who got this far
                  </span>
                  <span style={{ marginLeft: "auto", display: "flex", gap: 18, fontSize: 12.5 }}>
                    <span style={{ color: f.dropoff_pct && f.dropoff_pct >= 50 ? "#f87171" : "#94a3b8" }}>
                      {f.dropoff_pct === null ? "no data" : `${f.dropoff_pct}% drop-off`}
                    </span>
                    <span style={{ color: "#64748b" }}>median {days(f.median_days)}</span>
                  </span>
                </div>

                <div style={{ display: "flex", height: 8, background: "#141a26", borderRadius: 4, overflow: "hidden" }}>
                  <div style={{ width: `${(f.completed / widest) * 100}%`, background: "#38bdf8" }} />
                  <div style={{ width: `${((f.reached - f.completed) / widest) * 100}%`, background: "#334155" }} />
                </div>

                {f.blocked_reason && (
                  <p style={{ fontSize: 11.5, color: "#fbbf24", margin: "8px 0 0", lineHeight: 1.6 }}>
                    Not a measurement error — {f.blocked_reason}
                  </p>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* ── 2. The aggregate ──────────────────────────────────────────── */}
        <section style={{ marginBottom: 28 }}>
          <h2 style={{ fontSize: 14, color: "#e2e8f0", margin: "0 0 14px", fontWeight: 600 }}>Summary</h2>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 12 }}>
            {(["not_started", "in_progress", "stuck", "finished"] as const).map(s => (
              <div key={s} style={card}>
                <div style={{ fontSize: 26, fontWeight: 700, color: STATUS_COLORS[s] }}>
                  {summary.by_status[s] ?? 0}
                </div>
                <div style={{ fontSize: 11.5, color: "#64748b", marginTop: 2 }}>{STATUS_LABELS[s]}</div>
              </div>
            ))}
            <div style={card}>
              <div style={{ fontSize: 26, fontWeight: 700, color: "#e2e8f0" }}>
                {summary.median_total_days === null ? "—" : summary.median_total_days}
              </div>
              <div style={{ fontSize: 11.5, color: "#64748b", marginTop: 2 }}>
                Median days, signup to finish
              </div>
            </div>
            <div style={card}>
              <div style={{ fontSize: 26, fontWeight: 700, color: partial ? "#fbbf24" : "#e2e8f0" }}>
                {summary.measured_steps}/{summary.total_steps}
              </div>
              <div style={{ fontSize: 11.5, color: "#64748b", marginTop: 2 }}>Steps measured</div>
            </div>
          </div>
          {partial && (
            <p style={{ fontSize: 11.5, color: "#fbbf24", margin: "10px 0 0", lineHeight: 1.6, maxWidth: 620 }}>
              {summary.total_steps - summary.measured_steps} of the {summary.total_steps} steps record
              no completion, so nothing above covers them. A customer shown at 100% has finished the
              measured part of the journey, not the whole of it.
            </p>
          )}
        </section>

        {/* ── 3. Per customer ───────────────────────────────────────────── */}
        <section>
          <h2 style={{ fontSize: 14, color: "#e2e8f0", margin: "0 0 4px", fontWeight: 600 }}>Customers</h2>
          <p style={{ fontSize: 12, color: "#64748b", margin: "0 0 14px", lineHeight: 1.6, maxWidth: 620 }}>
            Sorted by days without progress, so whoever needs a nudge is at the top. A customer counts
            as stuck once that figure passes the threshold for the step they are on — the same
            thresholds the intelligence layer acts on, so this page cannot call someone healthy on the
            day the platform writes to them.
          </p>

          <div style={{ ...card, padding: 0, overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5, minWidth: 620 }}>
              <thead>
                <tr style={{ color: "#64748b", textAlign: "left" }}>
                  {["Organization", "Progress", "Current step", "No progress for", "Since signup", "Status"].map(h => (
                    <th key={h} style={{ padding: "11px 14px", fontWeight: 600, borderBottom: "1px solid #1a2030", whiteSpace: "nowrap" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.organizations.length === 0 && (
                  <tr>
                    <td colSpan={6} style={{ padding: "22px 14px", color: "#64748b", textAlign: "center" }}>
                      No organizations yet.
                    </td>
                  </tr>
                )}
                {data.organizations.map(o => (
                  <tr key={o.organization_id} style={{ color: "#cbd5e1" }}>
                    <td style={{ padding: "11px 14px", borderBottom: "1px solid #141a26" }}>{o.name}</td>
                    <td style={{ padding: "11px 14px", borderBottom: "1px solid #141a26", whiteSpace: "nowrap" }}>
                      {o.progress_pct}%
                      <span style={{ color: "#64748b" }}> ({o.completed_steps}/{o.measured_steps})</span>
                    </td>
                    <td style={{ padding: "11px 14px", borderBottom: "1px solid #141a26" }}>
                      {o.current_step ? label(o.current_step) : "—"}
                    </td>
                    <td style={{ padding: "11px 14px", borderBottom: "1px solid #141a26", whiteSpace: "nowrap" }}>
                      {days(o.idle_days)}
                      {o.current_step && data.stuck_after_days[o.current_step] !== undefined && (
                        <span style={{ color: "#475569" }}> / {data.stuck_after_days[o.current_step]}</span>
                      )}
                    </td>
                    <td style={{ padding: "11px 14px", borderBottom: "1px solid #141a26", whiteSpace: "nowrap" }}>
                      {days(o.elapsed_days)}
                    </td>
                    <td style={{ padding: "11px 14px", borderBottom: "1px solid #141a26" }}>
                      <span style={{ color: STATUS_COLORS[o.status], fontWeight: 600, whiteSpace: "nowrap" }}>
                        {STATUS_LABELS[o.status]}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p style={{ fontSize: 11.5, color: "#475569", margin: "12px 0 0", lineHeight: 1.6, maxWidth: 620 }}>
            Only first completions are recorded, so a customer who disconnects a cloud account still
            counts as having finished that step. And only completions are recorded, never attempts:
            someone who tried three times and gave up is not distinguishable here from someone who
            never tried.
          </p>
        </section>
      </>
    );
  };

  return (
    <SettingsLayout
      breadcrumb="Analytics"
      title="Onboarding Analytics"
      subtitle={
        data
          ? `How far customers get, and where they stop. Measured at ${new Date(data.generated_at).toLocaleString()}.`
          : "How far customers get, and where they stop."
      }
      email={email}
    >
      {body()}
    </SettingsLayout>
  );
}
