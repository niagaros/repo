import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useRequireAuth } from "../settings/useRequireAuth";

// /onboarding — the guided, step-by-step accelerator described in the PVA:
// "The onboarding flow standardizes and accelerates setup across five
// critical stages." This page is the missing backbone that ties the
// individual settings pages together into one sequence with a visible
// progress indicator.
//
// Honesty over completeness: only Step 1 (Cloud Infrastructure) has a real
// backend signal to check today. Steps 2, 3, 4 and 5 (Team, Auditors,
// Workspace, Training) have no settings page or API behind them yet — they
// are shown as "In progress" rather than faked as clickable/complete.
// (Note: the existing /settings/github page is a source-code scanner
// connection, not the Jira/ServiceNow-style "Connect Workspace" step #268
// describes — deliberately not reused here to avoid overstating progress.)

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

type StepState = "done" | "not_done" | "unavailable" | "loading";

interface Step {
  n: number;
  id: string;
  title: string;
  description: string;
  href: string;
  available: boolean;
}

const STEPS: Step[] = [
  {
    n: 1, id: "infrastructure",
    title: "Integrate Cloud Infrastructure",
    description: "Connect AWS so Niagaros can start scanning for misconfigurations.",
    href: "/settings/infrastructure", available: true,
  },
  {
    n: 2, id: "team",
    title: "Invite Team",
    description: "Add team members, assign roles and enforce MFA policies.",
    href: "/settings/team", available: false,
  },
  {
    n: 3, id: "auditor",
    title: "Invite Auditors",
    description: "Give auditors time-limited, read-only access to evidence.",
    href: "/settings/auditor", available: false,
  },
  {
    n: 4, id: "workspace",
    title: "Connect Workspace",
    description: "Sync findings into Jira, ServiceNow or Monday.com.",
    href: "/settings/workspace", available: false,
  },
  {
    n: 5, id: "training",
    title: "Complete Security Training",
    description: "Assign and track baseline security awareness training.",
    href: "/settings/training", available: false,
  },
];

export default function OnboardingHome() {
  const { loading: authLoading, email } = useRequireAuth();
  const navigate = useNavigate();
  const [infraState, setInfraState] = useState<StepState>("loading");

  const token = () => localStorage.getItem("niagaros_token") || "";
  const authHeader = () => ({ Authorization: `Bearer ${token()}` });

  // Step 1 is the only step with a real backend signal today — same check
  // used by Infrastructure.tsx, kept in sync deliberately rather than
  // introducing a second source of truth.
  useEffect(() => {
    if (authLoading || !email) return;
    (async () => {
      try {
        const resp = await fetch(`${getApiBase()}/get-dashboard-data?email=${encodeURIComponent(email)}`, {
          cache: "no-store",
          headers: authHeader(),
        });
        const data = await resp.json();
        if (data.needs_onboarding || data.status === "disconnected") {
          setInfraState("not_done");
        } else {
          setInfraState("done");
        }
      } catch {
        setInfraState("not_done");
      }
    })();
  }, [authLoading, email]);

  const stateFor = (step: Step): StepState => {
    if (!step.available) return "unavailable";
    if (step.id === "infrastructure") return infraState;
    return "not_done";
  };

  const doneCount = STEPS.filter(s => stateFor(s) === "done").length;
  const progressPct = Math.round((doneCount / STEPS.length) * 100);

  if (authLoading || infraState === "loading") return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  return (
    <div style={{ minHeight: "100vh", background: "#080b12", fontFamily: "system-ui,-apple-system,sans-serif", padding: "48px 24px" }}>
      <div style={{ maxWidth: 720, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ marginBottom: 8 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: "#ef4444", letterSpacing: "0.15em" }}>ONBOARDING</span>
        </div>
        <h1 style={{ fontSize: 26, fontWeight: 700, color: "#f1f5f9", margin: "0 0 8px" }}>
          Get Niagaros fully set up
        </h1>
        <p style={{ fontSize: 13.5, color: "#64748b", margin: "0 0 28px", lineHeight: 1.6 }}>
          Five steps to reach full security and compliance coverage. Come back any time —
          your progress is saved.
        </p>

        {/* Progress bar */}
        <div style={{ marginBottom: 32 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontSize: 12, color: "#9ca3af", fontWeight: 600 }}>{doneCount} of {STEPS.length} steps complete</span>
            <span style={{ fontSize: 12, color: "#ef4444", fontWeight: 700 }}>{progressPct}%</span>
          </div>
          <div style={{ height: 8, borderRadius: 4, background: "#111827", overflow: "hidden" }}>
            <div style={{
              height: "100%", width: `${progressPct}%`, background: "#ef4444",
              borderRadius: 4, transition: "width 0.3s ease",
            }} />
          </div>
        </div>

        {/* Step cards */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {STEPS.map(step => {
            const state = stateFor(step);
            const clickable = state === "not_done";
            return (
              <div
                key={step.id}
                onClick={() => { if (clickable) navigate(step.href); }}
                style={{
                  display: "flex", alignItems: "center", gap: 16,
                  background: "#111827",
                  border: `1px solid ${state === "done" ? "rgba(22,163,74,0.35)" : "#1e2433"}`,
                  borderRadius: 12, padding: "16px 20px",
                  cursor: clickable ? "pointer" : "default",
                  opacity: state === "unavailable" ? 0.55 : 1,
                }}
              >
                <div style={{
                  width: 32, height: 32, borderRadius: "50%", flexShrink: 0,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 13, fontWeight: 700,
                  background: state === "done" ? "rgba(22,163,74,0.15)" : "#1a2030",
                  color: state === "done" ? "#4ade80" : "#6b7280",
                }}>
                  {state === "done" ? "✓" : step.n}
                </div>

                <div style={{ flex: 1 }}>
                  <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 3 }}>{step.title}</div>
                  <div style={{ color: "#4e627a", fontSize: 12.5 }}>{step.description}</div>
                </div>

                {state === "done" && (
                  <span style={{ fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 4, background: "rgba(22,163,74,0.12)", color: "#4ade80", border: "1px solid rgba(22,163,74,0.3)" }}>
                    Done
                  </span>
                )}
                {state === "not_done" && (
                  <span style={{ fontSize: 11, color: "#ef4444", fontWeight: 600 }}>Set up →</span>
                )}
                {state === "unavailable" && (
                  <span style={{ fontSize: 10, color: "#4e627a", fontWeight: 600 }}>In progress</span>
                )}
              </div>
            );
          })}
        </div>

        <div style={{ marginTop: 28, textAlign: "center" }}>
          <span
            onClick={() => navigate("/settings")}
            style={{ fontSize: 12.5, color: "#6b7280", cursor: "pointer" }}
          >
            Skip for now — go to Settings →
          </span>
        </div>
      </div>
    </div>
  );
}
