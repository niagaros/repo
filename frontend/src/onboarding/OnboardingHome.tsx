import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useRequireAuth } from "../settings/useRequireAuth";

// /onboarding — the guided, step-by-step accelerator described in the PVA:
// "The onboarding flow standardizes and accelerates setup across five
// critical stages." This page is the missing backbone that ties the
// individual settings pages together into one sequence with a visible
// progress indicator.
//
// Honesty over completeness: steps 1, 2 and 3 (Cloud Infrastructure, Team,
// Auditors) have real backend signals to check today. Step 4 (Workspace)
// now has a page and one working category, ticketing, so it is clickable —
// but completion of it is not yet derived from a backend signal the way the
// first three are, so it does not tick itself off. Steps 5, 6 and 7 have no
// page or API behind them at all and are shown as "In progress" rather than
// faked as clickable or complete.
// (Note: the existing /settings/github page is a source-code scanner
// connection, not the Jira/ServiceNow-style "Connect Workspace" step #268
// describes. It is linked from the workspace hub rather than counted as it.)
//
// Every step's state comes from the backend, which works it out from the
// actual state of the customer's environment rather than from anything this
// page claims. The call is allowed to fail: steps then read as "not done"
// rather than taking the page down with it. This is the first thing a new
// customer sees, so it has to render even when something behind it does not
// answer.

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

type StepState = "done" | "not_done" | "unavailable" | "loading";

interface ProgressStep {
  step: string;
  done: boolean;
  available: boolean;
  // When this step was first completed. Kept even if the step is later
  // undone and redone: what matters is how long this customer took to get
  // here, not when it was last true.
  completed_at: string | null;
}

interface ProgressResponse {
  steps: ProgressStep[];
  completed_count: number;
  total_count: number;
}

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
    href: "/settings/team", available: true,
  },
  {
    n: 3, id: "auditor",
    title: "Invite Auditors",
    description: "Give auditors time-limited, read-only access to evidence.",
    href: "/settings/auditor", available: true,
  },
  {
    n: 4, id: "workspace",
    title: "Connect Workspaces",
    description: "Sync findings into source control, ticketing, communication, identity, SIEM and CI/CD.",
    href: "/settings/workspace", available: true,
  },
  // Steps 5 and 6 were added to the onboarding issue after this project's
  // scope was agreed (#281, #282). They are listed here because the wizard
  // has to show the journey as it actually is — leaving them out would make
  // the progress indicator claim a completeness that does not exist.
  {
    n: 5, id: "compliance",
    title: "Configure Compliance",
    description: "Select and configure the compliance frameworks that apply to your organization.",
    href: "/settings/compliance", available: false,
  },
  {
    n: 6, id: "governance",
    title: "Configure Governance",
    description: "Set up policies, ownership and review cycles for your security posture.",
    href: "/settings/governance", available: false,
  },
  {
    n: 7, id: "training",
    title: "Complete Security Training",
    description: "Assign and track baseline security awareness training.",
    href: "/settings/training", available: false,
  },
];

export default function OnboardingHome() {
  const { loading: authLoading, email } = useRequireAuth();
  const navigate = useNavigate();
  // One call, and the backend decides what is done — not this page.
  //
  // Until now the wizard worked that out itself from three separate
  // endpoints. That is fine for drawing a bar, but the backend also records
  // when a step was first completed, and a completion the client asserted
  // would be a tick box by another name. The whole design rests on there
  // being no tick box: a step counts as done because the system can see it
  // is, not because somebody says so.
  //
  // The recorded moment is what the intelligence layer and the analytics
  // dashboard need — neither can answer "how long has this customer been
  // stuck here" without it.
  const [progress, setProgress] = useState<ProgressResponse | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);

  const token = () => localStorage.getItem("niagaros_token") || "";
  const authHeader = () => ({ Authorization: `Bearer ${token()}` });

  useEffect(() => {
    if (authLoading || !email) return;
    (async () => {
      try {
        const resp = await fetch(`${getApiBase()}/onboarding/progress`, {
          cache: "no-store",
          headers: authHeader(),
        });
        if (!resp.ok) throw new Error(String(resp.status));
        setProgress(await resp.json());
      } catch {
        // This is the first page a new customer sees. If something behind it
        // does not answer, it still has to render — every step then reads as
        // not done rather than taking the page down.
        setLoadFailed(true);
      }
    })();
  }, [authLoading, email]);

  const stateFor = (step: Step): StepState => {
    if (!step.available) return "unavailable";
    const found = progress?.steps.find(s => s.step === step.id);
    return found?.done ? "done" : "not_done";
  };

  const doneCount = STEPS.filter(s => stateFor(s) === "done").length;
  const progressPct = Math.round((doneCount / STEPS.length) * 100);

  if (authLoading || (!progress && !loadFailed)) return (
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
          Work through these steps to reach full security and compliance coverage. Come back any time —
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
            // A finished step stays reachable. Only steps that do not exist
            // yet are closed off. Locking a completed step would leave no way
            // back to it from here, and the settings sidebar has no link to
            // this page either — so the wizard and the pages it points at
            // would be sealed off from each other in both directions.
            const clickable = state === "not_done" || state === "done";
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
