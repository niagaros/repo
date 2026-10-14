import React from "react";

// Small shared pieces for the onboarding steps 5–7 pages (Compliance,
// Governance, Training). Styling matches the existing settings pages
// (Team.tsx, Auditors.tsx) so the steps look like one product.

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// Calls the governance API with the caller's token and turns any failure into
// a readable message — never a raw stack trace or an HTML error page.
export async function api<T = any>(path: string, method = "GET", body?: unknown): Promise<T> {
  const token = localStorage.getItem("niagaros_token") || "";
  let resp: Response;
  try {
    resp = await fetch(`${getApiBase()}${path}`, {
      method,
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "Could not reach Niagaros. Check your connection and try again.");
  }
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const fallback = resp.status === 401 ? "Your session has expired. Please sign in again."
      : resp.status === 403 ? "You don't have permission to do this."
      : "Something went wrong. Please try again.";
    throw new ApiError(resp.status, (data && typeof data.error === "string" && data.error) || fallback);
  }
  return data as T;
}

export const cardStyle: React.CSSProperties = {
  background: "#111827", border: "1px solid #1e2433", borderRadius: 14,
  padding: "20px 24px", marginBottom: 20,
};

export const inputStyle: React.CSSProperties = {
  width: "100%", boxSizing: "border-box", background: "#0d1017", border: "1px solid #1e2433",
  borderRadius: 8, padding: "9px 12px", color: "#e2e8f0", fontSize: 13, fontFamily: "inherit",
};

export const labelStyle: React.CSSProperties = {
  display: "block", fontSize: 11, color: "#6b7280", marginBottom: 5,
};

export const sectionTitle: React.CSSProperties = {
  color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 4,
};

export const sectionHint: React.CSSProperties = {
  color: "#4e627a", fontSize: 12.5, marginBottom: 16, lineHeight: 1.55,
};

export const rowStyle: React.CSSProperties = {
  display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderTop: "1px solid #1a2030",
  flexWrap: "wrap",
};

export function Badge({ color, bg, children }: { color: string; bg: string; children: React.ReactNode }) {
  return (
    <span style={{ fontSize: 10.5, fontWeight: 700, padding: "2px 9px", borderRadius: 4, background: bg, color, whiteSpace: "nowrap" }}>
      {children}
    </span>
  );
}

export const tone = {
  green:  { color: "#4ade80", bg: "rgba(22,163,74,0.12)" },
  amber:  { color: "#fbbf24", bg: "rgba(251,191,36,0.12)" },
  red:    { color: "#f87171", bg: "rgba(239,68,68,0.12)" },
  blue:   { color: "#60a5fa", bg: "rgba(59,130,246,0.12)" },
  grey:   { color: "#9ca3af", bg: "#1a2030" },
};

export function Button({ onClick, disabled, kind = "primary", children, type = "button" }: {
  onClick?: () => void; disabled?: boolean; kind?: "primary" | "ghost" | "danger"; children: React.ReactNode;
  type?: "button" | "submit";
}) {
  const styles: Record<string, React.CSSProperties> = {
    primary: { background: "#ef4444", color: "#fff", border: "none" },
    ghost:   { background: "none", color: "#9ca3af", border: "1px solid #374151" },
    danger:  { background: "none", color: "#f87171", border: "1px solid rgba(239,68,68,0.4)" },
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      style={{
        ...styles[kind], borderRadius: 8, padding: kind === "primary" ? "9px 18px" : "5px 12px",
        fontSize: kind === "primary" ? 13 : 12, fontWeight: 600,
        cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.6 : 1, whiteSpace: "nowrap",
      }}
    >
      {children}
    </button>
  );
}

export function ErrorBox({ message }: { message: string }) {
  if (!message) return null;
  return (
    <div role="alert" style={{ color: "#f87171", fontSize: 12.5, marginTop: 10, lineHeight: 1.5 }}>{message}</div>
  );
}

export function Field({ label, children, width }: { label: string; children: React.ReactNode; width?: number | string }) {
  return (
    <div style={{ flex: width ? `0 0 ${typeof width === "number" ? width + "px" : width}` : "1 1 180px", minWidth: 0 }}>
      <label style={labelStyle}>{label}</label>
      {children}
    </div>
  );
}

// "Expires in 12 days" / "Expired 3 days ago" with a colour that matches urgency.
export function ExpiryBadge({ days, reminderDays, label = "Expires" }: { days: number | null; reminderDays: number; label?: string }) {
  if (days === null || days === undefined) return null;
  if (days < 0) return <Badge {...tone.red}>{label === "Review" ? "Review overdue" : "Expired"} {Math.abs(days)}d ago</Badge>;
  if (days <= reminderDays) return <Badge {...tone.amber}>{label} in {days}d</Badge>;
  return null;
}

export function StepBanner({ step, done, doneText, todoText }: { step: number; done: boolean; doneText: string; todoText: string }) {
  return (
    <div style={{
      ...cardStyle, display: "flex", alignItems: "center", gap: 14,
      borderColor: done ? "rgba(22,163,74,0.35)" : "#1e2433",
    }}>
      <div style={{
        width: 32, height: 32, borderRadius: "50%", flexShrink: 0, display: "flex", alignItems: "center",
        justifyContent: "center", fontSize: 13, fontWeight: 700,
        background: done ? "rgba(22,163,74,0.15)" : "#1a2030", color: done ? "#4ade80" : "#9ca3af",
      }}>
        {done ? "✓" : step}
      </div>
      <div style={{ flex: 1, color: done ? "#4ade80" : "#9ca3af", fontSize: 13, lineHeight: 1.5 }}>
        <strong style={{ color: "#f1f5f9" }}>Onboarding step {step}: </strong>{done ? doneText : todoText}
      </div>
      <a href="/onboarding" style={{ color: "#ef4444", fontSize: 12, fontWeight: 600, textDecoration: "none", whiteSpace: "nowrap" }}>
        All steps →
      </a>
    </div>
  );
}

// Date-only values ("2026-03-01") are parsed as local dates; new Date("2026-03-01") would be UTC
// midnight and show the previous day west of Greenwich.
export const fmtDate = (iso: string | null) => {
  if (!iso) return "—";
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso);
  const d = m ? new Date(+m[1], +m[2] - 1, +m[3]) : new Date(iso);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
};
export const fmtDateTime = (iso: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");
