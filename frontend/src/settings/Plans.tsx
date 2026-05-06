import React, { useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

// ── Types ─────────────────────────────────────────────────────────────────────
interface Plan {
  id: string;
  name: string;
  subtitle: string;
  monthlyPrice: string;
  yearlyPrice: string;
  yearlyNote?: string;
  badge?: string;
  current?: boolean;
  features: { label: string; included: boolean }[];
  addons?: string[];
  ctaLabel: string;
  ctaVariant: "primary" | "ghost" | "outline";
}

// ── Plan data ─────────────────────────────────────────────────────────────────
const PLANS: Plan[] = [
  {
    id: "developer",
    name: "Developer",
    subtitle: "For talent who likes to get 3x as much done in ⅓ of the time.",
    monthlyPrice: "€0",
    yearlyPrice: "€0",
    yearlyNote: "Free forever",
    current: true,
    features: [
      { label: "CSPM",               included: true  },
      { label: "Single-Cloud",       included: true  },
      { label: "Cross-Compliance",   included: true  },
      { label: "CIS AWS",            included: true  },
      { label: "ISO 27001",          included: true  },
      { label: "GDPR",               included: true  },
      { label: "NIST CSF 2.0",       included: true  },
      { label: "NIS 2",              included: true  },
      { label: "SOC 2",              included: true  },
      { label: "Self-Service",       included: true  },
      { label: "1:1 Onboarding",     included: false },
      { label: "Premium Support",    included: false },
    ],
    ctaLabel: "Current plan",
    ctaVariant: "ghost",
  },
  {
    id: "essentials",
    name: "Essentials",
    subtitle: "Enterprise-grade cloud security at startup-friendly pricing.",
    monthlyPrice: "€499",
    yearlyPrice: "€5,000",
    yearlyNote: "Save ~15%",
    badge: "Popular",
    features: [
      { label: "CSPM",               included: true  },
      { label: "Single-Cloud",       included: true  },
      { label: "Cross-Compliance",   included: true  },
      { label: "CIS AWS",            included: true  },
      { label: "ISO 27001",          included: true  },
      { label: "GDPR",               included: true  },
      { label: "NIST CSF 2.0",       included: true  },
      { label: "NIS 2",              included: true  },
      { label: "SOC 2",              included: true  },
      { label: "1:1 Onboarding",     included: true  },
      { label: "Premium Support",    included: false },
    ],
    ctaLabel: "Get Quote",
    ctaVariant: "primary",
  },
  {
    id: "midmarket",
    name: "Mid-Market",
    subtitle: "Cloud security without enterprise complexity or cost.",
    monthlyPrice: "€2,499",
    yearlyPrice: "€25,000",
    features: [
      { label: "CSPM",               included: true  },
      { label: "Single-Cloud",       included: true  },
      { label: "Cross-Compliance",   included: true  },
      { label: "CIS AWS",            included: true  },
      { label: "ISO 27001",          included: true  },
      { label: "GDPR",               included: true  },
      { label: "NIST CSF 2.0",       included: true  },
      { label: "NIS 2",              included: true  },
      { label: "SOC 2",              included: true  },
      { label: "1:1 Onboarding",     included: true  },
      { label: "Premium Support",    included: true  },
    ],
    addons: [
      "Regional Cloud Providers (EMEA, APAC, AMER)",
      "Code & CI/CD Security",
      "CNAPP",
      "Workload & Runtime Security",
      "Custom Compliance Checks & Scanners",
    ],
    ctaLabel: "Get Quote",
    ctaVariant: "outline",
  },
  {
    id: "enterprise",
    name: "Enterprise",
    subtitle: "Unified platform for cloud risk, protection and response.",
    monthlyPrice: "€20,000",
    yearlyPrice: "€200,000",
    features: [
      { label: "CSPM",               included: true },
      { label: "Multi-Cloud",        included: true },
      { label: "Cross-Compliance",   included: true },
      { label: "CIS AWS",            included: true },
      { label: "ISO 27001",          included: true },
      { label: "GDPR",               included: true },
      { label: "NIST CSF 2.0",       included: true },
      { label: "NIS 2",              included: true },
      { label: "SOC 2",              included: true },
      { label: "1:1 Onboarding",     included: true },
      { label: "Enterprise Support", included: true },
    ],
    addons: [
      "Regional Cloud Providers (EMEA, APAC, AMER)",
      "Code & CI/CD Security",
      "CNAPP",
      "Workload & Runtime Security",
      "Custom Compliance Checks & Scanners",
    ],
    ctaLabel: "Get Quote",
    ctaVariant: "outline",
  },
];

// ── Sub-components ────────────────────────────────────────────────────────────
function PlanCard({ plan, billing }: { plan: Plan; billing: "monthly" | "yearly" }) {
  const [hovered, setHovered] = useState(false);
  const isCurrent = !!plan.current;

  const ctaStyle: React.CSSProperties =
    plan.ctaVariant === "primary"
      ? { background: "#ef4444", color: "#fff", border: "none" }
      : plan.ctaVariant === "outline"
      ? { background: "transparent", color: "#ef4444", border: "1px solid #ef4444" }
      : { background: "#1e2433", color: "#6b7280", border: "1px solid #1e2433", cursor: "default" };

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: isCurrent ? "#111827" : hovered ? "#161926" : "#111827",
        border: `1px solid ${isCurrent ? "#ef4444" : hovered ? "#374151" : "#1e2433"}`,
        borderRadius: 14, padding: "24px 22px",
        display: "flex", flexDirection: "column", gap: 0,
        transition: "all 0.15s", position: "relative",
      }}
    >
      {/* Current plan indicator */}
      {isCurrent && (
        <div style={{
          position: "absolute", top: -1, left: 20, right: 20,
          height: 2, background: "#ef4444", borderRadius: "0 0 2px 2px",
        }} />
      )}

      {/* Badge */}
      {plan.badge && (
        <div style={{
          position: "absolute", top: 16, right: 16,
          fontSize: 10, fontWeight: 700, padding: "3px 8px", borderRadius: 4,
          background: "rgba(239,68,68,0.12)", color: "#ef4444",
          border: "1px solid rgba(239,68,68,0.3)", textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          {plan.badge}
        </div>
      )}

      {/* Plan name */}
      <div style={{ fontSize: 16, fontWeight: 700, color: "#f1f5f9", marginBottom: 6 }}>{plan.name}</div>
      <div style={{ fontSize: 12, color: "#4e627a", lineHeight: 1.5, marginBottom: 20, minHeight: 36 }}>{plan.subtitle}</div>

      {/* Price */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 4 }}>
          <span style={{ fontSize: 28, fontWeight: 800, color: "#f1f5f9" }}>
            {billing === "monthly" ? plan.monthlyPrice : plan.yearlyPrice}
          </span>
          <span style={{ fontSize: 12, color: "#4e627a" }}>
            {billing === "monthly" ? "/ month" : "/ year"}
          </span>
        </div>
        {(billing === "yearly" && plan.yearlyNote) && (
          <div style={{ fontSize: 11, color: "#16a34a", marginTop: 2 }}>✓ {plan.yearlyNote}</div>
        )}
        {plan.id !== "developer" && (
          <div style={{ fontSize: 10.5, color: "#374151", marginTop: 4 }}>
            Incl. 10 users · fair-use policies apply
          </div>
        )}
        {plan.id === "developer" && (
          <div style={{ fontSize: 10.5, color: "#374151", marginTop: 4 }}>
            Incl. 1 user · fair-use policies apply
          </div>
        )}
      </div>

      {/* Features */}
      <div style={{ flex: 1, marginBottom: 20 }}>
        {plan.features.map(f => (
          <div key={f.label} style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "5px 0", borderBottom: "1px solid #1a2030",
            fontSize: 12.5,
          }}>
            <span style={{ color: f.included ? "#16a34a" : "#374151", fontSize: 13, flexShrink: 0 }}>
              {f.included ? "✓" : "✕"}
            </span>
            <span style={{ color: f.included ? "#d1d5db" : "#374151" }}>{f.label}</span>
          </div>
        ))}

        {/* Add-ons */}
        {plan.addons && plan.addons.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 10.5, fontWeight: 700, color: "#374151", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6 }}>
              Optional Add-ons
            </div>
            {plan.addons.map(a => (
              <div key={a} style={{ display: "flex", alignItems: "flex-start", gap: 6, padding: "3px 0", fontSize: 11.5, color: "#4e627a" }}>
                <span style={{ color: "#ef4444", flexShrink: 0, marginTop: 1 }}>+</span>
                <span>{a}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* CTA */}
      <button
        disabled={isCurrent}
        onClick={() => {
          if (isCurrent) return;
          const subject = encodeURIComponent(`Quote Request – Niagaros ${plan.name} Plan`);
          const body = encodeURIComponent(
            `Hello Niagaros team,\n\nI'm interested in the ${plan.name} plan (${plan.monthlyPrice}/month).\nPlease send me more information.\n\nName: \nCompany: \nEmail: \n\nKind regards`
          );
          window.open(`mailto:teamniagaros@gmail.com?subject=${subject}&body=${body}`, "_blank");
        }}
        style={{
          ...ctaStyle, borderRadius: 8, padding: "10px 0",
          fontSize: 13, fontWeight: 600, cursor: isCurrent ? "default" : "pointer",
          transition: "opacity 0.15s", width: "100%",
        }}
        onMouseEnter={e => { if (!isCurrent) (e.currentTarget as HTMLElement).style.opacity = "0.85"; }}
        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.opacity = "1"; }}
      >
        {isCurrent ? "✓ Current plan" : plan.ctaLabel}
      </button>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function Plans() {
  const { loading, email } = useRequireAuth();
  const [billing, setBilling] = useState<"monthly" | "yearly">("monthly");

  if (loading) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  return (
    <SettingsLayout
      title="Rate Plans"
      subtitle="More pricing details for our cloud security platform are on request. Basic knowledge of the glossary, cloud and compliance is required."
      breadcrumb="Rate Plans"
      email={email}
    >
      {/* Billing toggle */}
      <div style={{ display: "flex", alignItems: "center", gap: 0, marginBottom: 28, background: "#111827", border: "1px solid #1e2433", borderRadius: 8, padding: 4, width: "fit-content" }}>
        {(["monthly", "yearly"] as const).map(b => (
          <button
            key={b}
            onClick={() => setBilling(b)}
            style={{
              padding: "7px 20px", borderRadius: 6, border: "none",
              background: billing === b ? "#ef4444" : "transparent",
              color: billing === b ? "#fff" : "#6b7280",
              fontSize: 13, fontWeight: 600, cursor: "pointer",
              transition: "all 0.15s", textTransform: "capitalize",
            }}
          >
            {b === "yearly" ? "Yearly  (save ~15%)" : "Monthly"}
          </button>
        ))}
      </div>

      {/* Plan cards grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: 14, marginBottom: 36 }}>
        {PLANS.map(plan => (
          <PlanCard key={plan.id} plan={plan} billing={billing} />
        ))}
      </div>

      {/* Info footer */}
      <div style={{
        background: "rgba(239,68,68,0.04)", border: "1px solid rgba(239,68,68,0.12)",
        borderRadius: 10, padding: "16px 20px",
        display: "flex", alignItems: "flex-start", gap: 12,
      }}>
        <span style={{ fontSize: 18, flexShrink: 0, marginTop: 1 }}>ℹ️</span>
        <div>
          <div style={{ color: "#f1f5f9", fontWeight: 600, fontSize: 13, marginBottom: 4 }}>Need a custom plan?</div>
          <div style={{ color: "#4e627a", fontSize: 12.5, lineHeight: 1.7 }}>
            Pricing for cyber security services can vary based on organisation size, scope, compliance needs, industry and contract length.
            Contact us for a tailored quote — <span style={{ color: "#ef4444" }}>info@niagaros.com</span>
          </div>
        </div>
      </div>
    </SettingsLayout>
  );
}
