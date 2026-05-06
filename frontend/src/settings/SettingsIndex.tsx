import React from "react";
import { useNavigate } from "react-router-dom";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

interface CardProps {
  icon: string;
  title: string;
  desc: string;
  href: string;
}

function SettingCard({ icon, title, desc, href }: CardProps) {
  const navigate = useNavigate();
  const [hovered, setHovered] = React.useState(false);

  return (
    <div
      onClick={() => navigate(href)}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? "#161926" : "#111827",
        border: `1px solid ${hovered ? "#ef4444" : "#1e2433"}`,
        borderRadius: 12, padding: "18px 20px",
        cursor: "pointer", display: "flex", alignItems: "center", gap: 14,
        transition: "all 0.15s",
      }}
    >
      <div style={{
        width: 40, height: 40, borderRadius: 10, flexShrink: 0,
        background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)",
        display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18,
      }}>
        {icon}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: "#f1f5f9", fontWeight: 600, fontSize: 14, marginBottom: 3 }}>{title}</div>
        <div style={{ color: "#4e627a", fontSize: 12.5, lineHeight: 1.5 }}>{desc}</div>
      </div>
      <div style={{ color: "#374151", fontSize: 18, flexShrink: 0 }}>›</div>
    </div>
  );
}

function SectionLabel({ children }: { children: string }) {
  return (
    <h2 style={{
      fontSize: 10.5, fontWeight: 700, color: "#374151",
      margin: "0 0 12px", textTransform: "uppercase", letterSpacing: "0.1em",
    }}>
      {children}
    </h2>
  );
}

export default function SettingsIndex() {
  const { loading, email } = useRequireAuth();

  if (loading) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  return (
    <SettingsLayout
      title="Settings"
      subtitle="Manage your personal and account settings in one place."
      email={email}
    >
      {/* Personal Settings */}
      <section style={{ marginBottom: 36 }}>
        <SectionLabel>Personal Settings</SectionLabel>
        <SettingCard
          icon="👤"
          title="Personal Data"
          desc="Manage your contact info, profile photo and personal details"
          href="/settings/personal-data"
        />
      </section>

      {/* Account Settings */}
      <section style={{ marginBottom: 36 }}>
        <SectionLabel>Account Settings</SectionLabel>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(270px, 1fr))", gap: 12 }}>
          <SettingCard
            icon="🏢"
            title="Company"
            desc="Manage your company name and basic details"
            href="/settings/company"
          />
          <SettingCard
            icon="💰"
            title="Rate Plans"
            desc="View and upgrade your cloud security plan"
            href="/settings/plans"
          />
        </div>
      </section>

      {/* Integrations */}
      <section>
        <SectionLabel>Integrations</SectionLabel>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(270px, 1fr))", gap: 12 }}>
          <SettingCard
            icon="🐙"
            title="GitHub"
            desc="Connect your GitHub org for CIS GitHub Benchmark scanning"
            href="/settings/github"
          />
        </div>
      </section>
    </SettingsLayout>
  );
}
