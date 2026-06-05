import React from "react";
import { useNavigate, useLocation } from "react-router-dom";

const NiagarosLogo = ({ size = 32 }: { size?: number }) => (
  <svg width={size * 0.75} height={size} viewBox="0 0 36 48" fill="none">
    <path
      d="M18 2 C18 2 3 20 3 31 C3 40.4 9.8 46 18 46 C26.2 46 33 40.4 33 31 C33 20 18 2 18 2 Z"
      stroke="#ef4444" strokeWidth="2.2" fill="none" strokeLinecap="round" strokeLinejoin="round"
    />
    <circle cx="12.5" cy="36.5" r="3.2" stroke="#ef4444" strokeWidth="1.7" fill="none" />
  </svg>
);

const SUB_NAV = [
  { label: "Personal Data", href: "/settings/personal-data" },
  { label: "Company",       href: "/settings/company" },
  { label: "Rate Plans",    href: "/settings/plans" },
  { label: "GitHub",        href: "/settings/github" },
];

interface Props {
  children: React.ReactNode;
  breadcrumb?: string;
  title: string;
  subtitle?: string;
  email?: string;
}

export default function SettingsLayout({ children, breadcrumb, title, subtitle, email }: Props) {
  const navigate  = useNavigate();
  const { pathname } = useLocation();

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#080b12", fontFamily: "system-ui,-apple-system,sans-serif" }}>

      {/* ── Sidebar ─────────────────────────────────────────────────────── */}
      <aside style={{ width: 220, background: "#0d0f14", borderRight: "1px solid #1a2030", display: "flex", flexDirection: "column", flexShrink: 0 }}>

        {/* Logo */}
        <div style={{ padding: "20px 16px 16px", borderBottom: "1px solid #1a2030", cursor: "pointer" }}
          onClick={() => navigate("/settings")}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <NiagarosLogo size={32} />
            <div>
              <span style={{ display: "block", fontSize: 14, fontWeight: 700, color: "#f1f5f9", letterSpacing: "0.2em" }}>NIAGAROS</span>
              <span style={{ display: "block", fontSize: 8, color: "#334155", letterSpacing: "0.15em", marginTop: 1 }}>CLOUD SECURITY</span>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ padding: "12px 0", flex: 1 }}>
          {/* Dashboard link — back to CSPM */}
          <a
            href="/niagaros-dashboard.html"
            style={{
              display: "flex", alignItems: "center", gap: 10,
              padding: "9px 14px", margin: "1px 6px", borderRadius: 7,
              color: "#9ca3af", fontSize: 13, fontWeight: 500,
              textDecoration: "none", transition: "all 0.12s",
            }}
            onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.background = "#161b27"; el.style.color = "#e5e7eb"; }}
            onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.background = "transparent"; el.style.color = "#9ca3af"; }}
          >
            <span>📊</span><span>Dashboard</span>
          </a>

          {/* Settings (active group) */}
          <div style={{
            display: "flex", alignItems: "center", gap: 10,
            padding: "9px 14px", margin: "1px 6px", borderRadius: 7,
            background: "#1e1428", color: "#fff", fontSize: 13, fontWeight: 500,
          }}>
            <span style={{ color: "#ef4444" }}>⚙</span><span>Settings</span>
          </div>

          {/* Sub-items */}
          {SUB_NAV.map(item => {
            const isActive = pathname === item.href;
            return (
              <div
                key={item.href}
                onClick={() => navigate(item.href)}
                style={{
                  display: "flex", alignItems: "center",
                  padding: "7px 14px 7px 40px", margin: "1px 6px", borderRadius: 7,
                  background: isActive ? "#16131e" : "transparent",
                  color: isActive ? "#f1f5f9" : "#6b7280",
                  fontSize: 12.5, fontWeight: isActive ? 600 : 400,
                  cursor: "pointer", transition: "all 0.12s",
                  borderLeft: isActive ? "2px solid #ef4444" : "2px solid transparent",
                }}
                onMouseEnter={e => { if (!isActive) { const el = e.currentTarget as HTMLElement; el.style.color = "#d1d5db"; el.style.background = "#111520"; } }}
                onMouseLeave={e => { if (!isActive) { const el = e.currentTarget as HTMLElement; el.style.color = "#6b7280"; el.style.background = "transparent"; } }}
              >
                {item.label}
              </div>
            );
          })}
        </nav>
      </aside>

      {/* ── Main ────────────────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: "100vh", overflow: "auto" }}>

        {/* Top bar */}
        <header style={{
          height: 52, background: "#0d0f14", borderBottom: "1px solid #1a2030",
          display: "flex", alignItems: "center", padding: "0 32px",
          justifyContent: "space-between", flexShrink: 0,
        }}>
          {/* Breadcrumb */}
          <nav style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 13 }}>
            <span
              onClick={() => navigate("/settings")}
              style={{ color: "#ef4444", cursor: "pointer", fontWeight: 500 }}
            >Settings</span>
            {breadcrumb && (
              <>
                <span style={{ color: "#374151" }}>/</span>
                <span style={{ color: "#9ca3af" }}>{breadcrumb}</span>
              </>
            )}
          </nav>

          {/* User pill */}
          {email && (
            <div style={{
              display: "flex", alignItems: "center", gap: 8,
              background: "#111827", border: "1px solid #1e2433",
              borderRadius: 20, padding: "5px 12px 5px 8px",
            }}>
              <div style={{
                width: 22, height: 22, borderRadius: "50%",
                background: "#ef4444", display: "flex", alignItems: "center",
                justifyContent: "center", fontSize: 10, fontWeight: 700, color: "#fff",
              }}>
                {email.charAt(0).toUpperCase()}
              </div>
              <span style={{ fontSize: 12, color: "#9ca3af" }}>{email}</span>
            </div>
          )}
        </header>

        {/* Page content */}
        <main style={{ flex: 1, padding: "36px 40px", background: "#0b0e17" }}>
          <h1 style={{ fontSize: 24, fontWeight: 700, color: "#f1f5f9", margin: "0 0 6px" }}>{title}</h1>
          {subtitle && <p style={{ fontSize: 13.5, color: "#64748b", margin: "0 0 32px", lineHeight: 1.6 }}>{subtitle}</p>}
          {children}
        </main>
      </div>
    </div>
  );
}
