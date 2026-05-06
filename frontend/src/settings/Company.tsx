import React, { useEffect, useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

export default function Company() {
  const { loading: authLoading, email } = useRequireAuth();
  const [companyName, setCompanyName] = useState("");
  const [fetching,    setFetching]    = useState(true);
  const [saving,      setSaving]      = useState(false);
  const [saved,       setSaved]       = useState(false);
  const [error,       setError]       = useState("");

  // Load company name from existing dashboard API
  useEffect(() => {
    if (authLoading || !email) return;
    (async () => {
      try {
        const token = localStorage.getItem("niagaros_token") || "";
        const resp = await fetch(
          `${getApiBase()}/get-dashboard-data?email=${encodeURIComponent(email)}`,
          { headers: token ? { Authorization: `Bearer ${token}` } : {} }
        );
        const data = await resp.json();
        const name = data.accounts?.[0]?.name || "";
        setCompanyName(name);
      } catch { /* ignore */ }
      finally { setFetching(false); }
    })();
  }, [authLoading, email]);

  const handleSave = async () => {
    setSaving(true);
    setError("");
    try {
      const token = localStorage.getItem("niagaros_token") || "";
      const resp = await fetch(`${getApiBase()}/account`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ company_name: companyName.trim() }),
      });
      if (!resp.ok) {
        const d = await resp.json();
        throw new Error(d.error || "Save failed");
      }
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e: any) {
      setError(e.message || "Could not save. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  if (authLoading) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  return (
    <SettingsLayout title="Company" subtitle="Manage your company information." breadcrumb="Company" email={email}>

      {error && (
        <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, padding: "10px 14px", marginBottom: 20, color: "#fca5a5", fontSize: 13 }}>
          {error}
        </div>
      )}

      <div style={{ background: "#111827", border: "1px solid #1e2433", borderRadius: 14, padding: "28px 32px", maxWidth: 600 }}>
        <h3 style={{ fontSize: 14, fontWeight: 700, color: "#f1f5f9", margin: "0 0 6px" }}>Company Details</h3>
        <p style={{ fontSize: 12.5, color: "#4e627a", margin: "0 0 24px" }}>
          This information will appear on invoices and reports.
        </p>

        {fetching ? (
          <div style={{ color: "#4e627a", fontSize: 13 }}>Loading…</div>
        ) : (
          <>
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: "block", fontSize: 12, fontWeight: 600, color: "#6b7280", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Company name
              </label>
              <CompanyInput value={companyName} onChange={setCompanyName} placeholder="e.g. Acme Corp" />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button
                onClick={handleSave}
                disabled={saving || !companyName.trim()}
                style={{ background: saved ? "#16a34a" : "#ef4444", border: "none", borderRadius: 8, color: "#fff", fontSize: 13, fontWeight: 600, padding: "10px 24px", cursor: (saving || !companyName.trim()) ? "not-allowed" : "pointer", transition: "background 0.2s", opacity: (saving || !companyName.trim()) ? 0.6 : 1 }}
              >
                {saving ? "Saving…" : saved ? "✓ Saved" : "Save changes"}
              </button>
            </div>
          </>
        )}
      </div>
    </SettingsLayout>
  );
}

function CompanyInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  const [focused, setFocused] = React.useState(false);
  return (
    <input
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      style={{ width: "100%", boxSizing: "border-box", background: "#0d0f14", border: `1px solid ${focused ? "#ef4444" : "#1e2433"}`, borderRadius: 8, color: "#f1f5f9", fontSize: 13.5, padding: "10px 12px", outline: "none", transition: "border-color 0.15s" }}
    />
  );
}
