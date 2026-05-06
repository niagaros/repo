import React, { useState, useEffect, useRef } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

const TITLES   = ["", "Mr.", "Mrs.", "Ms.", "Dr.", "Prof."];
const SEX_OPTS = ["", "Male", "Female", "Non-binary", "Prefer not to say"];
const LANGS    = ["English", "Nederlands", "Deutsch", "Français", "Español"];

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

const inputStyle: React.CSSProperties = {
  width: "100%", boxSizing: "border-box",
  background: "#0d0f14", border: "1px solid #1e2433", borderRadius: 8,
  color: "#f1f5f9", fontSize: 13.5, padding: "10px 12px",
  outline: "none", transition: "border-color 0.15s",
};

const labelStyle: React.CSSProperties = {
  display: "block", fontSize: 12, fontWeight: 600,
  color: "#6b7280", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em",
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <label style={labelStyle}>{label}</label>
      {children}
    </div>
  );
}

function FocusInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const [focused, setFocused] = React.useState(false);
  return (
    <input {...props}
      style={{ ...inputStyle, borderColor: focused ? "#ef4444" : "#1e2433", ...props.style }}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
    />
  );
}

function FocusSelect(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  const [focused, setFocused] = React.useState(false);
  return (
    <select {...props}
      style={{ ...inputStyle, borderColor: focused ? "#ef4444" : "#1e2433", appearance: "none", cursor: "pointer", ...props.style }}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
    />
  );
}

export default function PersonalData() {
  const { loading: authLoading, email } = useRequireAuth();
  const fileRef = useRef<HTMLInputElement>(null);

  const [avatar,       setAvatar]       = useState("");
  const [fullName,     setFullName]     = useState("");
  const [title,        setTitle]        = useState("");
  const [phone,        setPhone]        = useState("");
  const [sex,          setSex]          = useState("");
  const [dob,          setDob]          = useState("");
  const [placeOfBirth, setPlaceOfBirth] = useState("");
  const [nationality,  setNationality]  = useState("");
  const [language,     setLanguage]     = useState("English");
  const [fetching,     setFetching]     = useState(true);
  const [saving,       setSaving]       = useState(false);
  const [saved,        setSaved]        = useState(false);
  const [error,        setError]        = useState("");

  // Load profile from API
  useEffect(() => {
    if (authLoading || !email) return;
    (async () => {
      try {
        const token = localStorage.getItem("niagaros_token") || "";
        const resp = await fetch(`${getApiBase()}/profile`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        if (!resp.ok) return;
        const data = await resp.json();
        if (data.avatar_data)    setAvatar(data.avatar_data);
        if (data.full_name)      setFullName(data.full_name);
        if (data.title)          setTitle(data.title);
        if (data.phone)          setPhone(data.phone);
        if (data.sex)            setSex(data.sex);
        if (data.date_of_birth)  setDob(data.date_of_birth);
        if (data.place_of_birth) setPlaceOfBirth(data.place_of_birth);
        if (data.nationality)    setNationality(data.nationality);
        if (data.language)       setLanguage(data.language);
      } catch { /* silently ignore — user can still edit */ }
      finally { setFetching(false); }
    })();
  }, [authLoading, email]);

  const handlePhotoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) { setError("Photo must be under 2 MB."); return; }
    const reader = new FileReader();
    reader.onload = ev => setAvatar(ev.target?.result as string);
    reader.readAsDataURL(file);
  };

  const handleSave = async () => {
    setSaving(true);
    setError("");
    try {
      const token = localStorage.getItem("niagaros_token") || "";
      const resp = await fetch(`${getApiBase()}/profile`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          full_name: fullName, title, phone, sex,
          date_of_birth: dob || null,
          place_of_birth: placeOfBirth,
          nationality, language,
          avatar_data: avatar || null,
        }),
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

  if (authLoading || fetching) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  return (
    <SettingsLayout
      title="Personal Information"
      subtitle="Manage your personal profile information and account preferences."
      breadcrumb="Personal Data"
      email={email}
    >
      {error && (
        <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, padding: "10px 14px", marginBottom: 20, color: "#fca5a5", fontSize: 13 }}>
          {error}
        </div>
      )}

      {/* Profile card */}
      <div style={{ background: "#111827", border: "1px solid #1e2433", borderRadius: 14, padding: "28px 32px", marginBottom: 24 }}>
        <h3 style={{ fontSize: 14, fontWeight: 700, color: "#f1f5f9", margin: "0 0 24px" }}>Profile</h3>

        <div style={{ display: "flex", gap: 32, alignItems: "flex-start", flexWrap: "wrap" }}>
          {/* Avatar */}
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 10, flexShrink: 0 }}>
            {avatar ? (
              <img src={avatar} alt="avatar" style={{ width: 88, height: 88, borderRadius: "50%", objectFit: "cover", border: "3px solid #1e2433" }} />
            ) : (
              <div style={{ width: 88, height: 88, borderRadius: "50%", background: "linear-gradient(135deg,#ef4444,#b91c1c)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 32, fontWeight: 700, color: "#fff", border: "3px solid #1e2433" }}>
                {(fullName || email).charAt(0).toUpperCase()}
              </div>
            )}
            <input ref={fileRef} type="file" accept="image/*" style={{ display: "none" }} onChange={handlePhotoChange} />
            <button onClick={() => fileRef.current?.click()} style={{ background: "#1e2433", border: "1px solid #2d3748", borderRadius: 7, color: "#e5e7eb", fontSize: 12, padding: "6px 14px", cursor: "pointer" }}>
              Upload
            </button>
            {avatar && (
              <button onClick={() => { setAvatar(""); if (fileRef.current) fileRef.current.value = ""; }} style={{ background: "transparent", border: "none", color: "#ef4444", fontSize: 12, cursor: "pointer" }}>
                Remove
              </button>
            )}
          </div>

          {/* Fields */}
          <div style={{ flex: 1, minWidth: 280 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 20px" }}>
              <div style={{ gridColumn: "1 / -1" }}>
                <Field label="Full name">
                  <FocusInput placeholder="Jane Doe" value={fullName} onChange={e => setFullName(e.target.value)} />
                </Field>
              </div>
              <Field label="Title">
                <FocusSelect value={title} onChange={e => setTitle(e.target.value)}>
                  {TITLES.map(t => <option key={t} value={t}>{t || "Select title"}</option>)}
                </FocusSelect>
              </Field>
              <Field label="Email">
                <FocusInput value={email} readOnly style={{ ...inputStyle, color: "#6b7280", cursor: "not-allowed" }} />
              </Field>
              <Field label="Phone">
                <FocusInput placeholder="+31 6 12345678" value={phone} onChange={e => setPhone(e.target.value)} />
              </Field>
              <Field label="Sex">
                <FocusSelect value={sex} onChange={e => setSex(e.target.value)}>
                  {SEX_OPTS.map(s => <option key={s} value={s}>{s || "Select sex"}</option>)}
                </FocusSelect>
              </Field>
              <Field label="Date of birth">
                <FocusInput type="date" value={dob} onChange={e => setDob(e.target.value)} />
              </Field>
              <Field label="Place of birth">
                <FocusInput placeholder="Country" value={placeOfBirth} onChange={e => setPlaceOfBirth(e.target.value)} />
              </Field>
              <div style={{ gridColumn: "1 / -1" }}>
                <Field label="Nationality">
                  <FocusInput placeholder="Nationality" value={nationality} onChange={e => setNationality(e.target.value)} />
                </Field>
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 4 }}>
              <button onClick={handleSave} disabled={saving} style={{ background: saved ? "#16a34a" : "#ef4444", border: "none", borderRadius: 8, color: "#fff", fontSize: 13, fontWeight: 600, padding: "10px 24px", cursor: saving ? "not-allowed" : "pointer", transition: "background 0.2s", opacity: saving ? 0.7 : 1 }}>
                {saving ? "Saving…" : saved ? "✓ Saved" : "Save changes"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Preferences */}
      <div style={{ background: "#111827", border: "1px solid #1e2433", borderRadius: 14, padding: "28px 32px" }}>
        <h3 style={{ fontSize: 14, fontWeight: 700, color: "#f1f5f9", margin: "0 0 24px" }}>Preferences / Authentication</h3>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 20px", maxWidth: 560 }}>
          <Field label="Default language">
            <FocusSelect value={language} onChange={e => setLanguage(e.target.value)}>
              {LANGS.map(l => <option key={l} value={l}>{l}</option>)}
            </FocusSelect>
          </Field>
          <Field label="Email">
            <div style={{ display: "flex", alignItems: "center", gap: 10, background: "#0d0f14", border: "1px solid #1e2433", borderRadius: 8, padding: "10px 12px" }}>
              <span style={{ fontSize: 13, color: "#f1f5f9", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{email}</span>
              <span style={{ fontSize: 11, fontWeight: 700, padding: "2px 7px", borderRadius: 4, background: "rgba(22,163,74,0.15)", color: "#4ade80", border: "1px solid rgba(22,163,74,0.3)", flexShrink: 0 }}>Active</span>
              <span style={{ fontSize: 11, color: "#16a34a", flexShrink: 0 }}>✓ Verified</span>
            </div>
          </Field>
        </div>
      </div>
    </SettingsLayout>
  );
}
