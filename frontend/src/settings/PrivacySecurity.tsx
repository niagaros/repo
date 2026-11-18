import React, { useCallback, useEffect, useState } from "react";
import {
  associateWebAuthnCredential, confirmUserAttribute, fetchAuthSession, sendUserAttributeVerificationCode,
  setUpTOTP, signOut, updateMFAPreference, verifyTOTPSetup,
} from "aws-amplify/auth";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

// /settings/user/privacy-security — issue #291. Cognito is the authority for email verification, TOTP and passkeys
// (WebAuthn: Cognito checks the challenge, origin and relying-party id; the fingerprint or face never leaves the
// device). /account-security adds the PIN, recovery codes, sessions, the security history and the step-up rule: a
// sign-in from the last 15 minutes (and the PIN, if set) before anything sensitive changes.

function apiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}
const PASSKEY_DOMAIN = "niagaros.com";
const onPasskeyDomain = () => location.hostname === PASSKEY_DOMAIN || location.hostname.endsWith("." + PASSKEY_DOMAIN);

type Overview = {
  email: string; email_verified: boolean;
  phone: { number?: string; verified: boolean; available: boolean; reason: string };
  totp: { enabled: boolean; preferred: boolean };
  passkeys: { id: string; name?: string; created_at?: string; authenticator?: string }[] | null; passkeys_error?: string;
  pin: { set: boolean; set_at?: string; locked_until?: string; used_for: string };
  recovery_codes: { remaining: number; generated_at?: string };
  session: { signed_in_at?: string; expires_at?: string; recent_enough_for_changes: boolean; step_up_minutes: number };
  sessions: { current: boolean; signed_in_at?: string; first_seen: string; last_seen: string; ip?: string; user_agent?: string; signed_out_at?: string }[];
  events: { at: string; event: string; outcome: string; ip?: string; user_agent?: string; detail?: any }[];
  policy: { organization: string; mfa_required: boolean; role: string; managed_in?: string } | null;
  assessment: { status: string; required: string[]; recommendations: string[] };
  federation: { available: boolean; reason: string };
};

const STATUS: Record<string, [string, string, string]> = {
  protected: ["Protected", "#16a34a", "Your required sign-in protections are in place."],
  action_required: ["Action required", "#ef4444", "Something your account or organization requires is missing."],
  review_recommended: ["Review recommended", "#f59e0b", "Your account works, but it could be better protected."],
  restricted: ["Restricted", "#ef4444", "A policy or security event limits this account."],
  unknown: ["Unknown", "#64748b", "Niagaros could not determine the full status right now."],
};
const EVENT_LABEL: Record<string, string> = {
  pin_set: "Security PIN set", pin_changed: "Security PIN changed", pin_removed: "Security PIN removed",
  pin_failed: "Wrong security PIN", pin_locked: "Security PIN locked after too many attempts",
  recovery_codes_generated: "Recovery codes created", recovery_code_used: "Recovery code used: two-step verification reset",
  recovery_failed: "Recovery attempt failed", authenticator_app_disabled: "Authenticator app turned off",
  authenticator_app_disable_refused: "Turning off the authenticator app was refused (organization policy)",
  authenticator_app_changed: "Authenticator app setting changed", email_verification_changed: "Email verification changed",
  passkeys_changed: "Number of passkeys changed", passkey_removed: "Passkey removed",
  signed_out_everywhere: "Signed out everywhere", new_sign_in_session_seen: "New sign-in",
  step_up_required: "Change refused: sign-in too old",
};

const card: React.CSSProperties = { background: "#0d0f14", border: "1px solid #1a2030", borderRadius: 12, padding: "18px 20px", marginBottom: 16 };
const h2: React.CSSProperties = { color: "#f1f5f9", fontSize: 15, fontWeight: 700, margin: "0 0 4px" };
const note: React.CSSProperties = { color: "#64748b", fontSize: 12.5, lineHeight: 1.6, margin: "0 0 10px" };
const input: React.CSSProperties = { background: "#080b12", border: "1px solid #1e2433", borderRadius: 8, color: "#f1f5f9", fontSize: 13.5, padding: "9px 11px", minWidth: 0 };
const btn: React.CSSProperties = { background: "#ef4444", color: "#fff", border: "none", borderRadius: 8, padding: "9px 14px", fontSize: 13, fontWeight: 600, cursor: "pointer" };
const ghost: React.CSSProperties = { ...btn, background: "transparent", color: "#cbd5e1", border: "1px solid #1e2433" };
const pill = (color: string): React.CSSProperties => ({ display: "inline-block", fontSize: 11, fontWeight: 700, padding: "2px 9px", borderRadius: 20, color, background: color + "22", border: `1px solid ${color}55` });
const fmt = (d?: string) => (d ? new Date(d).toLocaleString() : "—");
const row: React.CSSProperties = { display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" };

function Section({ id, title, status, children }: { id: string; title: string; status?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section id={id} aria-labelledby={id + "-h"} style={card}>
      <div style={{ ...row, justifyContent: "space-between", marginBottom: 6 }}>
        <h2 id={id + "-h"} style={h2}>{title}</h2>{status}
      </div>
      {children}
    </section>
  );
}

export default function PrivacySecurity() {
  const { loading, email } = useRequireAuth();
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [pin, setPin] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [emailCode, setEmailCode] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [totpSecret, setTotpSecret] = useState("");
  const [totpUri, setTotpUri] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [newPin, setNewPin] = useState("");
  const [platformAuth, setPlatformAuth] = useState<boolean | null>(null);

  const token = async () => (await fetchAuthSession()).tokens?.accessToken?.toString() || "";
  const load = useCallback(async () => {
    setError("");
    try {
      const r = await fetch(`${apiBase()}/account-security`, { headers: { Authorization: `Bearer ${await token()}` } });
      const b = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(b.error || `Could not load your security settings (HTTP ${r.status}).`);
      setData(b);
    } catch (e: any) { setError(e.message); }
  }, []);

  useEffect(() => { if (!loading) load(); }, [loading, load]);
  useEffect(() => {
    const PKC = (window as any).PublicKeyCredential;
    if (!PKC?.isUserVerifyingPlatformAuthenticatorAvailable) { setPlatformAuth(false); return; }
    PKC.isUserVerifyingPlatformAuthenticatorAvailable().then((v: boolean) => setPlatformAuth(v)).catch(() => setPlatformAuth(false));
  }, []);

  const post = async (body: any) => {
    setBusy(true); setMsg("");
    try {
      const r = await fetch(`${apiBase()}/account-security`, {
        method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${await token()}` }, body: JSON.stringify(body),
      });
      const b = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(b.error || `That did not work (HTTP ${r.status}).`);
      setMsg(b.note || "Saved.");
      return b;
    } catch (e: any) { setMsg(e.message); return null; }
    finally { setBusy(false); await load(); }
  };
  const run = async (fn: () => Promise<any>, ok: string) => {
    setBusy(true); setMsg("");
    try { await fn(); setMsg(ok); } catch (e: any) { setMsg(e?.message || "That did not work."); }
    finally { setBusy(false); await load(); }
  };
  // Adding a sign-in method is a security change too: recent sign-in and (if set) the PIN, checked by the backend.
  // The server checks the sign-in age and the PIN at the moment of the click (a page left open does not count).
  const confirmIdentity = async (purpose: string): Promise<boolean> => !!(await post({ action: "confirm_step_up", pin, purpose }));
  const signInAgain = async () => {
    sessionStorage.setItem("niagaros_return_to", "/settings/user/privacy-security");
    await signOut();
    window.location.href = "/";
  };

  if (loading) return null;
  const st = data ? STATUS[data.assessment.status] || STATUS.unknown : null;
  const needsStepUp = data && !data.session.recent_enough_for_changes;
  const pinField = data?.pin.set ? (
    <input aria-label="Security PIN" type="password" inputMode="numeric" autoComplete="off" placeholder="Security PIN" value={pin}
      onChange={e => setPin(e.target.value.replace(/\D/g, "").slice(0, 8))} style={{ ...input, width: 140 }} />
  ) : null;
  const stepUpNote = needsStepUp ? (
    <p style={{ ...note, color: "#f59e0b" }}>You signed in more than {data!.session.step_up_minutes} minutes ago. To change security settings,{" "}
      <button style={{ ...ghost, padding: "3px 8px" }} onClick={signInAgain}>sign in again</button>.</p>
  ) : null;

  return (
    <SettingsLayout title="Privacy & Security" subtitle="How you sign in, how you get back in, and what happened on your account." email={email}>
      {error && <div role="alert" style={{ ...card, borderColor: "#7f1d1d", color: "#fca5a5" }}>{error} <button style={ghost} onClick={load}>Try again</button></div>}
      {msg && <div role="status" style={{ ...card, padding: "10px 14px", color: "#cbd5e1" }}>{msg}</div>}
      {!data && !error && <div style={{ color: "#64748b" }}>Loading…</div>}
      {data && st && (<>
        <Section id="overview" title="Security overview" status={<span style={pill(st[1])}>{st[0]}</span>}>
          <p style={note}>{st[2]}</p>
          {data.assessment.required.length > 0 && <ul style={{ color: "#fca5a5", fontSize: 13, margin: "0 0 8px 18px" }}>{data.assessment.required.map(r => <li key={r}>{r}</li>)}</ul>}
          {data.assessment.recommendations.length > 0 && <ul style={{ color: "#cbd5e1", fontSize: 13, margin: "0 0 8px 18px" }}>{data.assessment.recommendations.map(r => <li key={r}>{r}</li>)}</ul>}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(170px,1fr))", gap: 8 }}>
            {[["Email", data.email_verified ? "Verified" : "Not verified"], ["Authenticator app", data.totp.enabled ? "On" : "Off"],
              ["Passkeys", data.passkeys == null ? "Unknown" : String(data.passkeys.length)], ["Recovery codes", `${data.recovery_codes.remaining} left`],
              ["Security PIN", data.pin.set ? "Set" : "Not set"], ["Signed in", fmt(data.session.signed_in_at)]].map(([k, v]) => (
              <div key={k} style={{ border: "1px solid #1a2030", borderRadius: 10, padding: "10px 12px" }}>
                <div style={{ color: "#64748b", fontSize: 11 }}>{k}</div><div style={{ color: "#f1f5f9", fontSize: 14, fontWeight: 700 }}>{v}</div>
              </div>))}
          </div>
          {data.policy && <p style={{ ...note, marginTop: 10 }}>Organization policy ({data.policy.organization}): two-step verification is {data.policy.mfa_required ? <b style={{ color: "#f1f5f9" }}>required</b> : "optional"}.
            {data.policy.managed_in ? <> You can change this under <a href={data.policy.managed_in} style={{ color: "#93c5fd" }}>Team</a>.</> : " Only an organization admin can change it."}</p>}
        </Section>

        <Section id="email" title="Email verification" status={<span style={pill(data.email_verified ? "#16a34a" : "#ef4444")}>{data.email_verified ? "Verified" : "Not verified"}</span>}>
          <p style={note}>{data.email}. Verifying shows you control this address; it is not a second sign-in factor.</p>
          {!data.email_verified && <div style={row}>
            <button style={ghost} disabled={busy} onClick={() => run(async () => { await sendUserAttributeVerificationCode({ userAttributeKey: "email" }); setEmailSent(true); }, "A code was sent to your email. It expires after 24 hours.")}>Send code</button>
            {emailSent && <><input aria-label="Email code" style={{ ...input, width: 130 }} value={emailCode} onChange={e => setEmailCode(e.target.value.trim())} placeholder="Code" />
              <button style={btn} disabled={busy} onClick={() => run(() => confirmUserAttribute({ userAttributeKey: "email", confirmationCode: emailCode }), "Email verified.")}>Verify</button></>}
          </div>}
        </Section>

        <Section id="sms" title="Phone (SMS) verification" status={<span style={pill("#64748b")}>Not available</span>}>
          <p style={note}>{data.phone.reason}. Use an authenticator app or a passkey instead.</p>
        </Section>

        <Section id="totp" title="Authenticator app (TOTP)" status={<span style={pill(data.totp.enabled ? "#16a34a" : "#64748b")}>{data.totp.enabled ? "On" : "Off"}</span>}>
          <p style={note}>A 6-digit code from Google Authenticator, Authy, 1Password or similar, asked for after your password.</p>
          {!data.totp.enabled && !totpSecret && <>{stepUpNote}<div style={row}>{pinField}<button style={btn} disabled={busy || !!needsStepUp} onClick={async () => {
            if (!(await confirmIdentity("authenticator_app"))) return;
            await run(async () => { const d = await setUpTOTP(); setTotpSecret(d.sharedSecret); setTotpUri(d.getSetupUri("Niagaros", data.email).toString()); },
              "Add the key below to your authenticator app.");
          }}>Set up</button></div></>}
          {totpSecret && <div>
            <p style={note}>Choose “enter a setup key” in your app and paste this key, or open the link on your phone:</p>
            <code style={{ display: "block", color: "#4ade80", background: "#080b12", padding: 10, borderRadius: 8, wordBreak: "break-all", marginBottom: 8 }}>{totpSecret}</code>
            <a href={totpUri} style={{ color: "#93c5fd", fontSize: 12.5 }}>Open in authenticator app</a>
            <div style={{ ...row, marginTop: 10 }}>
              <input aria-label="6-digit code" inputMode="numeric" maxLength={6} style={{ ...input, width: 120 }} value={totpCode} onChange={e => setTotpCode(e.target.value.replace(/\D/g, ""))} placeholder="000000" />
              <button style={btn} disabled={busy || totpCode.length !== 6} onClick={() => run(async () => {
                await verifyTOTPSetup({ code: totpCode }); await updateMFAPreference({ totp: "PREFERRED" }); setTotpSecret(""); setTotpCode("");
              }, "Authenticator app turned on.")}>Verify and turn on</button>
            </div>
          </div>}
          {data.totp.enabled && <>{stepUpNote}<div style={row}>{pinField}
            <button style={ghost} disabled={busy || !!needsStepUp || data.policy?.mfa_required} onClick={() => post({ action: "disable_totp", pin })}>Turn off</button>
            {data.policy?.mfa_required && <span style={note}>Required by {data.policy.organization}.</span>}</div></>}
        </Section>

        <Section id="passkeys" title="Passkeys and fingerprint / face sign-in" status={<span style={pill(data.passkeys?.length ? "#16a34a" : "#64748b")}>{data.passkeys == null ? "Unknown" : `${data.passkeys.length} registered`}</span>}>
          <p style={note}>A passkey is a key pair stored on your device or password manager; signing in with it cannot be phished.
            Your device may ask for your fingerprint, face or device PIN to use it — that check happens on the device and Niagaros never receives it.</p>
          <p style={note}>This device: {platformAuth == null ? "checking…" : platformAuth ? "supports fingerprint / face / device PIN for passkeys." : "has no built-in biometric authenticator Niagaros can use; you can still use a security key or a passkey from your phone or password manager."}</p>
          {data.passkeys_error && <p style={{ ...note, color: "#f59e0b" }}>{data.passkeys_error}.</p>}
          {(data.passkeys || []).length > 0 && <table style={{ width: "100%", fontSize: 12.5, color: "#cbd5e1", borderCollapse: "collapse", marginBottom: 10 }}><tbody>
            {data.passkeys!.map(p => <tr key={p.id}><td style={{ padding: "6px 0" }}>{p.name || "Passkey"}</td><td>{p.authenticator === "platform" ? "this kind of device" : p.authenticator || ""}</td><td>{fmt(p.created_at)}</td>
              <td style={{ textAlign: "right" }}><button style={ghost} disabled={busy || !!needsStepUp} onClick={() => post({ action: "delete_passkey", credential_id: p.id, pin })}>Remove</button></td></tr>)}
          </tbody></table>}
          {onPasskeyDomain() ? <div style={row}>{stepUpNote}
            {pinField}
            <button style={btn} disabled={busy || data.passkeys == null || !!needsStepUp} onClick={async () => {
              if (!(await confirmIdentity("passkey"))) return;
              await run(() => associateWebAuthnCredential(), "Passkey added.");
            }}>Add a passkey</button></div>
            : <p style={{ ...note, color: "#f59e0b" }}>Passkeys belong to {PASSKEY_DOMAIN}. Open this page on app.{PASSKEY_DOMAIN} to add one.</p>}
        </Section>

        <Section id="pin" title="Security PIN" status={<span style={pill(data.pin.set ? "#16a34a" : "#64748b")}>{data.pin.set ? "Set" : "Not set"}</span>}>
          <p style={note}>Used only for: {data.pin.used_for.toLowerCase()}. A PIN is not a sign-in method and is weaker than an authenticator app or a passkey.
            It is stored as a salted hash; 5 wrong attempts lock it for 15 minutes.{data.pin.locked_until ? ` Locked until ${fmt(data.pin.locked_until)}.` : ""}</p>
          {stepUpNote}
          <div style={row}>
            {data.pin.set && pinField}
            <input aria-label="New PIN" type="password" inputMode="numeric" autoComplete="new-password" placeholder="New PIN (6–8 digits)" value={newPin}
              onChange={e => setNewPin(e.target.value.replace(/\D/g, "").slice(0, 8))} style={{ ...input, width: 190 }} />
            <button style={btn} disabled={busy || !!needsStepUp || newPin.length < 6} onClick={async () => { await post({ action: "set_pin", new_pin: newPin, current_pin: pin }); setNewPin(""); setPin(""); }}>{data.pin.set ? "Change PIN" : "Set PIN"}</button>
            {data.pin.set && <button style={ghost} disabled={busy || !!needsStepUp} onClick={() => post({ action: "remove_pin", pin })}>Remove</button>}
          </div>
        </Section>

        <Section id="recovery" title="Recovery codes" status={<span style={pill(data.recovery_codes.remaining ? "#16a34a" : "#f59e0b")}>{data.recovery_codes.remaining} left</span>}>
          <p style={note}>If you lose your authenticator app, one code (with your password) resets two-step verification and signs you out everywhere.
            Each code works once. {data.recovery_codes.generated_at ? `Created ${fmt(data.recovery_codes.generated_at)}.` : ""} Lost your device? Use them at <a href="/account-recovery" style={{ color: "#93c5fd" }}>account recovery</a>.</p>
          {stepUpNote}
          <div style={row}>{pinField}
            <button style={btn} disabled={busy || !!needsStepUp} onClick={async () => { const b = await post({ action: "generate_recovery_codes", pin }); if (b?.codes) setCodes(b.codes); }}>
              {data.recovery_codes.remaining ? "Create new codes (old ones stop working)" : "Create recovery codes"}</button></div>
          {codes && <div style={{ marginTop: 12 }}>
            <p style={{ ...note, color: "#f59e0b" }}>Shown only now. Store them in your password manager or print them.</p>
            <pre aria-label="Recovery codes" style={{ background: "#080b12", color: "#4ade80", padding: 12, borderRadius: 8, columns: 2, fontSize: 14 }}>{codes.join("\n")}</pre>
            <button style={ghost} onClick={() => { navigator.clipboard?.writeText(codes.join("\n")); setMsg("Copied."); }}>Copy</button>{" "}
            <button style={ghost} onClick={() => setCodes(null)}>I saved them</button>
          </div>}
        </Section>

        <Section id="sessions" title="Sessions and devices">
          <p style={note}>Sign-ins Niagaros has seen in the last 30 days, with the address and browser the server observed.
            This sign-in expires {fmt(data.session.expires_at)} and is refreshed automatically while you use Niagaros.</p>
          <table style={{ width: "100%", fontSize: 12.5, color: "#cbd5e1", borderCollapse: "collapse" }}><tbody>
            {data.sessions.map((s, i) => <tr key={i} style={{ borderTop: "1px solid #1a2030" }}>
              <td style={{ padding: "7px 0" }}>{s.current ? <b>This session</b> : "Other session"}{s.signed_out_at ? " (signed out)" : ""}</td>
              <td>{s.ip || "—"}</td><td style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.user_agent}</td><td>last used {fmt(s.last_seen)}</td></tr>)}
          </tbody></table>
          {stepUpNote}
          <div style={{ ...row, marginTop: 10 }}>{pinField}
            <button style={btn} disabled={busy || !!needsStepUp} onClick={async () => { const b = await post({ action: "sign_out_everywhere", pin }); if (b) { await signOut(); window.location.href = "/"; } }}>Sign out everywhere</button></div>
          <p style={{ ...note, marginTop: 8 }}>Ends every session immediately, including this one; each device has to sign in again.</p>
        </Section>

        <Section id="activity" title="Recent security activity">
          {data.events.length ? <table style={{ width: "100%", fontSize: 12.5, color: "#cbd5e1", borderCollapse: "collapse" }}><tbody>
            {data.events.map((e, i) => <tr key={i} style={{ borderTop: "1px solid #1a2030" }}>
              <td style={{ padding: "7px 0", whiteSpace: "nowrap" }}>{fmt(e.at)}</td>
              <td style={{ color: e.outcome === "failure" ? "#fca5a5" : "#cbd5e1" }}>{EVENT_LABEL[e.event] || e.event}{e.outcome === "observed" ? " (seen by Niagaros)" : ""}</td>
              <td>{e.ip || ""}</td></tr>)}
          </tbody></table> : <p style={note}>Nothing yet.</p>}
        </Section>

        <Section id="privacy" title="Privacy">
          <p style={note}>Your name and contact details are on <a href="/settings/personal-data" style={{ color: "#93c5fd" }}>Personal data</a>.
            Niagaros stores no biometric data, no TOTP secret and no plain-text PIN or recovery code.</p>
        </Section>

        <Section id="federation" title="Single sign-on" status={<span style={pill("#64748b")}>Not available</span>}>
          <p style={note}>{data.federation.reason}.</p>
        </Section>
      </>)}
    </SettingsLayout>
  );
}
