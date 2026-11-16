import React, { useState } from "react";

// /account-recovery — issue #291. Public: someone who lost their authenticator app enters their email and one recovery
// code. The answer is always the same, so the page cannot be used to find out which addresses have an account.
function apiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

export default function AccountRecovery() {
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setMsg("");
    try {
      const r = await fetch(`${apiBase()}/account-security`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "recover", email: email.trim(), code: code.trim() }),
      });
      const b = await r.json().catch(() => ({}));
      setMsg(r.ok ? b.message : b.error || "Recovery is not available right now. Try again later.");
    } catch {
      setMsg("Niagaros could not be reached. Try again later.");
    } finally { setBusy(false); }
  };

  const input: React.CSSProperties = { width: "100%", boxSizing: "border-box", background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, color: "#e2e8f0", fontSize: 14, padding: "10px 12px", marginBottom: 12 };
  return (
    <div style={{ minHeight: "100vh", background: "#080b12", fontFamily: "system-ui,-apple-system,sans-serif", display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
      <form onSubmit={submit} style={{ background: "#111827", border: "1px solid #1e2433", borderRadius: 14, padding: "28px 28px", width: "100%", maxWidth: 420 }}>
        <h1 style={{ color: "#f1f5f9", fontSize: 20, margin: "0 0 8px" }}>Lost your authenticator?</h1>
        <p style={{ color: "#64748b", fontSize: 13, lineHeight: 1.6, margin: "0 0 18px" }}>
          Enter your email address and one of the recovery codes you saved. This turns off two-step verification and signs your account out everywhere.
          You still need your password to sign in, and your organization may ask you to set up two-step verification again.
        </p>
        <label htmlFor="rec-email" style={{ color: "#94a3b8", fontSize: 12 }}>Email address</label>
        <input id="rec-email" type="email" autoComplete="email" required value={email} onChange={e => setEmail(e.target.value)} style={input} />
        <label htmlFor="rec-code" style={{ color: "#94a3b8", fontSize: 12 }}>Recovery code</label>
        <input id="rec-code" required placeholder="ABCD-EFGH" autoComplete="one-time-code" value={code} onChange={e => setCode(e.target.value.toUpperCase())} style={{ ...input, letterSpacing: "0.1em" }} />
        <button type="submit" disabled={busy} style={{ width: "100%", background: "#ef4444", color: "#fff", border: "none", borderRadius: 8, padding: "11px 0", fontSize: 14, fontWeight: 600, cursor: "pointer" }}>
          {busy ? "Checking…" : "Reset two-step verification"}</button>
        {msg && <p role="status" style={{ color: "#cbd5e1", fontSize: 13, lineHeight: 1.6, marginTop: 14 }}>{msg}</p>}
        <p style={{ marginTop: 16 }}><a href="/" style={{ color: "#93c5fd", fontSize: 13 }}>Back to sign in</a></p>
      </form>
    </div>
  );
}
