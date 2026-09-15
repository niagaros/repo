import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchAuthSession, setUpTOTP, verifyTOTPSetup, updateMFAPreference } from "aws-amplify/auth";

// /mfa-setup — issue #265, acceptance criterion #3: "Given MFA is
// required by policy, when a user signs in without MFA configured, then
// access is blocked until enrollment is completed." useRequireAuth.ts
// redirects here when an organization requires MFA and the signed-in
// user doesn't have it configured yet.
//
// Deliberately doesn't render a QR code (no new npm dependency for it) —
// the secret key is shown for manual entry instead, which every
// authenticator app (Google Authenticator, Authy, 1Password, ...)
// supports as an alternative to scanning.
//
// Uses aws-amplify/auth's real TOTP APIs (setUpTOTP / verifyTOTPSetup /
// updateMFAPreference) against the actual Cognito user pool — this is
// the one part of #265 that genuinely cannot be verified against a local
// SQLite stand-in the way the rest of the Team feature was; it needs a
// real login to test end-to-end.

type Step = "loading" | "scan" | "verify" | "done" | "error";

export default function MfaSetup() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>("loading");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const session = await fetchAuthSession();
        if (!session.tokens?.accessToken) {
          window.location.href = "/";
          return;
        }
        const details = await setUpTOTP();
        setSecret(details.sharedSecret);
        setStep("scan");
      } catch (e: any) {
        setError(e?.message || "Could not start MFA setup.");
        setStep("error");
      }
    })();
  }, []);

  const submitCode = async () => {
    setError("");
    if (!/^\d{6}$/.test(code.trim())) {
      setError("Enter the 6-digit code from your authenticator app.");
      return;
    }
    setVerifying(true);
    try {
      await verifyTOTPSetup({ code: code.trim() });
      await updateMFAPreference({ totp: "PREFERRED" });
      setStep("done");
      setTimeout(() => navigate("/onboarding"), 1500);
    } catch (e: any) {
      setError(e?.message || "That code didn't work — check your authenticator app and try again.");
    } finally {
      setVerifying(false);
    }
  };

  const cardStyle: React.CSSProperties = {
    background: "#111827", border: "1px solid #1e2433", borderRadius: 14,
    padding: "28px 32px", maxWidth: 460, margin: "0 auto",
  };

  return (
    <div style={{ minHeight: "100vh", background: "#080b12", fontFamily: "system-ui,-apple-system,sans-serif", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <div style={{ width: "100%" }}>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: "#ef4444", letterSpacing: "0.15em" }}>SECURITY REQUIRED</span>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: "#f1f5f9", margin: "8px 0 0" }}>Set up multi-factor authentication</h1>
          <p style={{ fontSize: 13, color: "#64748b", margin: "8px 0 0" }}>
            Your organization requires MFA before you can continue.
          </p>
        </div>

        {step === "loading" && (
          <div style={{ textAlign: "center", color: "#64748b", fontSize: 13 }}>Loading…</div>
        )}

        {step === "error" && (
          <div style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)" }}>
            <div style={{ color: "#f87171", fontSize: 13 }}>{error}</div>
          </div>
        )}

        {(step === "scan" || step === "verify") && (
          <div style={cardStyle}>
            <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 10 }}>
              1. Add this key to your authenticator app
            </div>
            <p style={{ color: "#4e627a", fontSize: 12.5, lineHeight: 1.6, marginBottom: 12 }}>
              In Google Authenticator, Authy, 1Password or similar, choose "Enter a setup key manually"
              and paste this code:
            </p>
            <div style={{
              background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8,
              padding: "12px 14px", fontFamily: "monospace", fontSize: 14, color: "#4ade80",
              letterSpacing: "0.05em", wordBreak: "break-all", marginBottom: 20,
            }}>
              {secret}
            </div>

            <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 10 }}>
              2. Enter the 6-digit code it generates
            </div>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
              placeholder="000000"
              style={{
                width: "100%", background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8,
                padding: "10px 12px", color: "#e2e8f0", fontSize: 18, letterSpacing: "0.3em",
                textAlign: "center", marginBottom: 12,
              }}
            />
            {error && <div style={{ color: "#f87171", fontSize: 12, marginBottom: 12 }}>{error}</div>}
            <button
              onClick={submitCode}
              disabled={verifying}
              style={{
                width: "100%", background: "#ef4444", color: "#fff", border: "none", borderRadius: 8,
                padding: "10px 0", fontSize: 13, fontWeight: 600,
                cursor: verifying ? "default" : "pointer", opacity: verifying ? 0.6 : 1,
              }}
            >
              {verifying ? "Verifying…" : "Verify and continue"}
            </button>
          </div>
        )}

        {step === "done" && (
          <div style={{ ...cardStyle, borderColor: "rgba(22,163,74,0.4)", textAlign: "center" }}>
            <div style={{ color: "#4ade80", fontWeight: 700, fontSize: 14 }}>✓ MFA enabled — redirecting…</div>
          </div>
        )}
      </div>
    </div>
  );
}
