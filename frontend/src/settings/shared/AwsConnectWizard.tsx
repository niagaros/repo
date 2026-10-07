import React, { useState } from "react";

// Shared AWS "connect your account" wizard.
//
// Extracted from App.tsx's forced first-login OnboardingWizard so the exact
// same flow can be reused from the new /settings/infrastructure page
// (issue #269) without duplicating ~150 lines of markup. Behaviour and the
// backend contract (POST /onboard) are unchanged.

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

export interface OnboardResult { account_id: string; external_id: string; }

// ── Shared styles (also used by App.tsx for its loading/error states) ─────────
export const S = {
  page: {
    minHeight: "100vh", background: "#0d0f14",
    display: "flex", alignItems: "center", justifyContent: "center",
    fontFamily: "'Inter', system-ui, sans-serif", color: "#f1f5f9",
    overflowY: "auto", padding: "24px 16px", boxSizing: "border-box" as const,
  } as React.CSSProperties,
  card: {
    background: "#12151d", border: "1px solid #1e2433", borderRadius: 16,
    padding: "48px 40px", width: "100%", maxWidth: 480,
    boxShadow: "0 24px 48px rgba(0,0,0,.4)",
  } as React.CSSProperties,
  title: { fontSize: 22, fontWeight: 700, color: "#f1f5f9", margin: "0 0 8px" } as React.CSSProperties,
  sub:   { fontSize: 14, color: "#64748b", margin: "0 0 28px", lineHeight: 1.6 } as React.CSSProperties,
  label: { display: "block", fontSize: 13, color: "#94a3b8", marginBottom: 6, fontWeight: 500 } as React.CSSProperties,
  input: {
    width: "100%", background: "#0d0f14", border: "1px solid #1e2433",
    borderRadius: 8, padding: "10px 14px", color: "#f1f5f9", fontSize: 14,
    outline: "none", boxSizing: "border-box" as const, marginBottom: 18,
  } as React.CSSProperties,
  btn: {
    width: "100%", background: "#ef4444", color: "#fff", border: "none",
    borderRadius: 8, padding: "12px 0", fontSize: 15, fontWeight: 600,
    cursor: "pointer", marginTop: 8,
  } as React.CSSProperties,
  btnGhost: {
    width: "100%", background: "transparent", color: "#64748b",
    border: "1px solid #1e2433", borderRadius: 8, padding: "10px 0",
    fontSize: 14, cursor: "pointer", marginTop: 8,
  } as React.CSSProperties,
  code: {
    background: "#0d0f14", border: "1px solid #1e2433", borderRadius: 8,
    padding: "14px 16px", fontSize: 12, color: "#94a3b8",
    whiteSpace: "pre-wrap" as const, wordBreak: "break-all" as const,
    lineHeight: 1.7, display: "block", marginBottom: 12,
  } as React.CSSProperties,
  error: {
    background: "rgba(239,68,68,.1)", border: "1px solid rgba(239,68,68,.3)",
    borderRadius: 8, padding: "10px 14px", color: "#ef4444",
    fontSize: 13, marginBottom: 16,
  } as React.CSSProperties,
};

export const Steps = ({ current, total }: { current: number; total: number }) => (
  <div style={{ display: "flex", gap: 8, marginBottom: 28 }}>
    {Array.from({ length: total }).map((_, i) => (
      <div key={i} style={{
        width: 8, height: 8, borderRadius: "50%", transition: "all .2s",
        background: i <= current ? "#ef4444" : "#1e2433",
        opacity: i < current ? 0.4 : 1,
      }} />
    ))}
  </div>
);

interface Props { email: string; onComplete: () => void; }

export default function AwsConnectWizard({ email, onComplete }: Props) {
  const [step, setStep]             = useState(0);
  const [companyName, setCompanyName]   = useState("");
  const [awsAccountId, setAwsAccountId] = useState("");
  const [region, setRegion]             = useState("eu-west-1");
  const [result, setResult]             = useState<OnboardResult | null>(null);
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState("");

  const handleSubmit = async () => {
    setError("");
    if (!companyName.trim()) { setError("Please enter your company name."); return; }
    if (!/^\d{12}$/.test(awsAccountId.trim())) {
      setError("AWS Account ID must be exactly 12 digits.");
      return;
    }
    setLoading(true);
    try {
      const resp = await fetch(`${getApiBase()}/onboard`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, company_name: companyName.trim(), aws_account_id: awsAccountId.trim(), region }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Onboarding failed");
      setResult(data);
      setStep(2);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const cfnTemplate = result ? `AWSTemplateFormatVersion: '2010-09-09'
Description: Niagaros CSPM Scanner Role
Parameters:
  NiagarosAccountId:
    Type: String
    Default: '225989360315'
  ExternalId:
    Type: String
    Default: '${result.external_id}'
Resources:
  CSPMScannerRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: CSPMScannerRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::\${NiagarosAccountId}:root'
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/ReadOnlyAccess` : "";

  // Step 0 — Welcome
  if (step === 0) return (
    <div style={S.page}>
      <div style={S.card}>
        <Steps current={0} total={4} />
        <div style={{ fontSize: 36, marginBottom: 16 }}>👋</div>
        <p style={S.title}>Welcome to Niagaros</p>
        <p style={S.sub}>We will connect your AWS account to the platform. This takes about 5 minutes. Make sure you have:</p>
        <ul style={{ color: "#64748b", fontSize: 13, lineHeight: 2.2, paddingLeft: 20, marginBottom: 32 }}>
          <li>Your AWS Account ID (12 digits)</li>
          <li>Access to the AWS Console or CLI</li>
        </ul>
        <button style={S.btn} onClick={() => setStep(1)}>Get started →</button>
      </div>
    </div>
  );

  // Step 1 — AWS info
  if (step === 1) return (
    <div style={S.page}>
      <div style={S.card}>
        <Steps current={1} total={4} />
        <p style={S.title}>Your AWS account</p>
        <p style={S.sub}>Enter your company name and AWS Account ID so we can create the connection.</p>
        {error && <div style={S.error}>{error}</div>}
        <label style={S.label}>Company name</label>
        <input style={S.input} placeholder="e.g. Acme Corp" value={companyName} onChange={e => setCompanyName(e.target.value)} />
        <label style={S.label}>AWS Account ID</label>
        <input style={S.input} placeholder="123456789012" value={awsAccountId} onChange={e => setAwsAccountId(e.target.value)} maxLength={12} />
        <label style={S.label}>Primary AWS Region</label>
        <select style={S.input} value={region} onChange={e => setRegion(e.target.value)}>
          <option value="eu-west-1">Europe (Ireland) — eu-west-1</option>
          <option value="eu-north-1">Europe (Stockholm) — eu-north-1</option>
          <option value="eu-central-1">Europe (Frankfurt) — eu-central-1</option>
          <option value="eu-west-2">Europe (London) — eu-west-2</option>
          <option value="us-east-1">US East (N. Virginia) — us-east-1</option>
          <option value="us-west-2">US West (Oregon) — us-west-2</option>
          <option value="ap-southeast-1">Asia Pacific (Singapore) — ap-southeast-1</option>
        </select>
        <div style={{ background: "#0d0f14", border: "1px solid #1e2433", borderRadius: 8, padding: "12px 14px", marginTop: -10, marginBottom: 20, fontSize: 12, color: "#475569", lineHeight: 1.8 }}>
          📍 Found in the top-right of the AWS Console next to your account name, or via:<br />
          <code style={{ color: "#ef4444" }}>aws sts get-caller-identity --query Account --output text</code>
        </div>
        <button style={S.btn} onClick={handleSubmit} disabled={loading}>{loading ? "Processing..." : "Continue →"}</button>
        <button style={S.btnGhost} onClick={() => setStep(0)}>← Back</button>
      </div>
    </div>
  );

  // Step 2 — IAM role
  const downloadTemplate = () => {
    const blob = new Blob([cfnTemplate], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "niagaros-role.yaml"; a.click();
    URL.revokeObjectURL(url);
  };

  if (step === 2 && result) return (
    <div style={{ ...S.page, alignItems: "flex-start", overflowY: "auto", padding: "40px 0" }}>
      <div style={{ ...S.card, maxWidth: 560, margin: "0 auto" }}>
        <Steps current={2} total={4} />
        <p style={S.title}>Set up AWS access</p>
        <p style={S.sub}>Follow these steps to give Niagaros read-only access to your AWS account. This takes about 3 minutes.</p>

        {/* Step 1 */}
        <div style={{ display: "flex", gap: 14, marginBottom: 20 }}>
          <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#ef4444", color: "#fff", fontSize: 13, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>1</div>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 14, marginBottom: 6 }}>Download the configuration file</div>
            <div style={{ color: "#475569", fontSize: 12, marginBottom: 10, lineHeight: 1.6 }}>This file contains all the settings needed to create the role in your AWS account.</div>
            <button style={{ ...S.btn, marginTop: 0, padding: "9px 0" }} onClick={downloadTemplate}>⬇ Download niagaros-role.yaml</button>
          </div>
        </div>

        {/* Step 2 */}
        <div style={{ display: "flex", gap: 14, marginBottom: 20 }}>
          <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#1e2433", color: "#94a3b8", fontSize: 13, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>2</div>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 14, marginBottom: 6 }}>Open AWS CloudFormation</div>
            <div style={{ color: "#475569", fontSize: 12, marginBottom: 10, lineHeight: 1.6 }}>
              Go to your AWS Console and search for <strong style={{ color: "#94a3b8" }}>CloudFormation</strong> in the top search bar. Then click <strong style={{ color: "#94a3b8" }}>"Create stack"</strong> → <strong style={{ color: "#94a3b8" }}>"With new resources"</strong>.
            </div>
          </div>
        </div>

        {/* Step 3 */}
        <div style={{ display: "flex", gap: 14, marginBottom: 20 }}>
          <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#1e2433", color: "#94a3b8", fontSize: 13, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>3</div>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 14, marginBottom: 6 }}>Upload the file</div>
            <div style={{ color: "#475569", fontSize: 12, lineHeight: 1.6 }}>
              Choose <strong style={{ color: "#94a3b8" }}>"Upload a template file"</strong>, click <strong style={{ color: "#94a3b8" }}>"Choose file"</strong> and select the <code style={{ color: "#ef4444" }}>niagaros-role.yaml</code> you just downloaded. Click <strong style={{ color: "#94a3b8" }}>Next</strong>.
            </div>
          </div>
        </div>

        {/* Step 4 */}
        <div style={{ display: "flex", gap: 14, marginBottom: 20 }}>
          <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#1e2433", color: "#94a3b8", fontSize: 13, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>4</div>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 14, marginBottom: 6 }}>Fill in the stack name</div>
            <div style={{ color: "#475569", fontSize: 12, lineHeight: 1.6 }}>
              Enter <code style={{ color: "#ef4444" }}>NiagarosCSPMRole</code> as the stack name. Leave all other fields as they are. Click <strong style={{ color: "#94a3b8" }}>Next</strong> twice.
            </div>
          </div>
        </div>

        {/* Step 5 */}
        <div style={{ display: "flex", gap: 14, marginBottom: 24 }}>
          <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#1e2433", color: "#94a3b8", fontSize: 13, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>5</div>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 14, marginBottom: 6 }}>Confirm and create</div>
            <div style={{ color: "#475569", fontSize: 12, lineHeight: 1.6 }}>
              Scroll to the bottom, tick <strong style={{ color: "#94a3b8" }}>"I acknowledge that AWS CloudFormation might create IAM resources with custom names"</strong> and click <strong style={{ color: "#94a3b8" }}>"Submit"</strong>. Wait until the status shows <strong style={{ color: "#10b981" }}>CREATE_COMPLETE</strong>.
            </div>
          </div>
        </div>

        <button style={S.btn} onClick={() => setStep(3)}>Done, role is created →</button>
        <button style={S.btnGhost} onClick={() => setStep(1)}>← Back</button>
      </div>
    </div>
  );

  // Step 3 — Complete
  if (step === 3) return (
    <div style={S.page}>
      <div style={S.card}>
        <Steps current={3} total={4} />
        <div style={{ fontSize: 48, marginBottom: 16 }}>✅</div>
        <p style={S.title}>You're all set!</p>
        <p style={S.sub}>Your AWS account has been connected to Niagaros.</p>
        <button style={S.btn} onClick={onComplete}>Continue →</button>
      </div>
    </div>
  );

  return null;
}
