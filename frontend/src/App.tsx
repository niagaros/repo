import React, { useEffect, useState, useCallback } from "react";
import { fetchAuthSession } from "aws-amplify/auth";
import { Authenticator, ThemeProvider, Theme, useAuthenticator } from "@aws-amplify/ui-react";
import "@aws-amplify/ui-react/styles.css";
import "./App.css";

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

// ── Logo SVG ──────────────────────────────────────────────────────────────────
const NiagarosLogo = ({ size = 40 }: { size?: number }) => (
  <svg width={size * 0.75} height={size} viewBox="0 0 36 48" fill="none">
    {/* Water drop outline — pointed top, rounded bottom */}
    <path
      d="M18 2 C18 2 3 20 3 31 C3 40.4 9.8 46 18 46 C26.2 46 33 40.4 33 31 C33 20 18 2 18 2 Z"
      stroke="#ef4444" strokeWidth="2.2" fill="none" strokeLinecap="round" strokeLinejoin="round"
    />
    {/* Inner circle — bottom-left reflection spot */}
    <circle cx="12.5" cy="36.5" r="3.2" stroke="#ef4444" strokeWidth="1.7" fill="none" />
  </svg>
);

// ── Left branding panel ───────────────────────────────────────────────────────
const LeftPanel = () => (
  <div style={{
    flex: "0 0 58%",
    background: "#060810",
    display: "flex", flexDirection: "column", justifyContent: "center",
    padding: "48px 64px", position: "relative", overflow: "hidden",
  }}>
    {/* dot grid */}
    <div style={{
      position: "absolute", inset: 0,
      backgroundImage: "radial-gradient(rgba(255,255,255,0.03) 1px, transparent 1px)",
      backgroundSize: "28px 28px",
    }} />
    {/* red glow top-right */}
    <div style={{
      position: "absolute", top: -180, right: -120,
      width: 560, height: 560, borderRadius: "50%",
      background: "radial-gradient(circle, rgba(239,68,68,.16) 0%, transparent 65%)",
      pointerEvents: "none",
    }} />
    {/* glow bottom-left */}
    <div style={{
      position: "absolute", bottom: -100, left: -60,
      width: 360, height: 360, borderRadius: "50%",
      background: "radial-gradient(circle, rgba(239,68,68,.06) 0%, transparent 70%)",
      pointerEvents: "none",
    }} />
    {/* top accent line */}
    <div style={{
      position: "absolute", top: 0, left: 0, right: 0, height: 1,
      background: "linear-gradient(90deg, #ef4444 0%, rgba(239,68,68,0.12) 50%, transparent 100%)",
    }} />

    {/* Logo */}
    <div style={{ display: "flex", alignItems: "center", gap: 11, marginBottom: 40, position: "relative" }}>
      <NiagarosLogo size={42} />
      <div>
        <span style={{ display: "block", fontSize: 20, fontWeight: 700, color: "#f1f5f9", letterSpacing: "0.25em" }}>NIAGAROS</span>
        <span style={{ display: "block", fontSize: 9, color: "#243040", letterSpacing: "0.18em", marginTop: 2 }}>CLOUD SECURITY</span>
      </div>
    </div>

    {/* Headline */}
    <h1 style={{ fontSize: 42, fontWeight: 800, margin: "0 0 14px", lineHeight: 1.1, position: "relative", letterSpacing: "-0.02em" }}>
      <span style={{ color: "#f1f5f9" }}>Cloud security,</span><br />
      <span style={{
        background: "linear-gradient(135deg, #ef4444 0%, #f87171 60%, #fca5a5 100%)",
        WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
      }}>automated.</span>
    </h1>
    <p style={{ fontSize: 14, color: "#445870", margin: "0 0 32px", lineHeight: 1.85, maxWidth: 400, position: "relative" }}>
      Scan your AWS environment and GitHub organisations for misconfigurations
      and compliance gaps — on demand, no agents required.
    </p>

    {/* ── Mock dashboard preview card ── */}
    <div style={{
      position: "relative", background: "#0b0e17",
      border: "1px solid #1a2235", borderRadius: 14,
      overflow: "hidden", marginBottom: 28,
    }}>
      {/* card header */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "12px 16px", borderBottom: "1px solid #131929",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#10b981" }} />
          <span style={{ color: "#4a607a", fontSize: 11, fontWeight: 600, letterSpacing: "0.06em" }}>LIVE SCAN RESULTS</span>
        </div>
        <span style={{ fontSize: 10, color: "#1e2d3d", fontWeight: 500 }}>Last scan: just now</span>
      </div>
      {/* compliance bars */}
      <div style={{ padding: "14px 16px", display: "flex", flexDirection: "column", gap: 10 }}>
        {[
          { name: "CIS AWS Benchmark",      pct: 74, color: "#f59e0b", pass: 37, fail: 13 },
          { name: "CIS GitHub Benchmark",   pct: 55, color: "#ef4444", pass: 12, fail: 10 },
          { name: "ISO 27001",              pct: 81, color: "#06b6d4", pass: 29, fail:  7 },
          { name: "NIST CSF",               pct: 68, color: "#8b5cf6", pass: 24, fail: 11 },
          { name: "GDPR",                   pct: 77, color: "#10b981", pass: 17, fail:  5 },
          { name: "SOC 2",                  pct: 71, color: "#ec4899", pass: 22, fail:  9 },
        ].map((f) => (
          <div key={f.name} style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ width: 130, fontSize: 11, color: "#4e627a", fontWeight: 500, flexShrink: 0 }}>{f.name}</div>
            <div style={{ flex: 1, height: 5, background: "#141b28", borderRadius: 99, overflow: "hidden" }}>
              <div style={{ width: `${f.pct}%`, height: "100%", background: f.color, borderRadius: 99, opacity: 0.85 }} />
            </div>
            <div style={{ fontSize: 11, fontWeight: 700, color: f.color, width: 32, textAlign: "right" as const }}>{f.pct}%</div>
            <div style={{ fontSize: 10, color: "#2a3a4e", width: 70, flexShrink: 0 }}>
              <span style={{ color: "#10b981" }}>{f.pass} pass</span>
              <span style={{ color: "#1e2d3d" }}> · </span>
              <span style={{ color: "#ef4444" }}>{f.fail} fail</span>
            </div>
          </div>
        ))}
      </div>
      {/* finding pills */}
      <div style={{ padding: "0 16px 14px", display: "flex", gap: 6, flexWrap: "wrap" as const }}>
        {[
          { text: "S3 bucket public", sev: "#ef4444" },
          { text: "MFA not enforced", sev: "#f59e0b" },
          { text: "Root key active", sev: "#ef4444" },
          { text: "Secret scanning off", sev: "#f59e0b" },
          { text: "+37 more", sev: "#374151" },
        ].map((p) => (
          <span key={p.text} style={{
            fontSize: 10, padding: "3px 9px", borderRadius: 20,
            background: `${p.sev}12`, color: p.sev,
            border: `1px solid ${p.sev}28`, fontWeight: 500,
          }}>{p.text}</span>
        ))}
      </div>
    </div>

    {/* Stats row */}
    <div style={{ display: "flex", gap: 0, position: "relative" }}>
      {[
        { value: "100+",   label: "Automated checks" },
        { value: "6",      label: "Frameworks" },
        { value: "AWS + GitHub", label: "Integrations" },
      ].map((s, i) => (
        <div key={i} style={{
          flex: 1, paddingRight: 24,
          borderRight: i < 2 ? "1px solid #131929" : "none",
          paddingLeft: i > 0 ? 24 : 0,
        }}>
          <div style={{ fontSize: 20, fontWeight: 800, color: "#f1f5f9", letterSpacing: "-0.01em" }}>{s.value}</div>
          <div style={{ fontSize: 10.5, color: "#2a3a4e", marginTop: 3, fontWeight: 500 }}>{s.label}</div>
        </div>
      ))}
    </div>

    {/* Footer */}
    <div style={{ position: "absolute", bottom: 20, left: 64, color: "#111824", fontSize: 10, letterSpacing: "0.04em" }}>
      © {new Date().getFullYear()} Niagaros · Cloud Security Posture Management
    </div>
  </div>
);

// ── Amplify theme ─────────────────────────────────────────────────────────────
const niagarosTheme: Theme = {
  name: "niagaros",
  tokens: {
    colors: {
      brand: {
        primary: {
          10:  { value: "#0d0f14" },
          20:  { value: "#12151d" },
          40:  { value: "#1a1f2e" },
          60:  { value: "#ef4444" },
          80:  { value: "#dc2626" },
          90:  { value: "#b91c1c" },
          100: { value: "#991b1b" },
        },
      },
    },
    components: {
      authenticator: {
        router: { borderWidth: { value: "0" }, backgroundColor: { value: "transparent" }, boxShadow: { value: "none" } },
      },
    },
  },
};

// ── Shared styles ─────────────────────────────────────────────────────────────
const S = {
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

// ── Step dots ─────────────────────────────────────────────────────────────────
const Steps = ({ current, total }: { current: number; total: number }) => (
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

// ── Types ─────────────────────────────────────────────────────────────────────
type AppState =
  | { kind: "loading" }
  | { kind: "onboarding" }
  | { kind: "dashboard"; accountId: string }
  | { kind: "error"; msg: string };

interface OnboardResult { account_id: string; external_id: string; }

// ── Onboarding wizard ─────────────────────────────────────────────────────────
function OnboardingWizard({ email, onComplete }: { email: string; onComplete: () => void }) {
  const [step, setStep]             = useState(0);
  const [companyName, setCompanyName]   = useState("");
  const [awsAccountId, setAwsAccountId] = useState("");
  const [region, setRegion]             = useState("eu-west-1");
  const [result, setResult]             = useState<OnboardResult | null>(null);
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState("");
  const [copied, setCopied]             = useState("");

  const copy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(""), 2000);
  };

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

  const cliCmd = `aws cloudformation create-stack \\\n  --stack-name NiagarosCSPMRole \\\n  --template-body file://niagaros-role.yaml \\\n  --capabilities CAPABILITY_NAMED_IAM`;

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
        <p style={S.sub}>Your AWS account has been connected to Niagaros. Click <strong>Scan Now</strong> on the dashboard to run your first scan.</p>
        <button style={S.btn} onClick={onComplete}>Go to dashboard →</button>
      </div>
    </div>
  );

  return null;
}

// ── Dashboard redirect ────────────────────────────────────────────────────────
function DashboardView({ accountId }: { accountId: string }) {
  useEffect(() => {
    window.location.href = `/niagaros-dashboard.html?account_id=${accountId}`;
  }, [accountId]);
  return (
    <div style={S.page}>
      <div style={{ color: "#64748b", fontSize: 14 }}>Loading dashboard…</div>
    </div>
  );
}

// ── App content (after login) ─────────────────────────────────────────────────
function AppContent() {
  const { user, signOut } = useAuthenticator();
  const [appState, setAppState] = useState<AppState>({ kind: "loading" });
  const email = user?.signInDetails?.loginId || "";

  const checkAccount = useCallback(async () => {
    if (!email) return;
    setAppState({ kind: "loading" });
    try {
      const session = await fetchAuthSession();
      const token = session.tokens?.accessToken?.toString() || "";
      if (token) localStorage.setItem("niagaros_token", token);

      const resp = await fetch(`${getApiBase()}/get-dashboard-data?email=${encodeURIComponent(email)}`, {
        cache: "no-store",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      const data = await resp.json();
      if (data.needs_onboarding) {
        setAppState({ kind: "onboarding" });
      } else {
        const accountId = data.accounts?.[0]?.id || "";
        setAppState({ kind: "dashboard", accountId });
      }
    } catch (e: any) {
      setAppState({ kind: "error", msg: e.message });
    }
  }, [email]);

  useEffect(() => { checkAccount(); }, [checkAccount]);

  if (appState.kind === "loading") return (
    <div style={S.page}><div style={{ color: "#64748b", fontSize: 14 }}>Loading…</div></div>
  );

  if (appState.kind === "error") return (
    <div style={S.page}>
      <div style={S.card}>
        <p style={{ color: "#ef4444" }}>Error: {appState.msg}</p>
        <button style={S.btn} onClick={checkAccount}>Try again</button>
        <button style={S.btnGhost} onClick={signOut}>Sign out</button>
      </div>
    </div>
  );

  if (appState.kind === "onboarding") return <OnboardingWizard email={email} onComplete={checkAccount} />;
  if (appState.kind === "dashboard") return <DashboardView accountId={appState.accountId} />;
  return null;
}

// ── Root ──────────────────────────────────────────────────────────────────────
export default function App() {
  return (
    <ThemeProvider theme={niagarosTheme}>
      <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
        <LeftPanel />

        {/* Right panel — login form */}
        <div style={{
          flex: "0 0 45%",
          background: "linear-gradient(180deg,#0a0c13 0%,#0d0f16 100%)",
          display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center",
          padding: "40px 48px",
        }}>
          <Authenticator
            loginMechanisms={["email"]}
            signUpAttributes={["email"]}
            formFields={{
              signIn: {
                username: { label: "Email address", placeholder: "you@example.com" },
                password: { label: "Password",      placeholder: "••••••••" },
              },
              signUp: {
                email:            { label: "Email address",     placeholder: "you@example.com", order: 1 },
                password:         { label: "Password",          placeholder: "••••••••",         order: 2 },
                confirm_password: { label: "Confirm password",  placeholder: "••••••••",         order: 3 },
              },
            }}
            components={{
              Header() {
                return (
                  <div style={{ textAlign: "center", paddingBottom: 12, paddingTop: 4 }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, marginBottom: 8 }}>
                      <NiagarosLogo size={34} />
                      <div>
                        <span style={{ display: "block", fontSize: 18, fontWeight: 700, color: "#f1f5f9", letterSpacing: "0.2em", fontFamily: "system-ui" }}>NIAGAROS</span>
                        <span style={{ display: "block", fontSize: 9, color: "#2d3f52", letterSpacing: "0.15em", marginTop: 1 }}>CLOUD SECURITY</span>
                      </div>
                    </div>
                    <p style={{ color: "#3d5166", fontSize: 12.5, margin: 0 }}>Sign in to your account to continue</p>
                  </div>
                );
              },
              Footer() {
                return (
                  <div style={{ textAlign: "center", paddingBottom: 16, color: "#1e2d3d", fontSize: 11 }}>
                    © {new Date().getFullYear()} Niagaros · All rights reserved
                  </div>
                );
              },
            }}
          >
            <AppContent />
          </Authenticator>
        </div>
      </div>
    </ThemeProvider>
  );
}
