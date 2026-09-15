import React, { useEffect, useState } from "react";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

// /settings/team — issue #265 "Invite Team".
//
// Scope for this MVP pass (matching the AWS-only approach used for #269):
//   - 4 fixed roles (Admin, Security, Compliance, Viewer), no custom roles.
//   - Invite, view, revoke, deactivate — no bulk invites, SSO/SCIM, audit
//     logs or approval workflows yet.
//   - Calls a NEW /team endpoint (api/team_handler.py) that is not yet
//     registered on API Gateway — this page won't work against production
//     until that backend is deployed. See docs/internal/architecture/aws/
//     api_inventory.md for how the other settings pages' endpoints work.

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

const ROLES = ["admin", "security", "compliance", "viewer"] as const;
type Role = typeof ROLES[number];

interface Member {
  id: string;
  email: string;
  full_name: string | null;
  role: Role;
  status: "active" | "deactivated";
  created_at: string;
}

interface Invite {
  id: string;
  email: string;
  role: Role;
  created_at: string;
}

type LoadState = "loading" | "loaded" | "error";

export default function Team() {
  const { loading: authLoading, email } = useRequireAuth();
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [members, setMembers]     = useState<Member[]>([]);
  const [invites, setInvites]     = useState<Invite[]>([]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole]   = useState<Role>("viewer");
  const [submitting, setSubmitting]   = useState(false);
  const [formError, setFormError]     = useState("");

  const token = () => localStorage.getItem("niagaros_token") || "";
  const authHeader = () => ({ Authorization: `Bearer ${token()}` });

  const load = async () => {
    try {
      const resp = await fetch(`${getApiBase()}/team`, { headers: authHeader(), cache: "no-store" });
      if (!resp.ok) throw new Error(String(resp.status));
      const data = await resp.json();
      setMembers(data.members || []);
      setInvites(data.pending_invites || []);
      setLoadState("loaded");
    } catch {
      setLoadState("error");
    }
  };

  useEffect(() => {
    if (authLoading || !email) return;
    load();
  }, [authLoading, email]);

  const submitInvite = async () => {
    setFormError("");
    if (!inviteEmail.trim() || !inviteEmail.includes("@")) {
      setFormError("Enter a valid email address.");
      return;
    }
    setSubmitting(true);
    try {
      const resp = await fetch(`${getApiBase()}/team/invite`, {
        method: "POST",
        headers: { ...authHeader(), "Content-Type": "application/json" },
        body: JSON.stringify({ email: inviteEmail.trim(), role: inviteRole }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        setFormError(data.error || "Could not send invite.");
        return;
      }
      setInviteEmail("");
      setInviteRole("viewer");
      await load();
    } catch {
      setFormError("Could not reach the server.");
    } finally {
      setSubmitting(false);
    }
  };

  const revokeInvite = async (id: string) => {
    await fetch(`${getApiBase()}/team/invite/${id}`, { method: "DELETE", headers: authHeader() });
    await load();
  };

  const deactivateMember = async (id: string) => {
    if (!confirm("Deactivate this team member? They will lose access.")) return;
    await fetch(`${getApiBase()}/team/member/${id}`, { method: "DELETE", headers: authHeader() });
    await load();
  };

  const changeRole = async (id: string, role: Role) => {
    await fetch(`${getApiBase()}/team/member/${id}`, {
      method: "PATCH",
      headers: { ...authHeader(), "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    });
    await load();
  };

  if (authLoading || loadState === "loading") return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  const cardStyle: React.CSSProperties = {
    background: "#111827", border: "1px solid #1e2433", borderRadius: 14,
    padding: "20px 24px", marginBottom: 20,
  };
  const badgeStyle = (color: string, bg: string): React.CSSProperties => ({
    fontSize: 10.5, fontWeight: 700, padding: "2px 9px", borderRadius: 4,
    background: bg, color, textTransform: "capitalize",
  });

  return (
    <SettingsLayout
      title="Team"
      subtitle="Invite team members and manage their roles."
      breadcrumb="Team"
      email={email}
    >
      {loadState === "error" && (
        <div style={{ ...cardStyle, borderColor: "rgba(239,68,68,0.4)", color: "#f87171", fontSize: 13 }}>
          Couldn't load the team — the backend for this page isn't deployed yet
          (see docs/internal/architecture/aws/api_inventory.md).
        </div>
      )}

      {/* Invite form */}
      <div style={cardStyle}>
        <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 14 }}>Invite a team member</div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div style={{ flex: 1, minWidth: 220 }}>
            <label style={{ display: "block", fontSize: 11, color: "#6b7280", marginBottom: 5 }}>Email</label>
            <input
              type="email"
              value={inviteEmail}
              onChange={e => setInviteEmail(e.target.value)}
              placeholder="colleague@company.com"
              style={{ width: "100%", background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: "9px 12px", color: "#e2e8f0", fontSize: 13 }}
            />
          </div>
          <div>
            <label style={{ display: "block", fontSize: 11, color: "#6b7280", marginBottom: 5 }}>Role</label>
            <select
              value={inviteRole}
              onChange={e => setInviteRole(e.target.value as Role)}
              style={{ background: "#0d1017", border: "1px solid #1e2433", borderRadius: 8, padding: "9px 12px", color: "#e2e8f0", fontSize: 13 }}
            >
              {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <button
            onClick={submitInvite}
            disabled={submitting}
            style={{ background: "#ef4444", color: "#fff", border: "none", borderRadius: 8, padding: "9px 20px", fontSize: 13, fontWeight: 600, cursor: submitting ? "default" : "pointer", opacity: submitting ? 0.6 : 1 }}
          >
            {submitting ? "Sending…" : "Send invite"}
          </button>
        </div>
        {formError && <div style={{ color: "#f87171", fontSize: 12, marginTop: 10 }}>{formError}</div>}
      </div>

      {/* Pending invites */}
      {invites.length > 0 && (
        <div style={cardStyle}>
          <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 14 }}>Pending invites</div>
          {invites.map(inv => (
            <div key={inv.id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0", borderTop: "1px solid #1a2030" }}>
              <span style={{ flex: 1, color: "#e2e8f0", fontSize: 13 }}>{inv.email}</span>
              <span style={badgeStyle("#fbbf24", "rgba(251,191,36,0.12)")}>{inv.role}</span>
              <span style={badgeStyle("#9ca3af", "#1a2030")}>pending</span>
              <button
                onClick={() => revokeInvite(inv.id)}
                style={{ background: "none", border: "1px solid #374151", color: "#9ca3af", borderRadius: 6, padding: "4px 10px", fontSize: 11, cursor: "pointer" }}
              >
                Revoke
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Members */}
      <div style={cardStyle}>
        <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 14 }}>Members ({members.length})</div>
        {members.map(m => (
          <div key={m.id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0", borderTop: "1px solid #1a2030" }}>
            <div style={{ flex: 1 }}>
              <div style={{ color: "#e2e8f0", fontSize: 13, fontWeight: 500 }}>{m.full_name || m.email}</div>
              {m.full_name && <div style={{ color: "#4e627a", fontSize: 11.5 }}>{m.email}</div>}
            </div>
            {m.status === "active" && m.email !== email ? (
              <select
                value={m.role}
                onChange={e => changeRole(m.id, e.target.value as Role)}
                style={{ background: "#0d1017", border: "1px solid #1e2433", borderRadius: 6, padding: "3px 8px", color: "#93c5fd", fontSize: 11.5 }}
              >
                {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            ) : (
              <span style={badgeStyle("#93c5fd", "rgba(59,130,246,0.12)")}>{m.role}</span>
            )}
            {m.status === "deactivated" ? (
              <span style={badgeStyle("#f87171", "rgba(239,68,68,0.12)")}>deactivated</span>
            ) : (
              <span style={badgeStyle("#4ade80", "rgba(22,163,74,0.12)")}>active</span>
            )}
            {m.status === "active" && m.email !== email && (
              <button
                onClick={() => deactivateMember(m.id)}
                style={{ background: "none", border: "1px solid #374151", color: "#9ca3af", borderRadius: 6, padding: "4px 10px", fontSize: 11, cursor: "pointer" }}
              >
                Deactivate
              </button>
            )}
          </div>
        ))}
      </div>
    </SettingsLayout>
  );
}
