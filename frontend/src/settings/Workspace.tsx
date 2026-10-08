import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import SettingsLayout from "./SettingsLayout";
import { useRequireAuth } from "./useRequireAuth";

// /settings/workspace — step 4 of the onboarding accelerator, issue #268
// "Connect Workspaces".
//
// This page is the hub the issue's first acceptance criterion asks for: on
// opening it, the six integration categories are shown. What sits behind
// each category differs sharply, and the page says so rather than implying
// an even surface:
//
//   - Ticketing (Jira, Monday.com) is real. The backend for it was built
//     under issue #279 and runs as the `integrations-handler` Lambda behind
//     GET/POST /integrations. Until now nothing called it — the endpoint
//     existed without a screen, which is why `workspace_integrations` was
//     empty. This page is that screen.
//   - Source control (GitHub) is real but lives elsewhere, at
//     /settings/github, and points the other way: it reads a GitHub org in
//     order to assess it, rather than pushing findings out. It is linked
//     from here instead of duplicated.
//   - Communication, Identity, SIEM and CI/CD are shown as in development.
//     Each needs a business account at the vendor to authenticate against,
//     and an integration that cannot be tested is not an integration. The
//     same approach is used for the non-AWS cloud providers in step 1.
//
// See the afbakeningsnotitie for #268 for which acceptance criteria that
// covers (1, 2 and 10, plus making 6 reachable) and which it does not.

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

interface CloudAccount {
  id: string;
  account_name: string | null;
  account_id: string;
}

interface Ticket {
  finding_id: string;
  key: string | null;
  url: string | null;
  status: string | null;
  last_synced_at: string | null;
}

interface Integration {
  id: string;
  provider: string;
  site_url: string | null;
  account_label: string | null;
  project: string | null;
  created_at: string;
  last_sync_at: string | null;
  tickets: Ticket[];
}

interface Project {
  id: string;
  name: string;
}

type Availability = "ready" | "elsewhere" | "planned";

interface Provider {
  id: string;
  name: string;
  availability: Availability;
  note: string;
}

interface Category {
  id: string;
  name: string;
  purpose: string;
  providers: Provider[];
}

// The six categories are the ones named in the onboarding step itself
// ("source control, ticketing, communication, identity, SIEM and CI/CD").
// The providers listed per category follow the issue; only the three marked
// "ready" or "elsewhere" have anything behind them today.
const CATALOGUE: Category[] = [
  {
    id: "source-control",
    name: "Source Control",
    purpose: "Assess repository settings against the CIS GitHub Benchmark.",
    providers: [
      { id: "github", name: "GitHub", availability: "elsewhere", note: "Managed on its own page" },
      { id: "gitlab", name: "GitLab", availability: "planned", note: "" },
      { id: "bitbucket", name: "Bitbucket", availability: "planned", note: "" },
    ],
  },
  {
    id: "ticketing",
    name: "Ticketing",
    purpose: "Turn a finding into a ticket and follow its status back.",
    providers: [
      { id: "jira", name: "Jira Cloud", availability: "ready", note: "" },
      { id: "monday", name: "Monday.com", availability: "ready", note: "" },
      { id: "servicenow", name: "ServiceNow", availability: "planned", note: "" },
    ],
  },
  {
    id: "communication",
    name: "Communication",
    purpose: "Notify a channel when a critical finding appears.",
    providers: [
      { id: "slack", name: "Slack", availability: "planned", note: "" },
      { id: "teams", name: "Microsoft Teams", availability: "planned", note: "" },
      { id: "discord", name: "Discord", availability: "planned", note: "" },
    ],
  },
  {
    id: "identity",
    name: "Identity",
    purpose: "Synchronize users and groups from the identity provider.",
    providers: [
      { id: "entra", name: "Microsoft Entra ID", availability: "planned", note: "" },
      { id: "okta", name: "Okta", availability: "planned", note: "" },
    ],
  },
  {
    id: "siem",
    name: "SIEM",
    purpose: "Forward security events to the central log platform.",
    providers: [
      { id: "splunk", name: "Splunk", availability: "planned", note: "" },
      { id: "sentinel", name: "Microsoft Sentinel", availability: "planned", note: "" },
    ],
  },
  {
    id: "cicd",
    name: "CI/CD",
    purpose: "Read deployment events so findings can be tied to a release.",
    providers: [
      { id: "github-actions", name: "GitHub Actions", availability: "planned", note: "" },
      { id: "gitlab-ci", name: "GitLab CI", availability: "planned", note: "" },
      { id: "jenkins", name: "Jenkins", availability: "planned", note: "" },
    ],
  },
];

const PROVIDER_LABEL: Record<string, string> = { jira: "Jira Cloud", monday: "Monday.com" };

const card: React.CSSProperties = {
  background: "#111827", border: "1px solid #1e2433", borderRadius: 14,
  padding: "22px 26px", marginBottom: 16,
};

const label: React.CSSProperties = {
  fontSize: 11, fontWeight: 700, color: "#374151",
  textTransform: "uppercase", letterSpacing: "0.1em",
};

const input: React.CSSProperties = {
  width: "100%", background: "#0d0f14", border: "1px solid #1e2433",
  borderRadius: 8, padding: "9px 12px", color: "#f1f5f9", fontSize: 13,
  fontFamily: "inherit", boxSizing: "border-box",
};

const primaryButton = (disabled: boolean): React.CSSProperties => ({
  background: "#ef4444", border: "none", borderRadius: 8, color: "#fff",
  fontSize: 13, fontWeight: 600, padding: "9px 22px",
  cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? 0.6 : 1,
});

const quietButton: React.CSSProperties = {
  background: "none", border: "1px solid #374151", color: "#9ca3af",
  borderRadius: 7, padding: "5px 12px", fontSize: 11.5, cursor: "pointer",
};

const formatDate = (iso: string | null) =>
  !iso ? "never" : new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });

export default function Workspace() {
  const { loading: authLoading, email } = useRequireAuth();
  const navigate = useNavigate();

  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [accountId, setAccountId] = useState("");
  const [accountsLoaded, setAccountsLoaded] = useState(false);

  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [loadError, setLoadError] = useState("");
  const [githubConnected, setGithubConnected] = useState(false);

  // Connect flow. `provider` is the one being set up; `projects` is filled
  // once the credentials have been accepted by the provider itself.
  const [provider, setProvider] = useState<string | null>(null);
  const [siteUrl, setSiteUrl] = useState("");
  const [providerEmail, setProviderEmail] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [formError, setFormError] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [newIntegrationId, setNewIntegrationId] = useState("");
  const [authenticatedAs, setAuthenticatedAs] = useState("");
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [chosenProject, setChosenProject] = useState("");

  const [busyId, setBusyId] = useState("");
  const [rowError, setRowError] = useState<Record<string, string>>({});
  const [syncResult, setSyncResult] = useState<Record<string, string>>({});

  const token = () => localStorage.getItem("niagaros_token") || "";
  const authHeader = () => ({ Authorization: `Bearer ${token()}` });

  // ── Loading ───────────────────────────────────────────────────────────────

  useEffect(() => {
    if (authLoading || !email) return;
    (async () => {
      try {
        const resp = await fetch(`${getApiBase()}/team/cloud-accounts`, { headers: authHeader(), cache: "no-store" });
        if (resp.ok) {
          const data = await resp.json();
          const list: CloudAccount[] = data.accounts || [];
          setAccounts(list);
          if (list.length > 0) setAccountId(list[0].id);
        }
      } catch {
        // An empty list is handled below as "connect AWS first".
      } finally {
        setAccountsLoaded(true);
      }

      try {
        const resp = await fetch(`${getApiBase()}/github-integration`, { headers: authHeader(), cache: "no-store" });
        if (resp.ok) {
          const data = await resp.json();
          setGithubConnected(Boolean(data.connected));
        }
      } catch {
        // The tile simply shows no badge.
      }
    })();
  }, [authLoading, email]);

  const loadIntegrations = async (id: string) => {
    setLoadError("");
    try {
      const resp = await fetch(`${getApiBase()}/integrations?cloud_account_id=${encodeURIComponent(id)}`, {
        headers: authHeader(), cache: "no-store",
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        setLoadError(data.error || "Could not retrieve the connected integrations.");
        setIntegrations([]);
        return;
      }
      setIntegrations(data.integrations || []);
    } catch {
      setLoadError("Could not reach the server.");
      setIntegrations([]);
    }
  };

  useEffect(() => {
    if (accountId) loadIntegrations(accountId);
  }, [accountId]);

  // ── Connect ───────────────────────────────────────────────────────────────

  const startConnect = (p: Provider) => {
    if (p.availability === "elsewhere") {
      navigate("/settings/github");
      return;
    }
    if (p.availability !== "ready") return;
    setProvider(p.id);
    setSiteUrl("");
    setProviderEmail("");
    setApiToken("");
    setFormError("");
    setProjects(null);
    setNewIntegrationId("");
    setAuthenticatedAs("");
    setChosenProject("");
  };

  const cancelConnect = () => {
    setProvider(null);
    setApiToken("");
    setProjects(null);
    setFormError("");
  };

  // The credentials are checked against the provider before anything is
  // stored, and the token goes to Secrets Manager rather than the database.
  // Both of those are the backend's doing; this form only hands it over and
  // never keeps the token after the call.
  const submitCredentials = async () => {
    setFormError("");
    if (!accountId) {
      setFormError("Select a cloud account first.");
      return;
    }
    if (!apiToken.trim()) {
      setFormError("An API token is required.");
      return;
    }
    if (provider === "jira" && !/^https:\/\/[a-z0-9][a-z0-9-]{1,62}\.atlassian\.net$/.test(siteUrl.trim())) {
      setFormError("The site must look like https://your-company.atlassian.net");
      return;
    }
    if (provider === "jira" && !providerEmail.trim()) {
      setFormError("Jira authenticates on an email address plus an API token.");
      return;
    }

    setConnecting(true);
    try {
      const resp = await fetch(`${getApiBase()}/integrations`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({
          action: "connect",
          provider,
          cloud_account_id: accountId,
          site_url: provider === "jira" ? siteUrl.trim() : undefined,
          email: provider === "jira" ? providerEmail.trim() : undefined,
          api_token: apiToken.trim(),
        }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        setFormError(data.error || "The provider rejected these credentials.");
        return;
      }
      setApiToken("");
      setNewIntegrationId(data.id);
      setAuthenticatedAs(data.authenticated_as || "");
      setProjects(data.projects || []);
      setChosenProject((data.projects || [])[0]?.id || "");
      loadIntegrations(accountId);
    } catch {
      setFormError("Could not reach the server.");
    } finally {
      setConnecting(false);
    }
  };

  const submitProject = async () => {
    setFormError("");
    setConnecting(true);
    try {
      const resp = await fetch(`${getApiBase()}/integrations`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({ action: "select_project", integration_id: newIntegrationId, project: chosenProject }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        setFormError(data.error || "Could not save that project.");
        return;
      }
      await loadIntegrations(accountId);
      cancelConnect();
    } catch {
      setFormError("Could not reach the server.");
    } finally {
      setConnecting(false);
    }
  };

  // ── Row actions ───────────────────────────────────────────────────────────

  const syncNow = async (id: string) => {
    setBusyId(id);
    setRowError({ ...rowError, [id]: "" });
    try {
      const resp = await fetch(`${getApiBase()}/integrations`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({ action: "sync", integration_id: id }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        setRowError({ ...rowError, [id]: data.error || "Synchronization failed." });
        return;
      }
      const n = (data.synced || []).length;
      setSyncResult({ ...syncResult, [id]: n === 0 ? "No tickets to synchronize yet." : `${n} ticket${n === 1 ? "" : "s"} synchronized.` });
      await loadIntegrations(accountId);
    } catch {
      setRowError({ ...rowError, [id]: "Could not reach the server." });
    } finally {
      setBusyId("");
    }
  };

  const disconnect = async (integration: Integration) => {
    const name = PROVIDER_LABEL[integration.provider] || integration.provider;
    if (!confirm(
      `Disconnect ${name}?\n\nThe stored API token is deleted. Tickets already created in ${name} stay where they are, ` +
      `but Niagaros stops following their status.`
    )) return;

    setBusyId(integration.id);
    setRowError({ ...rowError, [integration.id]: "" });
    try {
      const resp = await fetch(`${getApiBase()}/integrations`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeader() },
        body: JSON.stringify({ action: "disconnect", integration_id: integration.id }),
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        setRowError({ ...rowError, [integration.id]: data.error || "Could not disconnect." });
        return;
      }
      await loadIntegrations(accountId);
    } catch {
      setRowError({ ...rowError, [integration.id]: "Could not reach the server." });
    } finally {
      setBusyId("");
    }
  };

  // ── Render ────────────────────────────────────────────────────────────────

  if (authLoading) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#080b12", color: "#64748b", fontSize: 14 }}>
      Loading…
    </div>
  );

  const connectedProviderIds = new Set(integrations.map(i => i.provider));

  const badgeFor = (p: Provider) => {
    if (p.id === "github" && githubConnected) return { text: "Connected", color: "#4ade80", bg: "rgba(22,163,74,0.12)", border: "rgba(22,163,74,0.3)" };
    if (p.availability === "elsewhere") return { text: "Own page", color: "#9ca3af", bg: "#0d0f14", border: "#1e2433" };
    if (connectedProviderIds.has(p.id)) return { text: "Connected", color: "#4ade80", bg: "rgba(22,163,74,0.12)", border: "rgba(22,163,74,0.3)" };
    if (p.availability === "ready") return { text: "Available", color: "#ef4444", bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.25)" };
    return { text: "In development", color: "#4e627a", bg: "#0d0f14", border: "#1a2030" };
  };

  return (
    <SettingsLayout
      title="Connect Workspaces"
      subtitle="Connect the tools your team already works in, so findings end up where the work happens instead of only in this dashboard."
      breadcrumb="Workspace"
      email={email}
    >
      {/* ── Which cloud account ───────────────────────────────────────────── */}
      {accountsLoaded && accounts.length === 0 && (
        <div style={{ ...card, maxWidth: 760 }}>
          <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, marginBottom: 6 }}>Connect a cloud account first</div>
          <div style={{ color: "#64748b", fontSize: 13, lineHeight: 1.7, marginBottom: 16 }}>
            A workspace integration hangs off a connected cloud account, because what it carries across
            are that account's findings. Step 1 of the onboarding sets that up.
          </div>
          <button onClick={() => navigate("/settings/infrastructure")} style={primaryButton(false)}>
            Go to Cloud Infrastructure
          </button>
        </div>
      )}

      {accounts.length > 1 && (
        <div style={{ ...card, maxWidth: 760 }}>
          <div style={{ ...label, marginBottom: 10 }}>Cloud account</div>
          <select
            value={accountId}
            onChange={e => setAccountId(e.target.value)}
            style={{ ...input, maxWidth: 420 }}
          >
            {accounts.map(a => (
              <option key={a.id} value={a.id}>
                {a.account_name || "Unnamed account"} — {a.account_id}
              </option>
            ))}
          </select>
          <div style={{ color: "#4e627a", fontSize: 12, marginTop: 10, lineHeight: 1.6 }}>
            Integrations are kept per cloud account, not per organization. An account with its own
            Jira project therefore gets its own connection here.
          </div>
        </div>
      )}

      {/* ── What is connected ─────────────────────────────────────────────── */}
      {accountId && (
        <div style={{ ...card, maxWidth: 760 }}>
          <div style={{ ...label, marginBottom: 14 }}>Connected</div>

          {loadError && (
            <div style={{ color: "#f87171", fontSize: 12.5, marginBottom: 12 }}>{loadError}</div>
          )}

          {!loadError && integrations.length === 0 && (
            <div style={{ color: "#4e627a", fontSize: 12.5 }}>
              Nothing connected for this account yet. Pick a provider below.
            </div>
          )}

          {integrations.map(i => (
            <div key={i.id} style={{ borderTop: "1px solid #1a2030", padding: "14px 0" }}>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ color: "#f1f5f9", fontSize: 13.5, fontWeight: 600 }}>
                    {PROVIDER_LABEL[i.provider] || i.provider}
                    {i.account_label && <span style={{ color: "#64748b", fontWeight: 400 }}> — {i.account_label}</span>}
                  </div>
                  <div style={{ color: "#4e627a", fontSize: 12, marginTop: 5, lineHeight: 1.7 }}>
                    {i.site_url && <>{i.site_url}<br /></>}
                    {i.project
                      ? <>Project <span style={{ color: "#9ca3af" }}>{i.project}</span></>
                      : <span style={{ color: "#fbbf24" }}>No project selected yet — no tickets can be created.</span>}
                    <br />
                    Connected {formatDate(i.created_at)} · last synchronized {formatDate(i.last_sync_at)} ·{" "}
                    {i.tickets.length} ticket{i.tickets.length === 1 ? "" : "s"}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 7, flexShrink: 0 }}>
                  <button onClick={() => syncNow(i.id)} disabled={busyId === i.id} style={{ ...quietButton, opacity: busyId === i.id ? 0.5 : 1 }}>
                    {busyId === i.id ? "Working…" : "Synchronize"}
                  </button>
                  <button
                    onClick={() => disconnect(i)}
                    disabled={busyId === i.id}
                    style={{ ...quietButton, borderColor: "rgba(239,68,68,0.3)", color: "#ef4444", opacity: busyId === i.id ? 0.5 : 1 }}
                  >
                    Disconnect
                  </button>
                </div>
              </div>

              {rowError[i.id] && <div style={{ color: "#f87171", fontSize: 12, marginTop: 8 }}>{rowError[i.id]}</div>}
              {syncResult[i.id] && <div style={{ color: "#4ade80", fontSize: 12, marginTop: 8 }}>{syncResult[i.id]}</div>}

              {i.tickets.length > 0 && (
                <div style={{ marginTop: 10, paddingLeft: 2 }}>
                  {i.tickets.map(t => (
                    <div key={t.finding_id} style={{ display: "flex", gap: 12, fontSize: 12, padding: "4px 0", color: "#64748b" }}>
                      <span style={{ flex: "0 0 120px", color: "#9ca3af" }}>
                        {t.url ? <a href={t.url} target="_blank" rel="noreferrer" style={{ color: "#9ca3af" }}>{t.key}</a> : t.key}
                      </span>
                      <span style={{ flex: 1 }}>{t.status || "unknown"}</span>
                      <span>{formatDate(t.last_synced_at)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ── Connect form ──────────────────────────────────────────────────── */}
      {provider && (
        <div style={{ ...card, maxWidth: 760, borderColor: "rgba(239,68,68,0.25)" }}>
          <div style={{ display: "flex", alignItems: "center", marginBottom: 16 }}>
            <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14, flex: 1 }}>
              Connect {PROVIDER_LABEL[provider] || provider}
            </div>
            <button onClick={cancelConnect} style={{ background: "none", border: "none", color: "#64748b", fontSize: 18, cursor: "pointer", lineHeight: 1 }}>×</button>
          </div>

          {projects === null ? (
            <>
              {provider === "jira" && (
                <>
                  <div style={{ marginBottom: 14 }}>
                    <div style={{ ...label, marginBottom: 6 }}>Jira site</div>
                    <input value={siteUrl} onChange={e => setSiteUrl(e.target.value)} placeholder="https://your-company.atlassian.net" style={input} />
                  </div>
                  <div style={{ marginBottom: 14 }}>
                    <div style={{ ...label, marginBottom: 6 }}>Account email</div>
                    <input value={providerEmail} onChange={e => setProviderEmail(e.target.value)} placeholder="you@your-company.com" style={input} />
                  </div>
                </>
              )}
              <div style={{ marginBottom: 14 }}>
                <div style={{ ...label, marginBottom: 6 }}>API token</div>
                <input type="password" value={apiToken} onChange={e => setApiToken(e.target.value)} autoComplete="off" style={input} />
                <div style={{ color: "#4e627a", fontSize: 11.5, marginTop: 7, lineHeight: 1.6 }}>
                  The token is verified with {PROVIDER_LABEL[provider] || provider} before anything is saved, and is then
                  stored in AWS Secrets Manager — never in the database, and never sent back to this page.
                </div>
              </div>

              {formError && <div style={{ color: "#f87171", fontSize: 12.5, marginBottom: 14 }}>{formError}</div>}

              <button onClick={submitCredentials} disabled={connecting} style={primaryButton(connecting)}>
                {connecting ? "Verifying…" : "Verify and connect"}
              </button>
            </>
          ) : (
            <>
              <div style={{ color: "#4ade80", fontSize: 12.5, marginBottom: 16 }}>
                Authenticated{authenticatedAs ? ` as ${authenticatedAs}` : ""}. Choose where tickets should be created.
              </div>

              {projects.length === 0 ? (
                <div style={{ color: "#fbbf24", fontSize: 12.5, marginBottom: 16, lineHeight: 1.7 }}>
                  The connection works, but this account cannot see a single project or board.
                  Create one at the provider, or use an account that has access to one, and connect again.
                </div>
              ) : (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ ...label, marginBottom: 6 }}>Project</div>
                  <select value={chosenProject} onChange={e => setChosenProject(e.target.value)} style={{ ...input, maxWidth: 420 }}>
                    {projects.map(p => <option key={p.id} value={p.id}>{p.name} ({p.id})</option>)}
                  </select>
                </div>
              )}

              {formError && <div style={{ color: "#f87171", fontSize: 12.5, marginBottom: 14 }}>{formError}</div>}

              <div style={{ display: "flex", gap: 10 }}>
                <button onClick={submitProject} disabled={connecting || !chosenProject} style={primaryButton(connecting || !chosenProject)}>
                  {connecting ? "Saving…" : "Save project"}
                </button>
                <button onClick={cancelConnect} style={{ ...quietButton, padding: "9px 18px", fontSize: 13 }}>
                  Later
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {/* ── The catalogue — acceptance criterion 1 ────────────────────────── */}
      {CATALOGUE.map(cat => (
        <div key={cat.id} style={{ ...card, maxWidth: 760 }}>
          <div style={{ marginBottom: 14 }}>
            <div style={{ color: "#f1f5f9", fontWeight: 700, fontSize: 14 }}>{cat.name}</div>
            <div style={{ color: "#4e627a", fontSize: 12.5, marginTop: 4 }}>{cat.purpose}</div>
          </div>

          <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
            {cat.providers.map(p => {
              const badge = badgeFor(p);
              const clickable = p.availability === "ready" || p.availability === "elsewhere";
              return (
                <div
                  key={p.id}
                  onClick={() => clickable && startConnect(p)}
                  style={{
                    flex: "1 1 200px", minWidth: 200,
                    background: "#0d0f14",
                    border: `1px solid ${clickable ? "#1e2433" : "#151b28"}`,
                    borderRadius: 10, padding: "13px 15px",
                    cursor: clickable ? "pointer" : "default",
                    opacity: clickable ? 1 : 0.55,
                    transition: "border-color 0.12s",
                  }}
                  onMouseEnter={e => { if (clickable) (e.currentTarget as HTMLElement).style.borderColor = "#374151"; }}
                  onMouseLeave={e => { if (clickable) (e.currentTarget as HTMLElement).style.borderColor = "#1e2433"; }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ color: "#e5e7eb", fontSize: 13, fontWeight: 600, flex: 1 }}>{p.name}</span>
                    <span style={{
                      fontSize: 10, fontWeight: 700, padding: "2px 7px", borderRadius: 4,
                      background: badge.bg, color: badge.color, border: `1px solid ${badge.border}`,
                      whiteSpace: "nowrap",
                    }}>
                      {badge.text}
                    </span>
                  </div>
                  {p.note && <div style={{ color: "#4e627a", fontSize: 11, marginTop: 5 }}>{p.note}</div>}
                </div>
              );
            })}
          </div>
        </div>
      ))}

      {/* ── Why four categories are empty ─────────────────────────────────── */}
      <div style={{ ...card, maxWidth: 760, background: "#0d0f14" }}>
        <div style={{ ...label, marginBottom: 10 }}>Why some providers are still in development</div>
        <div style={{ color: "#64748b", fontSize: 12.5, lineHeight: 1.8 }}>
          Every integration authenticates against the vendor itself, so it can only be released once it
          has been tested against a real account there. Ticketing is available because that test could be
          done. Communication, identity, SIEM and CI/CD are designed and queued behind the accounts needed
          to prove them, and are shown here so the direction is visible rather than hidden.
        </div>
      </div>
    </SettingsLayout>
  );
}
