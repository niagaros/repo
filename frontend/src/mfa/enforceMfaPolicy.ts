import { fetchMFAPreference } from "aws-amplify/auth";

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

// Best-effort — a failed fetch (e.g. /team not deployed yet) resolves to
// false rather than throwing, so a missing backend never locks everyone
// out of the entire app.
async function orgRequiresMfa(token: string): Promise<boolean> {
  try {
    const resp = await fetch(`${getApiBase()}/team`, { headers: { Authorization: `Bearer ${token}` } });
    if (!resp.ok) return false;
    const data = await resp.json();
    return !!data.mfa_required;
  } catch {
    return false;
  }
}

/**
 * Issue #265, acceptance criterion #3: "Given MFA is required by policy,
 * when a user signs in without MFA configured, then access is blocked
 * until enrollment is completed."
 *
 * Shared by App.tsx (the real post-login entry point — checked here so
 * nobody reaches the AWS-onboarding-wizard or the dashboard redirect
 * without it) and useRequireAuth.ts (every /settings/* and /onboarding
 * page). Call once, right after resolving the access token; if this
 * returns true, stop rendering — a redirect to /mfa-setup is underway.
 *
 * Known residual gap: niagaros-dashboard.html is a static file served
 * outside the React app/router entirely. Someone who bookmarks or types
 * that URL directly skips App.tsx (and this check) completely — closing
 * that fully would mean adding an equivalent check inside that plain
 * HTML/JS page, which is a separate, smaller follow-up.
 */
export async function redirectToMfaSetupIfRequired(token: string): Promise<boolean> {
  if (window.location.pathname === "/mfa-setup") return false;
  if (!(await orgRequiresMfa(token))) return false;

  const pref = await fetchMFAPreference().catch(() => null);
  const hasMfaConfigured = !!pref?.enabled?.length;
  if (hasMfaConfigured) return false;

  window.location.href = "/mfa-setup";
  return true;
}
