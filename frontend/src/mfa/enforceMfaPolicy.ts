import { fetchMFAPreference } from "aws-amplify/auth";

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

// Best-effort — a failed fetch (e.g. /team not deployed yet) resolves to
// false rather than throwing, so a missing backend never locks everyone
// out of the entire app.
//
// One caller reaches the 401 branch by design rather than by accident, and
// that is worth stating because the code cannot tell the two apart. An
// auditor has no row in the audited organization's `users` table, so /team
// turns them away, and they end up here as "no MFA required".
//
// That is the intended outcome. An organization's MFA policy is a setting an
// admin makes for their own people; an auditor is not one of them, works for
// the firm that was hired rather than for the organization, and may serve
// several organizations at once — so whichever one invited them first would
// otherwise decide what applies to their personal account. Decided on
// 20 October 2026 and recorded here, because the alternative is that it keeps
// looking like something nobody considered.
//
// What this branch does NOT distinguish is a backend that is simply down.
// Then everyone skips the check, which is the deliberate trade-off in the
// paragraph above: a platform that locks every user out during an outage is
// worse. Noted as a residual, same as the static dashboard below.
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
