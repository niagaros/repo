import { useEffect, useState } from "react";
import { fetchAuthSession, getCurrentUser } from "aws-amplify/auth";
import { redirectToMfaSetupIfRequired } from "../mfa/enforceMfaPolicy";

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

// Issue #265, acceptance criterion #1: "when the invitation is accepted,
// then the user is provisioned with the assigned role and team." Fired
// once, silently, on every authenticated page load — a genuine no-op
// (accepted: False) for the vast majority of logins that have no pending
// invite, and safe to call repeatedly. Errors are swallowed on purpose:
// this must never block a page from loading, especially since /team isn't
// deployed to production yet (see api_inventory.md).
function tryAcceptPendingInvite(token: string) {
  fetch(`${getApiBase()}/team/accept-invite`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  }).catch(() => {});
}

export function useRequireAuth() {
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const session = await fetchAuthSession();
        const accessToken = session.tokens?.accessToken?.toString();
        if (!accessToken) {
          window.location.href = "/";
          return;
        }
        const user = await getCurrentUser();
        setEmail(user.signInDetails?.loginId || user.username || "");
        tryAcceptPendingInvite(accessToken);

        if (await redirectToMfaSetupIfRequired(accessToken)) return;

        setLoading(false);
      } catch {
        window.location.href = "/";
      }
    })();
  }, []);

  return { loading, email };
}
