import { useEffect, useState } from "react";
import { fetchAuthSession, getCurrentUser } from "aws-amplify/auth";
import { redirectToMfaSetupIfRequired } from "../mfa/enforceMfaPolicy";
import { acceptPendingInvite, redirectAuditorToPortal } from "../auth/postLoginRouting";

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

        // Every settings page reads its bearer token from this one
        // localStorage key, but until now only App.tsx's checkAccount()
        // ever wrote it. Landing directly on a settings page (bookmark,
        // refresh, a shared link, an auditor going straight to /auditor)
        // therefore sent either nothing or a stale token from an earlier
        // session — and Cognito access tokens expire after about an hour,
        // so even a correct login went stale while Amplify itself already
        // held a fresh, auto-refreshed one. Writing it here, on every
        // authenticated page load, keeps all of those pages working.
        localStorage.setItem("niagaros_token", accessToken);

        const user = await getCurrentUser();
        setEmail(user.signInDetails?.loginId || user.username || "");
        await acceptPendingInvite(accessToken);

        if (await redirectToMfaSetupIfRequired(accessToken)) return;

        // Een auditor hoort hier niet te komen. Hij heeft geen users-rij in de
        // organisatie, dus deze pagina's gaven hem alleen lege blokken en
        // foutmeldingen in plaats van hem te vertellen waar hij wél moet zijn.
        // De functie laat /auditor zelf met rust, anders stuurt dit zichzelf
        // in een kring.
        if (await redirectAuditorToPortal(accessToken)) return;

        setLoading(false);
      } catch {
        window.location.href = "/";
      }
    })();
  }, []);

  return { loading, email };
}
