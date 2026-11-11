import { useEffect, useState } from "react";

// Who may see the onboarding analytics.
//
// The rule itself lives in the backend — admin *and* a member of Niagaros —
// and this hook does not reimplement it. It asks. That matters: a copy of the
// rule in the browser is a second rule, and the moment the two disagree the
// one that draws the menu is the one everybody notices, while the one that
// guards the data is the one that counts.
//
// Three states, not two. `null` means the answer has not arrived yet, and the
// difference between "not yet" and "no" is what keeps a menu entry from
// flickering into view and out again on every page load.

export type AnalyticsAccess = boolean | null;

// One answer per browser session. Role and organization do not change while
// someone is signed in, and without this every page that draws the sidebar
// would spend a request asking the same question again.
const CACHE_KEY = "niagaros_analytics_access";

function getApiBase(): string {
  return (window as any).__NIAGAROS_CONFIG__?.REACT_APP_API_BASE_URL || "";
}

function cached(): AnalyticsAccess {
  try {
    const v = sessionStorage.getItem(CACHE_KEY);
    return v === null ? null : v === "true";
  } catch {
    // Private windows and blocked site data throw here. Not being able to
    // remember the answer is not a reason to fail; it only costs a request.
    return null;
  }
}

function remember(value: boolean) {
  try {
    sessionStorage.setItem(CACHE_KEY, String(value));
  } catch {
    /* see above */
  }
}

export function useAnalyticsAccess(ready: boolean): AnalyticsAccess {
  const [access, setAccess] = useState<AnalyticsAccess>(cached);

  useEffect(() => {
    if (!ready || access !== null) return;
    let cancelled = false;
    (async () => {
      try {
        const resp = await fetch(`${getApiBase()}/analytics/access`, {
          cache: "no-store",
          headers: { Authorization: `Bearer ${localStorage.getItem("niagaros_token") || ""}` },
        });
        // Anything other than a clear yes is a no. An endpoint that is not
        // deployed yet, or a token that has gone stale, must not open a door.
        const allowed = resp.ok ? (await resp.json()).may_view === true : false;
        if (cancelled) return;
        remember(allowed);
        setAccess(allowed);
      } catch {
        if (!cancelled) setAccess(false);
      }
    })();
    return () => { cancelled = true; };
  }, [ready, access]);

  return access;
}
