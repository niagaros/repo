import { useEffect, useState } from "react";
import { fetchAuthSession, getCurrentUser } from "aws-amplify/auth";

export function useRequireAuth() {
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const session = await fetchAuthSession();
        if (!session.tokens?.accessToken) {
          window.location.href = "/";
          return;
        }
        const user = await getCurrentUser();
        setEmail(user.signInDetails?.loginId || user.username || "");
        setLoading(false);
      } catch {
        window.location.href = "/";
      }
    })();
  }, []);

  return { loading, email };
}
