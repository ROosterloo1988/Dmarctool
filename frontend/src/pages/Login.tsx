import { useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../api";

const MESSAGES: Record<string, string> = {
  signin_failed: "Signing in with Microsoft failed. Please try again.",
  no_access: "Your account has no access to the DMARC portal. Ask IT to assign you the DMARC Admin or Viewer role.",
};

export function Login() {
  const params = new URLSearchParams(location.search);
  const { data: cfg } = useQuery({ queryKey: ["auth-config"], queryFn: () => api<{ oidc: boolean; local: boolean }>("/auth/config") });
  const [user, setUser] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(MESSAGES[params.get("error") ?? ""] ?? null);
  const [busy, setBusy] = useState(false);
  const next = params.get("next");
  const target = next && next.startsWith("/") && !next.startsWith("//") ? next : "/";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await api("/auth/local-login", { method: "POST", body: JSON.stringify({ username: user, password: pw }) });
      window.location.assign(target);
    } catch (ex) {
      setErr(ex instanceof ApiError ? ex.message : "Sign-in failed");
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <div className="card login-card">
        <h1>DMARC Portal</h1>
        <p className="muted" style={{ margin: 0 }}>Reports, sending sources and DNS status for our mail domains.</p>
        {params.get("logged_out") && <div className="alert alert-good">You have been signed out.</div>}
        {err && <div className="alert alert-critical" role="alert">{err}</div>}
        {cfg?.oidc && <a className="btn btn-primary" href="/auth/login">Sign in with Microsoft</a>}
        {cfg?.local && (
          <>
            {cfg.oidc && <div className="divider">or emergency local account</div>}
            <form className="stack" onSubmit={submit}>
              <label className="field">Username<input autoComplete="username" value={user} onChange={(e) => setUser(e.target.value)} required /></label>
              <label className="field">Password<input type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} required /></label>
              <button className="btn" disabled={busy} type="submit">{busy ? "Signing in…" : "Sign in"}</button>
            </form>
          </>
        )}
        {cfg && !cfg.oidc && !cfg.local && <div className="alert alert-critical">No sign-in method is configured. See the README (DMARC_OIDC_*).</div>}
      </div>
    </div>
  );
}
