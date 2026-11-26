import { useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { post } from "../api";
import { useApp } from "../context";

const Logo = () => (
  <svg width="22" height="22" viewBox="0 0 16 16" aria-hidden="true">
    <path d="M8 1l6 3v4c0 3.5-2.6 6.3-6 7-3.4-.7-6-3.5-6-7V4z" fill="var(--accent)" />
    <path d="M5 8.2l2 2 4-4" stroke="#fff" strokeWidth="1.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export function Layout() {
  const { me, isAdmin, domains, domain, setDomain } = useApp();
  const [open, setOpen] = useState(false);
  const loc = useLocation();

  const logout = async () => {
    const r = await post<{ redirect: string }>("/auth/logout");
    window.location.assign(r.redirect);
  };

  const link = (to: string, label: string) => (
    <NavLink to={to} onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? "active" : "")}>{label}</NavLink>
  );

  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "open" : ""}`} aria-label="Main navigation">
        <div className="brand"><Logo /> DMARC Portal</div>
        <nav className="nav">
          {link("/", "Dashboard")}
          {link("/sources", "Sending sources")}
          {link("/recommendations", "Recommendations")}
          {link("/dns", "DNS check")}
          <div className="nav-section">Explore</div>
          {link("/records", "Records")}
          {link("/reports", "Reports")}
          {isAdmin && link("/forensic", "Failure reports (RUF)")}
          <div className="nav-section">Operations</div>
          {link("/processing", "Mail processing")}
          {isAdmin && link("/settings", "Settings")}
          {isAdmin && link("/users", "Users & audit")}
        </nav>
        <div className="sidebar-foot">
          <div title={me.email ?? ""}><strong>{me.name}</strong></div>
          <div>{me.role === "admin" ? "Administrator" : "Viewer"}{me.is_local ? " · local account" : ""}</div>
          <button className="btn btn-ghost" style={{ padding: "6px 0" }} onClick={logout}>Sign out</button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button className="btn menu-toggle" onClick={() => setOpen(!open)} aria-label="Menu">☰</button>
          <label className="row" htmlFor="domain-select">
            <span className="muted">Domain</span>
            <select id="domain-select" value={domain ?? ""} onChange={(e) => setDomain(e.target.value)} disabled={!domains.length}>
              {!domains.length && <option value="">No domains yet</option>}
              {domains.map((d) => <option key={d.name} value={d.name}>{d.name}{d.parked ? " (parked)" : ""}</option>)}
            </select>
          </label>
          <span className="spacer" />
        </header>
        <main className="content" key={loc.pathname}>
          <Outlet />
        </main>
        <footer className="footer">
          IP data by <a href="https://db-ip.com" target="_blank" rel="noreferrer">DB-IP</a> (CC BY 4.0).
        </footer>
      </div>
    </div>
  );
}
