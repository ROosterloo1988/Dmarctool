import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../api";
import { num, pct } from "../format";
import type { Recommendation, SourceStatus } from "../types";

type Tone = "good" | "warning" | "serious" | "critical" | "neutral" | "info";
const ICON: Record<Tone, string> = { good: "✓", warning: "!", serious: "!", critical: "✕", neutral: "•", info: "i" };

export function Pill({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`pill pill-${tone}`} title={title}>
      <span className="pill-icon" aria-hidden="true">{ICON[tone]}</span>
      {children}
    </span>
  );
}

export function PassPill({ ok, yes = "pass", no = "fail" }: { ok: boolean; yes?: string; no?: string }) {
  return <Pill tone={ok ? "good" : "critical"}>{ok ? yes : no}</Pill>;
}

export function ResultPill({ result }: { result: string }) {
  const tone: Tone = result === "pass" ? "good" : result === "softfail" || result === "neutral" ? "warning"
    : result === "none" ? "neutral" : "critical";
  return <Pill tone={tone}>{result}</Pill>;
}

export function SeverityPill({ severity }: { severity: string }) {
  const tone: Tone = severity === "error" ? "critical" : severity === "warning" ? "warning" : severity === "ok" ? "good" : "info";
  return <Pill tone={tone}>{severity}</Pill>;
}

export function StatusPill({ status, recognised }: { status: SourceStatus; recognised?: boolean }) {
  if (status === "legit") return <Pill tone="good">legitimate</Pill>;
  if (status === "abuse") return <Pill tone="critical">abuse</Pill>;
  if (status === "unknown") return <Pill tone="warning">unknown</Pill>;
  return <Pill tone="neutral">{recognised ? "recognised" : "unclassified"}</Pill>;
}

export function PolicyPill({ policy }: { policy: string | null | undefined }) {
  if (!policy) return <Pill tone="critical">no policy</Pill>;
  const tone: Tone = policy === "reject" ? "good" : policy === "quarantine" ? "warning" : "serious";
  return <Pill tone={tone}>p={policy}</Pill>;
}

/** Pass-rate value with a thin bar; the number is always shown so colour never carries meaning alone. */
export function PctBar({ value }: { value: number | null | undefined }) {
  const v = value ?? 0;
  return (
    <span className="pctbar" title={pct(value)}>
      <span className="pctbar-track"><span className="pctbar-fill" style={{ width: `${Math.max(0, Math.min(100, v))}%` }} /></span>
      <span className="pctbar-label">{pct(value)}</span>
    </span>
  );
}

export function Kpi({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Loading() {
  return <div className="muted pad" role="status">Loading…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof ApiError ? `${error.status}: ${error.message}` : String(error);
  return <div className="alert alert-critical" role="alert">Something went wrong — {msg}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="pager">
      <span className="muted">{num(total)} rows</span>
      <button className="btn btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹ Prev</button>
      <span>Page {page} of {pages}</span>
      <button className="btn btn-ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next ›</button>
    </div>
  );
}

export function RecommendationList({ items, domain }: { items: Recommendation[]; domain: string }) {
  if (!items.length) return <Empty>No recommendations — nothing to fix right now.</Empty>;
  return (
    <ul className="recs">
      {items.map((r, i) => (
        <li key={i} className={`rec rec-${r.severity}`}>
          <div className="rec-head">
            <SeverityPill severity={r.severity} />
            <strong>{r.title}</strong>
          </div>
          {r.text && <p>{r.text}</p>}
          {r.actions.length > 0 && (
            <ul className="rec-actions">
              {r.actions.map((a, j) => <li key={j}>{a}</li>)}
            </ul>
          )}
          {r.source_key && (
            <Link className="small" to={`/records?domain=${domain}&source=${encodeURIComponent(r.source_key)}`}>
              Show records of this source →
            </Link>
          )}
        </li>
      ))}
    </ul>
  );
}
