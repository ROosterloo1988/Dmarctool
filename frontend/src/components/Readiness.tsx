import type { Readiness } from "../types";
import { Pill, PolicyPill } from "./ui";

const LABEL = { ready: "Ready for the next step", almost: "Almost ready", not_ready: "Not ready yet" } as const;
const TONE = { ready: "good", almost: "warning", not_ready: "critical" } as const;

export function ReadinessCard({ r }: { r: Readiness }) {
  const done = r.policy === "reject" && r.pct >= 100;
  return (
    <section className={`card ready ready-${r.status}`} aria-label="Ready for p=reject">
      <div className="ready-title">
        <span>Ready for p=reject?</span>
        {done ? <Pill tone="good">enforced</Pill> : <Pill tone={TONE[r.status]}>{LABEL[r.status]}</Pill>}
        <span style={{ marginLeft: "auto" }}><PolicyPill policy={r.policy} />{r.pct < 100 && <span className="muted small"> pct={r.pct}</span>}</span>
      </div>
      {done ? (
        <p className="muted">This domain is protected with p=reject. Keep an eye on new sending sources.</p>
      ) : (
        <ul className="checklist">
          {r.criteria.map((c) => (
            <li key={c.key}>
              <span className={`check ${c.ok ? "check-ok" : "check-no"}`} aria-label={c.ok ? "met" : "not met"}>{c.ok ? "✓" : "✕"}</span>
              <span>{c.text}</span>
            </li>
          ))}
        </ul>
      )}
      {r.next_step && (
        <div className="next-step">
          <strong>{r.next_step.title}.</strong> {r.next_step.text}
          {r.next_step.actions.map((a, i) => <div key={i} className="mono break" style={{ marginTop: 6 }}>{a}</div>)}
        </div>
      )}
      {r.unknown_failing.length > 0 && (
        <p className="small muted" style={{ marginBottom: 0 }}>
          {r.unknown_failing.length} unidentified source(s) fail DMARC and would be blocked by p=reject — check that none of them are yours on the Sending sources page.
        </p>
      )}
    </section>
  );
}
