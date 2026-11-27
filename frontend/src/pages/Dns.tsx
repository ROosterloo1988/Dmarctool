import { useMutation, useQuery } from "@tanstack/react-query";
import { api, post } from "../api";
import { Card, Empty, ErrorBox, Loading, Pill, PolicyPill, SeverityPill } from "../components/ui";
import { useApp } from "../context";
import { ago, dateTime } from "../format";
import type { Finding } from "../types";

interface SpfTerm { term: string; networks: string[]; child?: SpfNode; unresolvable?: boolean }
interface SpfNode { domain: string; record: string | null; error: string | null; terms: SpfTerm[] }
interface DnsData {
  latest: { checked_at: string; findings: Finding[]; errors: number; warnings: number; result: {
    dmarc: { records: string[]; tags?: Record<string, string>; effective_policy?: string; rua?: string[]; ruf?: string[]; inherited: boolean; policy_domain: string };
    spf: { records: string[]; lookups: number; void_lookups: number; tree: SpfNode | null };
    dkim: { selector: string; name: string; status?: string; bits?: number; key_type?: string }[];
  } } | null;
  history: { checked_at: string; errors: number; warnings: number }[];
}

function Tree({ node }: { node: SpfNode }) {
  return (
    <ul className="tree">
      {node.error && <li><Pill tone="critical">{node.error}</Pill></li>}
      {node.terms.map((t, i) => (
        <li key={i}>
          <span className="mono">{t.term}</span>
          {t.networks.length > 0 && !t.term.startsWith("ip") && <span className="muted small"> → {t.networks.slice(0, 4).join(", ")}{t.networks.length > 4 ? ` +${t.networks.length - 4}` : ""}</span>}
          {t.unresolvable && <span className="muted small"> (not evaluated)</span>}
          {t.child && <Tree node={t.child} />}
        </li>
      ))}
    </ul>
  );
}

const CHECKS = [["dmarc", "DMARC"], ["spf", "SPF"], ["dkim", "DKIM"], ["parked", "Parked domain"]] as const;

export function Dns() {
  const { domain, isAdmin } = useApp();
  const q = useQuery({ queryKey: ["dns", domain], queryFn: () => api<DnsData>(`/api/domains/${domain}/dns`), enabled: !!domain, refetchInterval: 30_000 });
  const run = useMutation({ mutationFn: () => post(`/api/domains/${domain}/dns/check`) });
  if (!domain || q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const l = q.data!.latest;

  return (
    <>
      <div className="page-head">
        <h1>DNS check · {domain}</h1>
        {l && <span className="muted">last checked {ago(l.checked_at)}</span>}
        <span className="spacer" />
        {isAdmin && <button className="btn" onClick={() => run.mutate()} disabled={run.isPending}>{run.isSuccess ? "Queued — refreshes shortly" : "Check now"}</button>}
      </div>
      {!l ? <Card><Empty>Not checked yet. The worker checks every hour.</Empty></Card> : (
        <>
          <div className="grid grid-half">
            <Card title={<>DMARC <PolicyPill policy={l.result.dmarc.effective_policy} /></>}>
              {l.result.dmarc.records.length ? l.result.dmarc.records.map((r, i) => <pre key={i} className="mono break" style={{ whiteSpace: "pre-wrap" }}>{r}</pre>)
                : <p className="muted">No record at _dmarc.{domain}</p>}
              {l.result.dmarc.inherited && <p className="muted small">Inherited from {l.result.dmarc.policy_domain}.</p>}
              {(l.result.dmarc.rua?.length ?? 0) > 0 && <p className="small">Aggregate reports to: {l.result.dmarc.rua!.join(", ")}</p>}
            </Card>
            <Card title={<>SPF <span className="muted small">{l.result.spf.lookups}/10 DNS lookups · {l.result.spf.void_lookups} void</span></>}>
              {l.result.spf.records.map((r, i) => <pre key={i} className="mono break" style={{ whiteSpace: "pre-wrap" }}>{r}</pre>)}
              {l.result.spf.tree ? <Tree node={l.result.spf.tree} /> : !l.result.spf.records.length && <p className="muted">No SPF record.</p>}
            </Card>
          </div>
          <Card title="DKIM selectors seen in reports">
            {l.result.dkim.length === 0 ? <Empty>No selectors seen in the reports of the last 30 days.</Empty> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Record</th><th>Status</th><th>Key</th></tr></thead>
                <tbody>{l.result.dkim.map((k) => (
                  <tr key={k.name}><td className="mono">{k.name}</td>
                    <td>{k.status === "ok" ? <Pill tone="good">ok</Pill> : k.status === "weak" ? <Pill tone="warning">weak</Pill>
                      : k.status === "revoked" ? <Pill tone="neutral">revoked</Pill> : <Pill tone="critical">{k.status ?? "error"}</Pill>}</td>
                    <td>{k.bits ? `${k.bits}-bit ${k.key_type?.toUpperCase()}` : "–"}</td></tr>
                ))}</tbody>
              </table></div>
            )}
          </Card>
          <Card title={`Findings (${l.errors} errors, ${l.warnings} warnings)`}>
            {CHECKS.map(([key, label]) => {
              const fs = l.findings.filter((f) => f.check === key);
              if (!fs.length) return null;
              return (
                <div key={key}>
                  <h3>{label}</h3>
                  <ul className="recs">
                    {fs.map((f, i) => (
                      <li className="rec" key={i}>
                        <div className="rec-head"><SeverityPill severity={f.severity} /><span>{f.message}</span></div>
                        {f.fix && f.severity !== "ok" && <p className="break">→ {f.fix}</p>}
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </Card>
          <Card title="History">
            <div className="tags">{q.data!.history.map((h) => (
              <span key={h.checked_at} className="tag" title={dateTime(h.checked_at)}>{dateTime(h.checked_at)}: {h.errors}E/{h.warnings}W</span>
            ))}</div>
          </Card>
        </>
      )}
    </>
  );
}
