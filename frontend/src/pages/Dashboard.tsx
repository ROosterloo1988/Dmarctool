import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api";
import { ReadinessCard } from "../components/Readiness";
import { TrendChart } from "../components/TrendChart";
import { Card, Empty, ErrorBox, Kpi, Loading, PctBar, Pill, RecommendationList } from "../components/ui";
import { useApp } from "../context";
import { ago, num, pct } from "../format";
import type { Dashboard as D } from "../types";

const RANGES = [7, 30, 90, 365];

export function Dashboard() {
  const { domain, domains, isAdmin } = useApp();
  const [days, setDays] = useState(30);
  const q = useQuery({
    queryKey: ["dashboard", domain, days],
    queryFn: () => api<D>(`/api/domains/${domain}/dashboard?days=${days}`),
    enabled: !!domain,
  });

  if (!domains.length)
    return (
      <Card title="Welcome">
        <Empty>
          No domains are monitored yet.{" "}
          {isAdmin ? <Link to="/settings">Add tenazenergy.com under Settings.</Link> : "Ask an administrator to add one."}
        </Empty>
      </Card>
    );
  if (q.isPending || !domain) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const d = q.data!;
  const delta = d.totals.dmarc_pass_pct !== null && d.previous.dmarc_pass_pct !== null
    ? d.totals.dmarc_pass_pct - d.previous.dmarc_pass_pct : null;

  return (
    <>
      <div className="page-head">
        <h1>{domain}</h1>
        <span className="spacer" />
        <div className="segmented" role="group" aria-label="Period">
          {RANGES.map((r) => <button key={r} aria-pressed={days === r} onClick={() => setDays(r)}>{r === 365 ? "1 year" : `${r} days`}</button>)}
        </div>
      </div>

      <div className="grid grid-kpi">
        <Kpi label="Messages reported" value={num(d.totals.messages)}
             sub={d.previous.messages ? `${num(d.previous.messages)} in the previous ${days} days` : undefined} />
        <Kpi label="DMARC pass" value={pct(d.totals.dmarc_pass_pct)}
             sub={delta === null ? undefined : `${delta >= 0 ? "▲" : "▼"} ${Math.abs(delta).toFixed(1)} pts vs previous period`} />
        <Kpi label="SPF aligned" value={pct(d.totals.spf_aligned_pct)} />
        <Kpi label="DKIM aligned" value={pct(d.totals.dkim_aligned_pct)} />
        <Kpi label="DNS check" value={d.dns ? (d.dns.errors ? <Pill tone="critical">{d.dns.errors} error(s)</Pill>
               : d.dns.warnings ? <Pill tone="warning">{d.dns.warnings} warning(s)</Pill> : <Pill tone="good">OK</Pill>) : "–"}
             sub={d.dns ? <Link to="/dns">checked {ago(d.dns.checked_at)}</Link> : "not checked yet"} />
      </div>

      <div className="grid grid-2">
        <Card title="Volume and DMARC result per day">
          <TrendChart data={d.trend} />
        </Card>
        <ReadinessCard r={d.readiness} />
      </div>

      <div className="grid grid-2">
        <Card title="What to do" actions={d.recommendation_count > d.recommendations.length &&
              <Link to="/recommendations">All {d.recommendation_count} recommendations →</Link>}>
          <RecommendationList items={d.recommendations} domain={domain} />
        </Card>
        <Card title="Top sending sources" actions={<Link to="/sources">All sources →</Link>}>
          {d.top_sources.length === 0 ? <Empty>No sources yet.</Empty> : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Source</th><th className="num">Messages</th><th>DMARC pass</th></tr></thead>
                <tbody>
                  {d.top_sources.map((s) => (
                    <tr key={s.key}>
                      <td><Link to={`/records?domain=${domain}&source=${encodeURIComponent(s.key)}`}>{s.name || s.key}</Link></td>
                      <td className="num">{num(s.messages)}</td>
                      <td><PctBar value={s.dmarc_pass_pct} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
