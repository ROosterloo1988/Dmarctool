import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { api } from "../api";
import { RecordTable } from "../components/RecordTable";
import { Card, ErrorBox, Loading, PctBar, Pill, ResultPill } from "../components/ui";
import { date, dateTime, num } from "../format";
import type { Paged, RecordRow } from "../types";

interface IpData {
  ip: string;
  info: { ptr: string | null; ptr_confirmed: boolean; asn: number | null; as_org: string | null; country: string | null; sender: string | null; updated_at: string } | null;
  domains: { domain: string; messages: number; dmarc_pass_pct: number | null; first_seen: string; last_seen: string; spf_result: string | null }[];
  reporters: { org_name: string; messages: number }[];
}

export function IpDetail() {
  const { ip } = useParams();
  const q = useQuery({ queryKey: ["ip", ip], queryFn: () => api<IpData>(`/api/ips/${ip}`) });
  const recs = useQuery({ queryKey: ["records", "ip", ip], queryFn: () => api<Paged<RecordRow>>(`/api/records?ip=${ip}&page_size=100`) });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const d = q.data!;
  return (
    <>
      <div className="page-head"><h1 className="mono">{d.ip}</h1>{d.info?.sender && <Pill tone="info">{d.info.sender}</Pill>}</div>
      <div className="grid grid-half">
        <Card title="About this IP">
          {d.info ? (
            <dl className="kv">
              <dt>Reverse DNS</dt><dd>{d.info.ptr ?? "–"} {d.info.ptr && (d.info.ptr_confirmed ? <Pill tone="good">forward-confirmed</Pill> : <Pill tone="warning">not confirmed</Pill>)}</dd>
              <dt>Network</dt><dd>{d.info.asn ? `AS${d.info.asn} ${d.info.as_org ?? ""}` : "–"}</dd>
              <dt>Country</dt><dd>{d.info.country ?? "–"}</dd>
              <dt>Recognised as</dt><dd>{d.info.sender ?? "not a known sender"}</dd>
              <dt>Looked up</dt><dd>{dateTime(d.info.updated_at)}</dd>
            </dl>
          ) : <p className="muted">Not enriched yet (runs every 15 minutes).</p>}
        </Card>
        <Card title="Seen for">
          <div className="table-wrap">
            <table>
              <thead><tr><th>Domain</th><th className="num">Messages</th><th>DMARC pass</th><th>In our SPF?</th><th>Seen</th></tr></thead>
              <tbody>{d.domains.map((x) => (
                <tr key={x.domain}><td>{x.domain}</td><td className="num">{num(x.messages)}</td><td><PctBar value={x.dmarc_pass_pct} /></td>
                  <td>{x.spf_result ? <ResultPill result={x.spf_result} /> : "–"}</td><td className="small">{date(x.first_seen)} – {date(x.last_seen)}</td></tr>
              ))}</tbody>
            </table>
          </div>
          <p className="muted small">"In our SPF?" evaluates this IP against the current SPF record of the domain (offline, from the last DNS check).</p>
          <h3>Reported by</h3>
          <div className="tags">{d.reporters.map((r) => <span className="tag" key={r.org_name}>{r.org_name} · {num(r.messages)}</span>)}</div>
        </Card>
      </div>
      <Card title="Records from this IP">
        {recs.isPending ? <Loading /> : recs.isError ? <ErrorBox error={recs.error} /> : <RecordTable items={recs.data!.items} />}
      </Card>
    </>
  );
}
