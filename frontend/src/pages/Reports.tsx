import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, qs } from "../api";
import { RecordTable } from "../components/RecordTable";
import { Card, Empty, ErrorBox, Loading, Pager, PctBar, Pill } from "../components/ui";
import { useApp } from "../context";
import { date, dateTime, num } from "../format";
import type { Paged, RecordRow, ReportRow } from "../types";

export function Reports() {
  const { domain } = useApp();
  const [sp, setSp] = useSearchParams();
  const reporter = sp.get("reporter") ?? "";
  const page = Number(sp.get("page") ?? 1);
  const reporters = useQuery({ queryKey: ["reporters", domain], queryFn: () => api<{ org_name: string; reports: number }[]>(`/api/reporters${qs({ domain })}`), enabled: !!domain });
  const query = qs({ domain, reporter, page, page_size: 50 });
  const q = useQuery({ queryKey: ["reports", query], queryFn: () => api<Paged<ReportRow>>(`/api/reports${query}`), enabled: !!domain });

  return (
    <>
      <div className="page-head"><h1>Aggregate reports</h1><span className="muted">for {domain}</span></div>
      <Card>
        <div className="filters" style={{ marginBottom: 12 }}>
          <label className="field">Reporter
            <select value={reporter} onChange={(e) => setSp(e.target.value ? { reporter: e.target.value } : {})}>
              <option value="">All reporters</option>
              {reporters.data?.map((r) => <option key={r.org_name} value={r.org_name}>{r.org_name} ({r.reports})</option>)}
            </select>
          </label>
        </div>
        {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No reports yet.</Empty> : (
          <>
            <div className="table-wrap">
              <table>
                <thead><tr><th>Period</th><th>Reporter</th><th>Report ID</th><th className="num">Messages</th><th>DMARC pass</th><th className="num">Records</th><th>Policy</th></tr></thead>
                <tbody>
                  {q.data!.items.map((r) => (
                    <tr key={r.id}>
                      <td>{date(r.date_begin)}</td>
                      <td>{r.org_name}</td>
                      <td className="mono break"><Link to={`/reports/${r.id}`}>{r.report_id}</Link></td>
                      <td className="num">{num(r.messages)}</td>
                      <td><PctBar value={r.dmarc_pass_pct} /></td>
                      <td className="num">{r.records}</td>
                      <td>{r.policy ? `p=${r.policy}` : "–"} {r.errors.length > 0 && <Pill tone="warning">reporter errors</Pill>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={page} pageSize={50} total={q.data!.total} onPage={(p) => setSp({ ...(reporter ? { reporter } : {}), page: String(p) })} />
          </>
        )}
      </Card>
    </>
  );
}

interface ReportDetailData {
  id: number; org_name: string; report_id: string; domain: string; email: string | null; extra_contact_info: string | null;
  date_begin: string; date_end: string; version: string | null; generator: string | null; errors: string[]; messages: number;
  policy: Record<string, string | number | null>; has_xml: boolean; created_at: string;
  inbound: { id: number; subject: string | null; received_at: string | null; moved_to: string | null } | null;
}

export function ReportDetail() {
  const { id } = useParams();
  const q = useQuery({ queryKey: ["report", id], queryFn: () => api<ReportDetailData>(`/api/reports/${id}`) });
  const recs = useQuery({ queryKey: ["records", "report", id], queryFn: () => api<Paged<RecordRow>>(`/api/records?report=${id}&page_size=500`) });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const r = q.data!;
  const policy = Object.entries(r.policy).filter(([, v]) => v !== null).map(([k, v]) => `${k}=${v}`).join("; ");
  return (
    <>
      <div className="page-head">
        <h1>Report from {r.org_name}</h1>
        <span className="spacer" />
        {r.has_xml && <a className="btn" href={`/api/reports/${r.id}/xml`}>Download XML</a>}
      </div>
      <Card>
        <dl className="kv">
          <dt>Report ID</dt><dd className="mono">{r.report_id}</dd>
          <dt>Domain</dt><dd>{r.domain}</dd>
          <dt>Period</dt><dd>{dateTime(r.date_begin)} – {dateTime(r.date_end)} (UTC)</dd>
          <dt>Messages</dt><dd>{num(r.messages)}</dd>
          <dt>Published policy</dt><dd className="mono">{policy}</dd>
          <dt>Reporter contact</dt><dd>{r.email ?? "–"} {r.extra_contact_info && <span className="muted">· {r.extra_contact_info}</span>}</dd>
          {r.generator && <><dt>Generator</dt><dd>{r.generator}</dd></>}
          {r.errors.length > 0 && <><dt>Reporter errors</dt><dd>{r.errors.join("; ")}</dd></>}
          <dt>Received</dt><dd>{r.inbound ? `${r.inbound.subject ?? ""} · ${dateTime(r.inbound.received_at)}${r.inbound.moved_to ? ` · moved to ${r.inbound.moved_to}` : ""}` : "imported from file"}</dd>
        </dl>
      </Card>
      <Card title="Records">
        {recs.isPending ? <Loading /> : recs.isError ? <ErrorBox error={recs.error} /> : <RecordTable items={recs.data!.items} showReport={false} />}
      </Card>
    </>
  );
}
