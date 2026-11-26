import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Card, Empty, ErrorBox, Loading, Pill } from "../components/ui";
import { useApp } from "../context";
import { date, dateTime } from "../format";

interface FRow { id: number; arrival_date: string | null; reporter: string | null; source_ip: string | null; reported_domain: string | null;
  auth_failure: string | null; delivery_result: string | null; original_from: string | null; original_subject: string | null; expires_at: string }

export function Forensic() {
  const { domain } = useApp();
  const q = useQuery({ queryKey: ["forensic", domain], queryFn: () => api<{ total: number; items: FRow[] }>(`/api/forensic?domain=${domain}`), enabled: !!domain });
  return (
    <>
      <div className="page-head"><h1>Failure reports (RUF)</h1><span className="muted">Contain personal data — admins only, deleted automatically after the retention period</span></div>
      <Card>
        {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No failure reports. Many large providers (Google, Microsoft) no longer send them.</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Arrived</th><th>Source IP</th><th>From</th><th>Subject</th><th>Failure</th><th>Delivery</th><th>Deleted on</th></tr></thead>
            <tbody>{q.data!.items.map((f) => (
              <tr key={f.id}>
                <td><Link to={`/forensic/${f.id}`}>{dateTime(f.arrival_date)}</Link></td>
                <td className="mono">{f.source_ip ? <Link to={`/ips/${f.source_ip}`}>{f.source_ip}</Link> : "–"}</td>
                <td className="break">{f.original_from ?? "–"}</td><td className="break">{f.original_subject ?? "–"}</td>
                <td>{f.auth_failure ?? "–"}</td><td>{f.delivery_result ?? "–"}</td><td>{date(f.expires_at)}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </Card>
    </>
  );
}

interface FDetail extends FRow { feedback_type: string; user_agent: string | null; original_mail_from: string | null; original_rcpt_to: string[];
  authentication_results: string | null; dkim_domain: string | null; dkim_selector: string | null; spf_dns: string | null;
  identity_alignment: string | null; original_to: string | null; original_message_id: string | null; original_date: string | null;
  original_headers: [string, string][]; body_stored: boolean; original_body: string | null }

export function ForensicDetail() {
  const { id } = useParams();
  const q = useQuery({ queryKey: ["forensic", "detail", id], queryFn: () => api<FDetail>(`/api/forensic/${id}`) });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const f = q.data!;
  return (
    <>
      <div className="page-head"><h1>Failure report</h1><Pill tone="warning">personal data</Pill><span className="muted">deleted on {date(f.expires_at)}</span></div>
      <Card title="Report">
        <dl className="kv">
          <dt>Type</dt><dd>{f.feedback_type} · {f.auth_failure ?? "–"}</dd>
          <dt>Reporter</dt><dd>{f.reporter} {f.user_agent && <span className="muted">({f.user_agent})</span>}</dd>
          <dt>Arrival</dt><dd>{dateTime(f.arrival_date)}</dd>
          <dt>Source IP</dt><dd className="mono">{f.source_ip ? <Link to={`/ips/${f.source_ip}`}>{f.source_ip}</Link> : "–"}</dd>
          <dt>Envelope</dt><dd>{f.original_mail_from ?? "–"} → {f.original_rcpt_to.join(", ") || "–"}</dd>
          <dt>Authentication-Results</dt><dd className="mono break">{f.authentication_results ?? "–"}</dd>
          <dt>Delivery result</dt><dd>{f.delivery_result ?? "–"}</dd>
        </dl>
      </Card>
      <Card title="Original message headers">
        <div className="table-wrap"><table><tbody>
          {f.original_headers.map(([k, v], i) => <tr key={i}><th style={{ position: "static" }}>{k}</th><td className="mono break">{v}</td></tr>)}
        </tbody></table></div>
      </Card>
      <Card title="Message body">
        {f.body_stored ? <pre className="mono break" style={{ whiteSpace: "pre-wrap", maxHeight: 400, overflow: "auto" }}>{f.original_body}</pre>
          : <p className="muted">Not stored (privacy default, see DMARC_RUF_STORE_BODY).</p>}
      </Card>
    </>
  );
}
