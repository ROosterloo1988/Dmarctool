import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, qs } from "../api";
import { Card, Empty, ErrorBox, Loading, Pill, ResultPill } from "../components/ui";
import { useApp } from "../context";
import { date, dateTime } from "../format";

interface FRow {
  id: number; arrival_date: string | null; reporter: string | null; source_ip: string | null; as_org: string | null;
  reported_domain: string | null; auth_failure: string | null; delivery_result: string | null; original_from: string | null;
  original_subject: string | null; body_stored: boolean; expires_at: string;
}
interface Campaign {
  source_ip: string | null; subject: string; reports: number; first_seen: string | null; last_seen: string | null;
  reporters: number; latest_id: number; from_example: string | null; as_org: string | null; country: string | null; ptr: string | null;
}

export function Forensic() {
  const { domain } = useApp();
  const [sp, setSp] = useSearchParams();
  const view = sp.get("view") ?? "campaigns";
  const ip = sp.get("ip") ?? "";
  const source = sp.get("source") ?? "";
  const [search, setSearch] = useState(sp.get("q") ?? "");
  const listQuery = qs({ domain, ip, source, q: sp.get("q") });
  const list = useQuery({ queryKey: ["forensic", listQuery], queryFn: () => api<{ total: number; items: FRow[] }>(`/api/forensic${listQuery}`),
                          enabled: !!domain && (view === "all" || !!ip || !!source) });
  const camps = useQuery({ queryKey: ["forensic-campaigns", domain], queryFn: () => api<Campaign[]>(`/api/forensic/campaigns?domain=${domain}`),
                           enabled: !!domain && view === "campaigns" && !ip && !source });
  const set = (k: string, v: string) => { const n = new URLSearchParams(sp); if (v) n.set(k, v); else n.delete(k); setSp(n); };
  const filtered = !!ip || !!source;

  return (
    <>
      <div className="page-head">
        <h1>Failure reports (RUF)</h1>
        <span className="muted">Personal data — admins only, deleted automatically after the retention period</span>
      </div>
      <Card>
        <div className="filters" style={{ marginBottom: 12 }}>
          {!filtered && (
            <div className="segmented" role="group" aria-label="View">
              <button aria-pressed={view === "campaigns"} onClick={() => set("view", "")}>Campaigns</button>
              <button aria-pressed={view === "all"} onClick={() => set("view", "all")}>All reports</button>
            </div>
          )}
          {view === "all" && !filtered && (
            <form className="row" onSubmit={(e) => { e.preventDefault(); set("q", search); }}>
              <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Subject or sender" />
              <button className="btn" type="submit">Search</button>
            </form>
          )}
          {ip && <span className="row">IP <span className="tag mono">{ip}</span><button className="btn btn-ghost" onClick={() => set("ip", "")}>✕</button></span>}
          {source && <span className="row">Source <span className="tag mono">{source}</span><button className="btn btn-ghost" onClick={() => set("source", "")}>✕</button></span>}
        </div>

        {view === "campaigns" && !filtered ? (
          camps.isPending ? <Loading /> : camps.isError ? <ErrorBox error={camps.error} /> : camps.data!.length === 0 ? <NoReports /> : (
            <>
              <p className="muted small" style={{ marginTop: 0 }}>Reports grouped by sending IP and subject, so a spoofing campaign shows as one line.</p>
              <div className="table-wrap"><table>
                <thead><tr><th>Subject</th><th>Sending IP</th><th className="num">Reports</th><th>Period</th><th className="num">Reporters</th><th /></tr></thead>
                <tbody>{camps.data!.map((c, i) => (
                  <tr key={i}>
                    <td className="break"><strong>{c.subject}</strong>{c.from_example && <div className="muted small">From: {c.from_example}</div>}</td>
                    <td>{c.source_ip ? <Link className="mono" to={`/ips/${c.source_ip}`}>{c.source_ip}</Link> : "–"}
                      {(c.as_org || c.country) && <div className="muted small">{[c.as_org, c.country].filter(Boolean).join(" · ")}</div>}</td>
                    <td className="num">{c.reports}</td>
                    <td className="small">{date(c.first_seen)}{c.last_seen && c.last_seen !== c.first_seen ? ` – ${date(c.last_seen)}` : ""}</td>
                    <td className="num">{c.reporters}</td>
                    <td><div className="row"><Link to={`/forensic/${c.latest_id}`}>Latest →</Link>
                      {c.source_ip && c.reports > 1 && <Link to={`/forensic?ip=${c.source_ip}`}>All {c.reports}</Link>}</div></td>
                  </tr>
                ))}</tbody>
              </table></div>
            </>
          )
        ) : list.isPending ? <Loading /> : list.isError ? <ErrorBox error={list.error} /> : list.data!.items.length === 0 ? <NoReports /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Arrived</th><th>Source IP</th><th>From</th><th>Subject</th><th>Failure</th><th>Delivery</th><th>Deleted on</th></tr></thead>
            <tbody>{list.data!.items.map((f) => (
              <tr key={f.id}>
                <td><Link to={`/forensic/${f.id}`}>{dateTime(f.arrival_date)}</Link></td>
                <td className="mono">{f.source_ip ? <Link to={`/ips/${f.source_ip}`}>{f.source_ip}</Link> : "–"}{f.as_org && <div className="muted small" style={{ fontFamily: "inherit" }}>{f.as_org}</div>}</td>
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

function NoReports() {
  return (
    <Empty>
      No failure reports. Request them with <span className="mono">ruf=mailto:…; fo=1</span> in the DMARC record — note that
      Google, Microsoft and Yahoo do not send them.
    </Empty>
  );
}

interface Hop { from: string | null; helo: string | null; ip: string | null; by: string | null; with: string | null; date: string | null;
  raw: string; private?: boolean; ptr?: string | null; asn?: number | null; as_org?: string | null; country?: string | null }
interface Analysis {
  auth: { authserv_id: string | null; results: { method: string; result: string; props: Record<string, string> }[] }[];
  auth_summary: Record<string, string>;
  dkim_signatures: Record<string, string>[];
  hops: Hop[];
  anomalies: { severity: "critical" | "warning" | "info"; code: string; text: string }[];
  body: null | { text: string; text_truncated: boolean; urls: { url: string; domain: string | null }[]; url_count: number;
    link_domains: Record<string, number>; attachments: { filename: string | null; content_type: string; size: number; sha256: string | null }[] };
}
interface FDetail extends FRow {
  feedback_type: string; user_agent: string | null; original_mail_from: string | null; original_rcpt_to: string[];
  authentication_results: string | null; dkim_domain: string | null; dkim_selector: string | null; spf_dns: string | null;
  identity_alignment: string | null; original_to: string | null; original_message_id: string | null; original_date: string | null;
  original_headers: [string, string][]; analysis: Analysis; reports_from_same_ip: number;
}

const kb = (n: number) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);

export function ForensicDetail() {
  const { id } = useParams();
  const [showHeaders, setShowHeaders] = useState(false);
  const q = useQuery({ queryKey: ["forensic", "detail", id], queryFn: () => api<FDetail>(`/api/forensic/${id}`) });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const f = q.data!;
  const a = f.analysis;
  return (
    <>
      <div className="page-head">
        <h1 className="break">{f.original_subject ?? "Failure report"}</h1>
        <Pill tone="warning">personal data</Pill>
        <span className="muted">deleted on {date(f.expires_at)}</span>
        <span className="spacer" />
        <a className="btn" href={`/api/forensic/${f.id}/export.eml`} title="Recipient addresses are replaced by redacted@domain">Export .eml (anonymised)</a>
        {f.body_stored && <a className="btn btn-ghost" href={`/api/forensic/${f.id}/export.eml?include_body=true`}>…with body</a>}
      </div>

      <div className="grid grid-half">
        <Card title="Verdict of the receiver">
          <div className="row" style={{ marginBottom: 10 }}>
            {["dmarc", "spf", "dkim"].map((k) => a.auth_summary[k] && <span key={k} className="row"><strong>{k.toUpperCase()}</strong> <ResultPill result={a.auth_summary[k]} /></span>)}
          </div>
          <dl className="kv">
            <dt>Reported by</dt><dd>{f.reporter} {f.user_agent && <span className="muted">({f.user_agent})</span>}</dd>
            <dt>Arrived</dt><dd>{dateTime(f.arrival_date)} · {f.delivery_result ?? "delivery unknown"}</dd>
            <dt>Sending IP</dt><dd>{f.source_ip ? <Link className="mono" to={`/ips/${f.source_ip}`}>{f.source_ip}</Link> : "–"}
              {f.reports_from_same_ip > 1 && <> · <Link to={`/forensic?ip=${f.source_ip}`}>{f.reports_from_same_ip} reports from this IP</Link></>}</dd>
            <dt>Envelope</dt><dd className="break">{f.original_mail_from ?? "–"} → {f.original_rcpt_to.join(", ") || "–"}</dd>
            <dt>From header</dt><dd className="break">{f.original_from ?? "–"}</dd>
            {a.dkim_signatures.length > 0 && <><dt>DKIM signatures</dt><dd>{a.dkim_signatures.map((d, i) => <div key={i} className="mono">d={d.d} s={d.s} {d.a && <span className="muted">({d.a})</span>}</div>)}</dd></>}
            {a.auth.flatMap((x) => x.results).filter((r) => Object.keys(r.props).length).length > 0 && <>
              <dt>Details</dt>
              <dd>{a.auth.flatMap((x, i) => x.results.map((r, j) => (
                <div key={`${i}-${j}`} className="small"><strong>{r.method}</strong>={r.result} <span className="mono">{Object.entries(r.props).map(([k, v]) => `${k}=${v}`).join(" ")}</span>
                  {x.authserv_id && <span className="muted"> · {x.authserv_id}</span>}</div>)))}</dd>
            </>}
          </dl>
        </Card>
        <Card title="What stands out">
          {a.anomalies.length === 0 ? <p className="muted">Nothing unusual in the headers.</p> : (
            <ul className="recs">
              {a.anomalies.map((x, i) => (
                <li key={i} className="rec"><div className="rec-head">
                  <Pill tone={x.severity === "critical" ? "critical" : x.severity === "warning" ? "warning" : "info"}>{x.severity === "critical" ? "suspicious" : x.severity}</Pill>
                  <span>{x.text}</span></div></li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card title={`Route of the message (${a.hops.length} hops)`}>
        {a.hops.length === 0 ? <p className="muted">No Received headers in the report.</p> : (
          <div className="table-wrap"><table>
            <thead><tr><th>#</th><th>From</th><th>IP</th><th>Network</th><th>Received by</th><th>Time</th></tr></thead>
            <tbody>{a.hops.map((h, i) => (
              <tr key={i} title={h.raw}>
                <td>{i + 1}</td>
                <td className="break">{h.from ?? "–"}{h.helo && <div className="muted small">HELO {h.helo}</div>}</td>
                <td className="mono">{h.ip ? (h.private ? <>{h.ip} <span className="muted small">(internal)</span></> : <Link to={`/ips/${h.ip}`}>{h.ip}</Link>) : "–"}
                  {h.ptr && <div className="muted small">{h.ptr}</div>}</td>
                <td>{h.as_org ? `${h.as_org}${h.asn ? ` (AS${h.asn})` : ""}` : "–"}{h.country && <span className="muted"> · {h.country}</span>}</td>
                <td className="break">{h.by ?? "–"} {h.with && <span className="muted small">({h.with})</span>}</td>
                <td className="small">{h.date ?? "–"}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
        <p className="muted small" style={{ marginBottom: 0 }}>Oldest hop first. The first public IP is normally the real sending server; headers above it can be forged by the sender.</p>
      </Card>

      {a.body ? (
        <div className="grid grid-half">
          <Card title={`Links (${a.body.url_count})`}>
            {a.body.urls.length === 0 ? <p className="muted">No links.</p> : (
              <>
                <div className="tags" style={{ marginBottom: 10 }}>{Object.entries(a.body.link_domains).map(([d, n]) => <span className="tag" key={d}>{d} · {n}</span>)}</div>
                <ul className="small" style={{ paddingLeft: 18, margin: 0 }}>{a.body.urls.map((u, i) => <li key={i} className="mono break">{u.url}</li>)}</ul>
                <p className="muted small">Links are made non-clickable ("hxxps", "[.]") and are never opened by the portal.</p>
              </>
            )}
            <h3>Attachments ({a.body.attachments.length})</h3>
            {a.body.attachments.length === 0 ? <p className="muted">None.</p> : (
              <div className="table-wrap"><table>
                <thead><tr><th>Name</th><th>Type</th><th className="num">Size</th><th>SHA-256</th></tr></thead>
                <tbody>{a.body.attachments.map((x, i) => (
                  <tr key={i}><td className="break">{x.filename ?? "(no name)"}</td><td>{x.content_type}</td><td className="num">{kb(x.size)}</td>
                    <td className="mono small break">{x.sha256 ?? "–"}</td></tr>
                ))}</tbody>
              </table></div>
            )}
            <p className="muted small">Attachments are never opened; the hash can be checked in a malware scanner.</p>
          </Card>
          <Card title="Message text">
            <pre className="break" style={{ whiteSpace: "pre-wrap", maxHeight: 420, overflow: "auto", margin: 0, fontFamily: "inherit" }}>{a.body.text || "(empty)"}</pre>
            {a.body.text_truncated && <p className="muted small">Truncated.</p>}
            <p className="muted small">Shown as plain text; HTML and scripts are never rendered.</p>
          </Card>
        </div>
      ) : (
        <Card title="Message body"><p className="muted" style={{ margin: 0 }}>Not stored for this report — the reporter sent only headers, or body storage was off when it arrived.</p></Card>
      )}

      <Card title="All original headers" actions={<button className="btn btn-ghost" onClick={() => setShowHeaders(!showHeaders)}>{showHeaders ? "Hide" : `Show (${f.original_headers.length})`}</button>}>
        {showHeaders && (
          <div className="table-wrap"><table><tbody>
            {f.original_headers.map(([k, v], i) => <tr key={i}><th style={{ position: "static" }}>{k}</th><td className="mono break">{v}</td></tr>)}
          </tbody></table></div>
        )}
      </Card>
    </>
  );
}
