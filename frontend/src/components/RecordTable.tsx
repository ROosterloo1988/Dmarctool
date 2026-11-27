import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { date, num } from "../format";
import type { RecordRow } from "../types";
import { PassPill, ResultPill } from "./ui";

export function RecordTable({ items, showReport = true }: { items: RecordRow[]; showReport?: boolean }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {showReport && <th>Period</th>}{showReport && <th>Reporter</th>}
            <th>Source IP</th><th>Source</th><th className="num">Count</th><th>DMARC</th><th>SPF</th><th>DKIM</th><th>Disposition</th>
          </tr>
        </thead>
        <tbody>
          {items.map((r) => {
            const spf = r.auth.filter((a) => a.method === "spf");
            const dkim = r.auth.filter((a) => a.method === "dkim");
            return (
              <Fragment key={r.id}>
                <tr className={`clickable ${open === r.id ? "expanded" : ""}`} onClick={() => setOpen(open === r.id ? null : r.id)}>
                  {showReport && <td>{date(r.report.date_begin)}</td>}
                  {showReport && <td><Link to={`/reports/${r.report.id}`} onClick={(e) => e.stopPropagation()}>{r.report.org_name}</Link></td>}
                  <td className="mono"><Link to={`/ips/${r.source_ip}`} onClick={(e) => e.stopPropagation()}>{r.source_ip}</Link>
                    {r.ptr && <div className="muted small break" title={r.ptr_confirmed ? "forward-confirmed reverse DNS" : "reverse DNS does not resolve back to this IP: not trustworthy"}>{r.ptr}{!r.ptr_confirmed && " (unverified)"}</div>}</td>
                  <td>{r.source_name}{r.country && <span className="muted small"> · {r.country}</span>}</td>
                  <td className="num">{num(r.count)}</td>
                  <td><PassPill ok={r.dmarc_pass} /></td>
                  <td><PassPill ok={r.spf_aligned} yes="aligned" no={spf.some((a) => a.result === "pass") ? "not aligned" : "fail"} /></td>
                  <td><PassPill ok={r.dkim_aligned} yes="aligned" no={dkim.some((a) => a.result === "pass") ? "not aligned" : dkim.length ? "fail" : "none"} /></td>
                  <td>{r.disposition ?? "–"}</td>
                </tr>
                {open === r.id && (
                  <tr className="detail-row">
                    <td colSpan={showReport ? 9 : 7}>
                      <dl className="kv">
                        <dt>Header From</dt><dd>{r.header_from ?? "–"}</dd>
                        <dt>Envelope From</dt><dd>{r.envelope_from ?? "–"}</dd>
                        {r.envelope_to && <><dt>Envelope To</dt><dd>{r.envelope_to}</dd></>}
                        <dt>Network</dt><dd>{r.asn ? `AS${r.asn} ${r.as_org ?? ""}` : "–"}</dd>
                        <dt>SPF results</dt>
                        <dd>{spf.length ? spf.map((a, i) => <div key={i}>{a.domain ?? "?"} {a.scope && <span className="muted">({a.scope})</span>} <ResultPill result={a.result} /> {a.result === "pass" && !a.aligned && <span className="muted small">not aligned</span>}</div>) : "–"}</dd>
                        <dt>DKIM results</dt>
                        <dd>{dkim.length ? dkim.map((a, i) => <div key={i}>{a.domain ?? "?"} <span className="muted">selector {a.selector ?? "?"}</span> <ResultPill result={a.result} /> {a.result === "pass" && !a.aligned && <span className="muted small">not aligned</span>}</div>) : "–"}</dd>
                        {r.reasons.length > 0 && <><dt>Override reason</dt><dd>{r.reasons.map((x) => `${x.type}${x.comment ? ` (${x.comment})` : ""}`).join(", ")}</dd></>}
                        <dt>Report</dt><dd><Link to={`/reports/${r.report.id}`}>{r.report.org_name} · {r.report.report_id}</Link></dd>
                      </dl>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
