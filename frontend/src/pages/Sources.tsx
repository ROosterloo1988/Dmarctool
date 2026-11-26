import { Fragment, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, put, qs } from "../api";
import { Card, Empty, ErrorBox, Loading, PctBar, StatusPill } from "../components/ui";
import { useApp } from "../context";
import { num } from "../format";
import type { Source, SourceStatus } from "../types";

type Filter = "all" | "failing" | "unclassified" | "legit" | "abuse";

function Classify({ domain, s }: { domain: string; s: Source }) {
  const qc = useQueryClient();
  const [note, setNote] = useState(s.note ?? "");
  const m = useMutation({
    mutationFn: (status: SourceStatus) => put(`/api/domains/${domain}/sources/${encodeURIComponent(s.key)}/classification`, { status, note: note || null }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sources", domain] });
      qc.invalidateQueries({ queryKey: ["dashboard", domain] });
    },
  });
  return (
    <div className="stack">
      <label className="field">Note (optional)<input value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} placeholder="e.g. invoices via Flowmailer, owner: Finance" /></label>
      <div className="row">
        <span className="muted small">Mark as:</span>
        <button className="btn" onClick={() => m.mutate("legit")} disabled={m.isPending}>Legitimate</button>
        <button className="btn" onClick={() => m.mutate("unknown")} disabled={m.isPending}>Unknown</button>
        <button className="btn btn-danger" onClick={() => m.mutate("abuse")} disabled={m.isPending}>Abuse</button>
        {s.status && <button className="btn btn-ghost" onClick={() => m.mutate(null)} disabled={m.isPending}>Clear</button>}
      </div>
      {m.isError && <ErrorBox error={m.error} />}
      {s.classified_by && <span className="muted small">Last classified by {s.classified_by}</span>}
    </div>
  );
}

function Detail({ domain, s, isAdmin }: { domain: string; s: Source; isAdmin: boolean }) {
  const list = (o: Record<string, number>) => Object.keys(o).length
    ? <div className="tags">{Object.entries(o).map(([k, v]) => <span className="tag" key={k}>{k} · {num(v)}</span>)}</div> : <span className="muted">–</span>;
  return (
    <div className="grid grid-half">
      <dl className="kv">
        <dt>Source key</dt><dd className="mono">{s.key}</dd>
        <dt>Category</dt><dd>{s.category ?? "–"}</dd>
        <dt>Network</dt><dd>{s.asns.join(", ") || "–"} {s.countries.length > 0 && <span className="muted">({s.countries.join(", ")})</span>}</dd>
        <dt>SPF pass / aligned</dt><dd>{s.spf_pass_pct}% / {s.spf_aligned_pct}%</dd>
        <dt>DKIM pass / aligned</dt><dd>{s.dkim_pass_pct}% / {s.dkim_aligned_pct}%</dd>
        <dt>Envelope (SPF) domains</dt><dd>{list(s.envelope_domains)}</dd>
        <dt>DKIM domains</dt><dd>{list(s.dkim_domains)}</dd>
        <dt>DKIM selectors</dt><dd>{list(s.selectors)}</dd>
        <dt>IP addresses ({s.ip_count})</dt>
        <dd><div className="tags">{s.ips.map((ip) => <Link className="tag mono" key={ip} to={`/ips/${ip}`}>{ip}</Link>)}</div></dd>
      </dl>
      <div className="stack">
        <Link to={`/records${qs({ domain, source: s.key })}`}>Show all records of this source →</Link>
        {isAdmin && s.ruf_count > 0 && <Link to={`/forensic${qs({ source: s.key })}`}>{s.ruf_count} failure report(s) from this source →</Link>}
        {isAdmin ? <Classify domain={domain} s={s} /> : s.note && <p><strong>Note:</strong> {s.note}</p>}
      </div>
    </div>
  );
}

export function Sources() {
  const { domain, isAdmin } = useApp();
  const [days, setDays] = useState(30);
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["sources", domain, days], queryFn: () => api<Source[]>(`/api/domains/${domain}/sources?days=${days}`), enabled: !!domain });

  const rows = useMemo(() => (q.data ?? []).filter((s) => {
    if (search && !`${s.name} ${s.key} ${s.ips.join(" ")} ${s.asns.join(" ")}`.toLowerCase().includes(search.toLowerCase())) return false;
    if (filter === "failing") return s.failing > 0;
    if (filter === "unclassified") return s.status === null;
    if (filter === "legit") return s.status === "legit";
    if (filter === "abuse") return s.status === "abuse";
    return true;
  }), [q.data, filter, search]);

  if (!domain || q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} />;
  const total = (q.data ?? []).reduce((a, s) => a + s.messages, 0);

  return (
    <>
      <div className="page-head">
        <h1>Sending sources</h1>
        <span className="muted">Who sends mail as {domain}, grouped by provider / network</span>
        <span className="spacer" />
        <a className="btn" href={`/api/domains/${domain}/sources.csv?days=${days}`}>Export CSV</a>
      </div>
      <Card>
        <div className="filters" style={{ marginBottom: 12 }}>
          <label className="field">Period
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
              {[7, 30, 90, 365].map((d) => <option key={d} value={d}>Last {d} days</option>)}
            </select>
          </label>
          <label className="field">Show
            <select value={filter} onChange={(e) => setFilter(e.target.value as Filter)}>
              <option value="all">All sources</option><option value="failing">With DMARC failures</option>
              <option value="unclassified">Not yet classified</option><option value="legit">Legitimate</option><option value="abuse">Abuse</option>
            </select>
          </label>
          <label className="field">Search<input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Name, IP or ASN" /></label>
        </div>
        {rows.length === 0 ? <Empty>No sources match.</Empty> : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Source</th><th>Status</th><th className="num">Messages</th><th className="num">Share</th><th>DMARC pass</th>
                  <th>SPF aligned</th><th>DKIM aligned</th><th className="num">IPs</th></tr>
              </thead>
              <tbody>
                {rows.map((s) => (
                  <Fragment key={s.key}>
                    <tr className={`clickable ${open === s.key ? "expanded" : ""}`} onClick={() => setOpen(open === s.key ? null : s.key)}
                        aria-expanded={open === s.key}>
                      <td><strong>{s.name}</strong>{s.note && <div className="muted small">{s.note}</div>}</td>
                      <td><StatusPill status={s.status} recognised={s.recognised} /></td>
                      <td className="num">{num(s.messages)}</td>
                      <td className="num">{total ? `${((100 * s.messages) / total).toFixed(1)}%` : "–"}</td>
                      <td><PctBar value={s.dmarc_pass_pct} /></td>
                      <td><PctBar value={s.spf_aligned_pct} /></td>
                      <td><PctBar value={s.dkim_aligned_pct} /></td>
                      <td className="num">{s.ip_count}</td>
                    </tr>
                    {open === s.key && <tr className="detail-row"><td colSpan={8}><Detail domain={domain} s={s} isAdmin={isAdmin} /></td></tr>}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
