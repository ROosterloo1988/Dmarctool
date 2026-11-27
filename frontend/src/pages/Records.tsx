import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, qs } from "../api";
import { RecordTable } from "../components/RecordTable";
import { Card, Empty, ErrorBox, Loading, Pager } from "../components/ui";
import { useApp } from "../context";
import { num } from "../format";
import type { Paged, RecordRow } from "../types";

const KEYS = ["domain", "from", "to", "reporter", "result", "source", "ip", "disposition"] as const;

export function Records() {
  const { domain: current, domains } = useApp();
  const [sp, setSp] = useSearchParams();
  const f: Record<string, string> = {};
  for (const k of KEYS) f[k] = sp.get(k) ?? "";
  if (!sp.has("domain") && current) f.domain = current;
  const page = Number(sp.get("page") ?? 1);

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(sp);
    if (!sp.has("domain") && current) next.set("domain", current);
    if (v) next.set(k, v); else next.delete(k);
    next.delete("page");
    setSp(next);
  };

  const reporters = useQuery({ queryKey: ["reporters", f.domain], queryFn: () => api<{ org_name: string }[]>(`/api/reporters${qs({ domain: f.domain })}`) });
  const query = qs({ ...f, page, page_size: 50 });
  const q = useQuery({ queryKey: ["records", query], queryFn: () => api<Paged<RecordRow> & { messages: number }>(`/api/records${query}`) });

  return (
    <>
      <div className="page-head">
        <h1>Records</h1>
        <span className="muted">One row per source IP per report</span>
        <span className="spacer" />
        <a className="btn" href={`/api/records.csv${qs(f)}`}>Export CSV</a>
      </div>
      <Card>
        <div className="filters" style={{ marginBottom: 12 }}>
          <label className="field">Domain
            <select value={f.domain} onChange={(e) => set("domain", e.target.value)}>
              <option value="">All</option>{domains.map((d) => <option key={d.name}>{d.name}</option>)}
            </select>
          </label>
          <label className="field">From<input type="date" value={f.from} onChange={(e) => set("from", e.target.value)} /></label>
          <label className="field">To<input type="date" value={f.to} onChange={(e) => set("to", e.target.value)} /></label>
          <label className="field">Reporter
            <select value={f.reporter} onChange={(e) => set("reporter", e.target.value)}>
              <option value="">All</option>{reporters.data?.map((r) => <option key={r.org_name}>{r.org_name}</option>)}
            </select>
          </label>
          <label className="field">Result
            <select value={f.result} onChange={(e) => set("result", e.target.value)}>
              <option value="">All</option><option value="pass">DMARC pass</option><option value="fail">DMARC fail</option>
              <option value="spf_unaligned">SPF not aligned</option><option value="dkim_unaligned">DKIM not aligned</option>
            </select>
          </label>
          <label className="field">Disposition
            <select value={f.disposition} onChange={(e) => set("disposition", e.target.value)}>
              <option value="">All</option><option>none</option><option>quarantine</option><option>reject</option>
            </select>
          </label>
          <label className="field">Source IP<input value={f.ip} onChange={(e) => set("ip", e.target.value.trim())} placeholder="e.g. 40.107.22.105" /></label>
          {f.source && <label className="field">Source<span className="row"><span className="tag mono">{f.source}</span><button className="btn btn-ghost" onClick={() => set("source", "")}>✕</button></span></label>}
        </div>
        {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : q.data!.items.length === 0 ? <Empty>No records match these filters.</Empty> : (
          <>
            <p className="muted small" style={{ marginTop: 0 }}>{num(q.data!.messages)} messages in {num(q.data!.total)} records</p>
            <RecordTable items={q.data!.items} />
            <Pager page={page} pageSize={50} total={q.data!.total} onPage={(p) => { const n = new URLSearchParams(sp); n.set("page", String(p)); setSp(n); }} />
          </>
        )}
      </Card>
    </>
  );
}
