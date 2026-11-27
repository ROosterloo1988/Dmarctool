import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, post, qs } from "../api";
import { Card, Empty, ErrorBox, Loading, Pager, Pill } from "../components/ui";
import { useApp } from "../context";
import { ago, dateTime, num } from "../format";

interface Inbound { id: number; source: string; subject: string | null; sender: string | null; received_at: string | null; processed_at: string;
  kind: string; status: string; reports_new: number; reports_duplicate: number; errors: string[]; moved_to: string | null;
  move_error: string | null; report_ids: number[] }
interface Job { id: number; job: string; status: string; requested_by: string | null; created_at: string; started_at: string | null;
  finished_at: string | null; stats: Record<string, unknown>; error: string | null }

const STATUS_TONE: Record<string, "good" | "neutral" | "warning" | "critical" | "info"> =
  { processed: "good", duplicate: "neutral", partial: "warning", failed: "critical", ok: "good", error: "critical", skipped: "warning", queued: "info", running: "info" };
const JOB_LABEL: Record<string, string> = { fetch: "Fetch mail", enrich: "Enrich IPs & statistics", dnscheck: "DNS check", geoip: "Update IP database", purge: "Retention clean-up", alerts: "Notifications" };

export function Processing() {
  const { isAdmin } = useApp();
  const qc = useQueryClient();
  const [status, setStatus] = useState("problems");
  const [page, setPage] = useState(1);
  const inbound = useQuery({ queryKey: ["inbound", status, page], queryFn: () => api<{ total: number; counts: Record<string, number>; items: Inbound[] }>(`/api/inbound${qs({ status, page })}`) });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api<{ last: Record<string, { status: string; started_at: string; error: string | null }>; items: Job[] }>("/api/jobs?limit=30"), refetchInterval: 10_000 });
  const run = useMutation({ mutationFn: (job: string) => post(`/api/jobs/${job}`), onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }) });
  const c = inbound.data?.counts ?? {};

  return (
    <>
      <div className="page-head"><h1>Mail processing</h1><span className="muted">Mailbox fetches, parse errors and background jobs</span></div>
      <Card title="Background jobs">
        {jobs.isPending ? <Loading /> : jobs.isError ? <ErrorBox error={jobs.error} /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Job</th><th>Last run</th><th>Result</th><th></th></tr></thead>
            <tbody>{Object.keys(JOB_LABEL).map((j) => {
              const l = jobs.data!.last[j];
              const pending = jobs.data!.items.some((x) => x.job === j && (x.status === "queued" || x.status === "running"));
              return (
                <tr key={j}>
                  <td>{JOB_LABEL[j]}</td>
                  <td>{l ? ago(l.started_at) : "never"}</td>
                  <td>{l ? <Pill tone={STATUS_TONE[l.status] ?? "neutral"}>{l.status}</Pill> : "–"} {l?.error && <span className="small muted break">{l.error}</span>}</td>
                  <td>{isAdmin && <button className="btn" disabled={pending || run.isPending} onClick={() => run.mutate(j)}>{pending ? "Queued…" : "Run now"}</button>}</td>
                </tr>
              );
            })}</tbody>
          </table></div>
        )}
      </Card>

      <Card title="Processed mail" actions={
        <div className="segmented" role="group" aria-label="Filter">
          {[["problems", `Problems (${(c.partial ?? 0) + (c.failed ?? 0)})`], ["", "All"], ["processed", `Processed (${c.processed ?? 0})`], ["duplicate", `Duplicates (${c.duplicate ?? 0})`]].map(([k, label]) => (
            <button key={k} aria-pressed={status === k} onClick={() => { setStatus(k); setPage(1); }}>{label}</button>
          ))}
        </div>}>
        {(c.move_errors ?? 0) > 0 && <div className="alert alert-critical" style={{ marginBottom: 12 }}>{c.move_errors} message(s) could not be moved in the mailbox; the next run retries automatically.</div>}
        {inbound.isPending ? <Loading /> : inbound.isError ? <ErrorBox error={inbound.error} /> : inbound.data!.items.length === 0 ? <Empty>{status === "problems" ? "No problems — every message was processed." : "Nothing processed yet."}</Empty> : (
          <>
            <div className="table-wrap"><table>
              <thead><tr><th>Processed</th><th>Subject / sender</th><th>Type</th><th>Status</th><th className="num">Reports</th><th>Mailbox</th><th>Errors</th></tr></thead>
              <tbody>{inbound.data!.items.map((m) => (
                <tr key={m.id}>
                  <td className="small">{dateTime(m.processed_at)}</td>
                  <td className="break"><div>{m.subject ?? "(no subject)"}</div><div className="muted small">{m.sender}</div></td>
                  <td>{m.kind.toUpperCase()}</td>
                  <td><Pill tone={STATUS_TONE[m.status] ?? "neutral"}>{m.status}</Pill></td>
                  <td className="num">{m.report_ids.length ? m.report_ids.map((id) => <Link key={id} to={`/reports/${id}`}>#{id} </Link>) : num(m.reports_new + m.reports_duplicate)}</td>
                  <td>{m.moved_to ?? (m.source === "file" ? "file import" : "–")}{m.move_error && <div className="small" style={{ color: "var(--critical-ink)" }}>{m.move_error}</div>}</td>
                  <td className="small break">{m.errors.join("; ") || "–"}</td>
                </tr>
              ))}</tbody>
            </table></div>
            <Pager page={page} pageSize={50} total={inbound.data!.total} onPage={setPage} />
          </>
        )}
      </Card>
    </>
  );
}
