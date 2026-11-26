import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, del, patch, post, put } from "../api";
import { Card, ErrorBox, Loading, Pill, PolicyPill } from "../components/ui";
import { useApp } from "../context";
import { ago, dateTime, num } from "../format";
import type { SettingEntry } from "../types";

type FieldType = "text" | "email" | "number" | "bool" | "list";

const NOTIFY_FIELDS: { key: string; type: FieldType; help?: string }[] = [
  { key: "notify.recipients", type: "list", help: "One or more addresses, separated by commas or new lines (a distribution list works too)." },
  { key: "notify.enabled", type: "bool" },
  { key: "notify.digest_hour_utc", type: "number", help: "06 UTC = 07:00 (winter) / 08:00 (summer) Dutch time. New DNS errors are always sent immediately." },
  { key: "notify.new_source_min_messages", type: "number" },
  { key: "notify.pass_drop_points", type: "number", help: "Compares the last 7 days with the 7 days before." },
];

const FIELDS: { key: string; type: FieldType; help?: string }[] = [
  { key: "mailbox.address", type: "email", help: "Change the Exchange RBAC scope for the app first (see docs/app-registratie.md §1.4)." },
  { key: "mailbox.source_folder", type: "text", help: "E.g. Inbox or Inbox/DMARC" },
  { key: "mailbox.processed_folder", type: "text" },
  { key: "mailbox.failed_folder", type: "text" },
  { key: "mailbox.poll_minutes", type: "number" },
  { key: "mailbox.batch_size", type: "number" },
  { key: "mailbox.enabled", type: "bool" },
];

function SettingRow({ k, entry, type, help }: { k: string; entry: SettingEntry; type: string; help?: string }) {
  const qc = useQueryClient();
  const show = (v: unknown) => (v === null || v === undefined ? "" : Array.isArray(v) ? v.join(", ") : String(v));
  const [value, setValue] = useState<string>(show(entry.value));
  useEffect(() => setValue(show(entry.value)), [entry.value]);
  const save = useMutation({
    mutationFn: (v: unknown) => put(`/api/settings/${k}`, { value: v }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
  });
  const reset = useMutation({ mutationFn: () => del(`/api/settings/${k}`), onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }) });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(type === "number" ? Number(value) : type === "bool" ? value === "true" : value);
  };
  return (
    <form className="stack" onSubmit={submit} style={{ borderBottom: "1px solid var(--border)", paddingBottom: 12 }}>
      <label className="field" htmlFor={k}>
        <span><strong style={{ color: "var(--text)" }}>{entry.label}</strong> <span className="mono">{k}</span></span>
      </label>
      <div className="row">
        {type === "bool" ? (
          <select id={k} value={value} onChange={(e) => setValue(e.target.value)}><option value="true">Yes</option><option value="false">No</option></select>
        ) : type === "list" ? (
          <textarea id={k} rows={2} value={value} onChange={(e) => setValue(e.target.value)} style={{ maxWidth: 520 }} placeholder="it@tenazenergy.com, security@tenazenergy.com" />
        ) : (
          <input id={k} type={type} value={value} onChange={(e) => setValue(e.target.value)} style={{ minWidth: 280 }} />
        )}
        <button className="btn btn-primary" type="submit" disabled={save.isPending}>Save</button>
        {entry.source === "database" && <button className="btn btn-ghost" type="button" onClick={() => reset.mutate()}>Reset to default ({show(entry.default) || "empty"})</button>}
        {save.isSuccess && <Pill tone="good">saved</Pill>}
      </div>
      <span className="muted small">
        {entry.source === "database" ? `Set by ${entry.updated_by ?? "?"} ${ago(entry.updated_at)}` : "Default from the environment (.env)"}
        {help && <> · {help}</>}
      </span>
      {save.isError && <ErrorBox error={save.error} />}
    </form>
  );
}

interface Notice { id: number; created_at: string; domain: string; kind: string; severity: string; title: string;
  immediate: boolean; sent_at: string | null; send_error: string | null }

function Notifications({ settings }: { settings: Record<string, SettingEntry> }) {
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["notifications"], queryFn: () => api<{ open_problems: number; items: Notice[] }>("/api/notifications?limit=20") });
  const test = useMutation({ mutationFn: () => post<{ sent_to: string[] }>("/api/notifications/test"),
                             onSettled: () => qc.invalidateQueries({ queryKey: ["notifications"] }) });
  return (
    <Card title="Notifications" actions={<button className="btn" onClick={() => test.mutate()} disabled={test.isPending}>Send test mail</button>}>
      <p className="muted" style={{ marginTop: 0 }}>
        Sent from the DMARC mailbox. <strong>Immediately:</strong> new DNS errors (e.g. a second DMARC record, broken SPF).
        <strong> Daily summary:</strong> DNS warnings, resolved problems, new unknown senders and drops of the pass rate.
        Each problem is reported once until it is resolved.
      </p>
      {test.isSuccess && <div className="alert alert-good" style={{ marginBottom: 12 }}>Test mail sent to {test.data.sent_to.join(", ")}.</div>}
      {test.isError && <div style={{ marginBottom: 12 }}><ErrorBox error={test.error} /></div>}
      <div className="stack" style={{ gap: 12 }}>
        {NOTIFY_FIELDS.map((f) => settings[f.key] && <SettingRow key={f.key} k={f.key} entry={settings[f.key]} type={f.type} help={f.help} />)}
      </div>
      <h3>Recent notifications</h3>
      {list.isPending ? <Loading /> : list.isError ? <ErrorBox error={list.error} /> : list.data!.items.length === 0 ? <p className="muted">None yet.</p> : (
        <div className="table-wrap"><table>
          <thead><tr><th>Created</th><th>Domain</th><th>Notification</th><th>Delivery</th></tr></thead>
          <tbody>{list.data!.items.map((n) => (
            <tr key={n.id}>
              <td className="small">{dateTime(n.created_at)}</td><td>{n.domain === "*" ? "–" : n.domain}</td>
              <td><Pill tone={n.severity === "critical" ? "critical" : n.severity === "warning" ? "warning" : "info"}>{n.severity}</Pill> {n.title}</td>
              <td className="small">{n.sent_at ? `${n.immediate ? "sent immediately" : "in summary"} · ${dateTime(n.sent_at)}`
                : n.send_error ? <span style={{ color: "var(--critical-ink)" }}>failed: {n.send_error}</span> : n.immediate ? "pending" : "waiting for summary"}</td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
    </Card>
  );
}

function Domains() {
  const { domains } = useApp();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [parked, setParked] = useState(false);
  const refresh = () => qc.invalidateQueries({ queryKey: ["domains"] });
  const add = useMutation({ mutationFn: () => post("/api/domains", { name, parked }), onSuccess: () => { setName(""); refresh(); } });
  const toggle = useMutation({ mutationFn: (d: { name: string; parked: boolean }) => patch(`/api/domains/${d.name}`, { parked: d.parked }), onSuccess: refresh });
  const remove = useMutation({ mutationFn: (n: string) => del(`/api/domains/${n}`), onSuccess: refresh });
  return (
    <Card title="Monitored domains">
      <div className="table-wrap"><table>
        <thead><tr><th>Domain</th><th>Policy</th><th className="num">Messages (30 d)</th><th>Parked</th><th>DNS</th><th></th></tr></thead>
        <tbody>{domains.map((d) => (
          <tr key={d.name}>
            <td>{d.name}</td><td><PolicyPill policy={d.policy} /></td><td className="num">{num(d.messages)}</td>
            <td><label className="row"><input type="checkbox" checked={d.parked} onChange={(e) => toggle.mutate({ name: d.name, parked: e.target.checked })} /> does not send mail</label></td>
            <td>{d.dns_errors === null ? "not checked" : `${d.dns_errors} errors, ${d.dns_warnings} warnings`}</td>
            <td><button className="btn btn-ghost btn-danger" onClick={() => confirm(`Stop monitoring ${d.name}? Report data is kept.`) && remove.mutate(d.name)}>Remove</button></td>
          </tr>
        ))}</tbody>
      </table></div>
      <form className="filters" style={{ marginTop: 12 }} onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
        <label className="field">Add domain<input value={name} onChange={(e) => setName(e.target.value)} placeholder="tenazenergy.com" required /></label>
        <label className="row"><input type="checkbox" checked={parked} onChange={(e) => setParked(e.target.checked)} /> parked (never sends mail)</label>
        <button className="btn btn-primary" type="submit" disabled={add.isPending}>Add</button>
      </form>
      {add.isError && <ErrorBox error={add.error} />}
    </Card>
  );
}

export function Settings() {
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api<Record<string, SettingEntry>>("/api/settings") });
  return (
    <>
      <div className="page-head"><h1>Settings</h1></div>
      <Domains />
      {q.data && <Notifications settings={q.data} />}
      <Card title="Mailbox">
        <p className="muted" style={{ marginTop: 0 }}>The Graph app credentials (tenant, client id, certificate/secret) are only configured in the server environment, never here.</p>
        {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : (
          <div className="stack" style={{ gap: 12 }}>
            {FIELDS.map((f) => q.data![f.key] && <SettingRow key={f.key} k={f.key} entry={q.data![f.key]} type={f.type} help={f.help} />)}
          </div>
        )}
      </Card>
    </>
  );
}
