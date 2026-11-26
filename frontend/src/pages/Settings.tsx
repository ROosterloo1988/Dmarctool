import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, del, patch, post, put } from "../api";
import { Card, ErrorBox, Loading, Pill, PolicyPill } from "../components/ui";
import { useApp } from "../context";
import { ago, num } from "../format";
import type { SettingEntry } from "../types";

const FIELDS: { key: string; type: "text" | "email" | "number" | "bool"; help?: string }[] = [
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
  const [value, setValue] = useState<string>(entry.value === null || entry.value === undefined ? "" : String(entry.value));
  useEffect(() => setValue(entry.value === null || entry.value === undefined ? "" : String(entry.value)), [entry.value]);
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
        ) : (
          <input id={k} type={type} value={value} onChange={(e) => setValue(e.target.value)} style={{ minWidth: 280 }} />
        )}
        <button className="btn btn-primary" type="submit" disabled={save.isPending}>Save</button>
        {entry.source === "database" && <button className="btn btn-ghost" type="button" onClick={() => reset.mutate()}>Reset to default ({String(entry.default ?? "empty")})</button>}
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
