import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, patch } from "../api";
import { Card, ErrorBox, Loading, Pager, Pill } from "../components/ui";
import { useApp } from "../context";
import { dateTime } from "../format";

interface U { id: number; name: string | null; email: string | null; role: string; is_local: boolean; active: boolean; last_login: string | null; locked: boolean }
interface A { id: number; at: string; user: string | null; action: string; target: string | null; detail: Record<string, unknown>; ip: string | null }

export function Users() {
  const { me } = useApp();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<U[]>("/api/users") });
  const audit = useQuery({ queryKey: ["audit", page], queryFn: () => api<{ total: number; items: A[] }>(`/api/audit?page=${page}&page_size=50`) });
  const upd = useMutation({ mutationFn: (b: { id: number; active?: boolean; role?: string }) => patch(`/api/users/${b.id}`, b), onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }) });

  return (
    <>
      <div className="page-head"><h1>Users & audit log</h1></div>
      <Card title="Users">
        <p className="muted" style={{ marginTop: 0 }}>Microsoft accounts appear after their first sign-in. Their role follows the app role assignment in Entra ID (Enterprise applications → DMARC-rapportage (portal) → Users and groups).</p>
        {users.isPending ? <Loading /> : users.isError ? <ErrorBox error={users.error} /> : (
          <div className="table-wrap"><table>
            <thead><tr><th>Name</th><th>Type</th><th>Role</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead>
            <tbody>{users.data!.map((u) => (
              <tr key={u.id}>
                <td>{u.name}<div className="muted small">{u.email}</div></td>
                <td>{u.is_local ? "local (emergency)" : "Microsoft Entra ID"}</td>
                <td>{u.is_local && u.id !== me.id ? (
                  <select value={u.role} onChange={(e) => upd.mutate({ id: u.id, role: e.target.value })}><option value="admin">admin</option><option value="viewer">viewer</option></select>
                ) : u.role}</td>
                <td>{!u.active ? <Pill tone="critical">disabled</Pill> : u.locked ? <Pill tone="warning">locked</Pill> : <Pill tone="good">active</Pill>}</td>
                <td>{dateTime(u.last_login)}</td>
                <td>{u.id !== me.id && <button className="btn btn-ghost" onClick={() => upd.mutate({ id: u.id, active: !u.active })}>{u.active ? "Disable" : "Enable"}</button>}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
        {upd.isError && <ErrorBox error={upd.error} />}
      </Card>
      <Card title="Audit log">
        {audit.isPending ? <Loading /> : audit.isError ? <ErrorBox error={audit.error} /> : (
          <>
            <div className="table-wrap"><table>
              <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr></thead>
              <tbody>{audit.data!.items.map((a) => (
                <tr key={a.id}><td className="small">{dateTime(a.at)}</td><td>{a.user ?? "–"}</td><td>{a.action}</td><td className="break">{a.target ?? "–"}</td>
                  <td className="mono small break">{Object.keys(a.detail).length ? JSON.stringify(a.detail) : ""}</td><td className="mono small">{a.ip}</td></tr>
              ))}</tbody>
            </table></div>
            <Pager page={page} pageSize={50} total={audit.data!.total} onPage={setPage} />
          </>
        )}
      </Card>
    </>
  );
}
