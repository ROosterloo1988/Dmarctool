import type { ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { AppProvider, useApp, useMe } from "./context";
import { Dashboard } from "./pages/Dashboard";
import { Dns } from "./pages/Dns";
import { Forensic, ForensicDetail } from "./pages/Forensic";
import { IpDetail } from "./pages/IpDetail";
import { Login } from "./pages/Login";
import { Processing } from "./pages/Processing";
import { Recommendations } from "./pages/Recommendations";
import { Records } from "./pages/Records";
import { ReportDetail, Reports } from "./pages/Reports";
import { Settings } from "./pages/Settings";
import { Sources } from "./pages/Sources";
import { Users } from "./pages/Users";

function AdminOnly({ children }: { children: ReactNode }) {
  const { isAdmin } = useApp();
  return isAdmin ? <>{children}</> : <div className="alert alert-critical">This page is only available to administrators.</div>;
}

function Authed() {
  const { data: me, isPending, isError } = useMe();
  if (isPending) return <Loading />;
  if (isError || !me) return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  return (
    <AppProvider me={me}>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="sources" element={<Sources />} />
          <Route path="recommendations" element={<Recommendations />} />
          <Route path="dns" element={<Dns />} />
          <Route path="records" element={<Records />} />
          <Route path="reports" element={<Reports />} />
          <Route path="reports/:id" element={<ReportDetail />} />
          <Route path="ips/:ip" element={<IpDetail />} />
          <Route path="forensic" element={<AdminOnly><Forensic /></AdminOnly>} />
          <Route path="forensic/:id" element={<AdminOnly><ForensicDetail /></AdminOnly>} />
          <Route path="processing" element={<Processing />} />
          <Route path="settings" element={<AdminOnly><Settings /></AdminOnly>} />
          <Route path="users" element={<AdminOnly><Users /></AdminOnly>} />
          <Route path="*" element={<div className="empty">Page not found.</div>} />
        </Route>
      </Routes>
    </AppProvider>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/*" element={<Authed />} />
      </Routes>
    </BrowserRouter>
  );
}
