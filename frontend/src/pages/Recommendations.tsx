import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { Card, ErrorBox, Loading, RecommendationList } from "../components/ui";
import { useApp } from "../context";
import type { Recommendation } from "../types";

export function Recommendations() {
  const { domain } = useApp();
  const q = useQuery({ queryKey: ["recs", domain], queryFn: () => api<Recommendation[]>(`/api/domains/${domain}/recommendations`), enabled: !!domain });
  if (!domain || q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} />;
  return (
    <>
      <div className="page-head"><h1>Recommendations for {domain}</h1></div>
      <Card>
        <p className="muted" style={{ marginTop: 0 }}>Based on the reports of the last 30 days and the latest DNS check. Most important first.</p>
        <RecommendationList items={q.data!} domain={domain} />
      </Card>
    </>
  );
}
