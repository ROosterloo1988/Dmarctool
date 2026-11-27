export interface Me { id: number; name: string; email: string | null; role: "admin" | "viewer"; is_local: boolean; csrf: string }

export interface DomainSummary {
  name: string; active: boolean; parked: boolean; messages: number; dmarc_pass_pct: number | null;
  policy: string | null; dns_errors: number | null; dns_warnings: number | null; dns_checked_at: string | null;
}

export interface Recommendation {
  severity: "error" | "warning" | "info"; code: string; title: string; text: string; actions: string[];
  source_key: string | null; messages: number | null;
}

export interface Criterion { key: string; ok: boolean; text: string }

export interface Readiness {
  domain: string; status: "ready" | "almost" | "not_ready"; policy: string | null; pct: number;
  pass_rate: number | null; legit_messages: number; total_messages: number; report_days: number;
  criteria: Criterion[]; unknown_failing: { key: string; name: string; messages: number }[];
  next_step: { title: string; text: string; actions: string[] } | null;
}

export interface TrendPoint { day: string; messages: number; pass: number; fail: number; pass_pct: number | null }

export interface Dashboard {
  domain: string; days: number;
  totals: { messages: number; dmarc_pass: number; spf_aligned: number; dkim_aligned: number; quarantined: number;
            rejected: number; forwarded: number; dmarc_pass_pct: number | null; spf_aligned_pct: number | null;
            dkim_aligned_pct: number | null };
  previous: { messages: number; dmarc_pass_pct: number | null };
  trend: TrendPoint[];
  top_sources: { key: string; name: string; messages: number; dmarc_pass_pct: number | null }[];
  readiness: Readiness; recommendations: Recommendation[]; recommendation_count: number;
  dns: { checked_at: string; errors: number; warnings: number } | null;
}

export type SourceStatus = "legit" | "unknown" | "abuse" | null;

export interface Source {
  key: string; name: string; sender: string | null; category: string | null; status: SourceStatus;
  recognised: boolean; considered_legit: boolean; messages: number; failing: number; dmarc_pass_pct: number;
  spf_aligned_pct: number; dkim_aligned_pct: number; spf_pass_pct: number; dkim_pass_pct: number; ip_count: number;
  envelope_domains: Record<string, number>; dkim_domains: Record<string, number>; selectors: Record<string, number>;
  note: string | null; classified_by: string | null; asns: string[]; countries: string[]; ips: string[]; ruf_count: number;
}

export interface AuthResult { method: "spf" | "dkim"; domain: string | null; selector: string | null; scope: string | null; result: string; aligned: boolean }

export interface RecordRow {
  id: number; report: { id: number; org_name: string; report_id: string; date_begin: string; date_end: string };
  domain: string; source_ip: string; ptr: string | null; ptr_confirmed: boolean; as_org: string | null; asn: number | null; country: string | null;
  source_key: string; source_name: string; count: number; disposition: string | null; header_from: string | null;
  envelope_from: string | null; envelope_to: string | null; spf_aligned: boolean; dkim_aligned: boolean;
  dmarc_pass: boolean; reasons: { type: string; comment: string | null }[]; auth: AuthResult[];
}

export interface Paged<T> { total: number; page?: number; page_size?: number; items: T[] }

export interface ReportRow {
  id: number; org_name: string; report_id: string; domain: string; date_begin: string; date_end: string;
  messages: number; dmarc_pass_pct: number | null; policy: string | null; records: number; errors: string[];
}

export interface Finding { check: string; severity: "error" | "warning" | "info" | "ok"; code: string; message: string; fix: string | null; detail: Record<string, unknown> }

export interface SettingEntry { value: unknown; source: "database" | "environment"; default: unknown; label: string; updated_by: string | null; updated_at: string | null }
