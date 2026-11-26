const nf = new Intl.NumberFormat("en-GB");

export const num = (n: number | null | undefined) => (n === null || n === undefined ? "–" : nf.format(n));
export const pct = (n: number | null | undefined) => (n === null || n === undefined ? "–" : `${n.toFixed(1)}%`);

export function date(s: string | null | undefined): string {
  if (!s) return "–";
  return new Date(s).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric", timeZone: "UTC" });
}

export function dateTime(s: string | null | undefined): string {
  if (!s) return "–";
  return new Date(s).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function ago(s: string | null | undefined): string {
  if (!s) return "never";
  const sec = (Date.now() - new Date(s).getTime()) / 1000;
  if (sec < 90) return "just now";
  if (sec < 3600) return `${Math.round(sec / 60)} min ago`;
  if (sec < 86400 * 2) return `${Math.round(sec / 3600)} h ago`;
  return `${Math.round(sec / 86400)} days ago`;
}
