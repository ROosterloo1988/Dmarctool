import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { num, pct } from "../format";
import type { TrendPoint } from "../types";

const shortDay = (d: string) => new Date(d).toLocaleDateString("en-GB", { day: "2-digit", month: "short", timeZone: "UTC" });

function VolumeTooltip({ active, payload }: { active?: boolean; payload?: { payload: TrendPoint }[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="tooltip">
      <div className="tooltip-title">{shortDay(p.day)}</div>
      <div className="tooltip-row"><span><span className="swatch" style={{ background: "var(--series-pass)" }} /> Pass</span><b>{num(p.pass)}</b></div>
      <div className="tooltip-row"><span><span className="swatch" style={{ background: "var(--series-fail)" }} /> Fail</span><b>{num(p.fail)}</b></div>
      <div className="tooltip-row"><span>Pass rate</span><b>{pct(p.pass_pct)}</b></div>
    </div>
  );
}

function PctTooltip({ active, payload }: { active?: boolean; payload?: { payload: TrendPoint }[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="tooltip">
      <div className="tooltip-title">{shortDay(p.day)}</div>
      <div className="tooltip-row"><span>DMARC pass rate</span><b>{pct(p.pass_pct)}</b></div>
      <div className="tooltip-row"><span>Messages</span><b>{num(p.messages)}</b></div>
    </div>
  );
}

export function TrendChart({ data }: { data: TrendPoint[] }) {
  const [asTable, setAsTable] = useState(false);
  const hasData = data.some((d) => d.messages > 0);
  // Axis line in grid colour; tick labels in the secondary text colour (never the series colour).
  const axis = { axisLine: { stroke: "var(--grid)" }, tickLine: false, tick: { fill: "var(--text-2)", fontSize: 11.5 },
                 interval: "preserveStartEnd" as const, minTickGap: 28 };
  const yTick = { fill: "var(--text-2)", fontSize: 11.5 };

  return (
    <div className="stack">
      <div className="row">
        <div className="legend" aria-label="Legend">
          <span><span className="swatch" style={{ background: "var(--series-pass)" }} />DMARC pass</span>
          <span><span className="swatch" style={{ background: "var(--series-fail)" }} />DMARC fail</span>
        </div>
        <span className="spacer" style={{ flex: 1 }} />
        <div className="segmented" role="group" aria-label="View">
          <button aria-pressed={!asTable} onClick={() => setAsTable(false)}>Chart</button>
          <button aria-pressed={asTable} onClick={() => setAsTable(true)}>Table</button>
        </div>
      </div>
      {!hasData ? (
        <div className="empty">No report data in this period yet.</div>
      ) : asTable ? (
        <div className="table-wrap" style={{ maxHeight: 320 }}>
          <table>
            <thead><tr><th>Day</th><th className="num">Messages</th><th className="num">Pass</th><th className="num">Fail</th><th className="num">Pass rate</th></tr></thead>
            <tbody>
              {data.filter((d) => d.messages).map((d) => (
                <tr key={d.day}><td>{shortDay(d.day)}</td><td className="num">{num(d.messages)}</td><td className="num">{num(d.pass)}</td>
                  <td className="num">{num(d.fail)}</td><td className="num">{pct(d.pass_pct)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <>
          <div className="chart" aria-label="Messages per day, split into DMARC pass and fail">
            <ResponsiveContainer>
              <BarChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }} barCategoryGap={2}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="day" tickFormatter={shortDay} {...axis} />
                <YAxis tickFormatter={(v) => num(v)} width={56} axisLine={false} tickLine={false} allowDecimals={false} tick={yTick} />
                <Tooltip content={<VolumeTooltip />} cursor={{ fill: "var(--surface-2)" }} />
                <Bar dataKey="pass" stackId="v" fill="var(--series-pass)" stroke="var(--surface)" strokeWidth={1} isAnimationActive={false} />
                <Bar dataKey="fail" stackId="v" fill="var(--series-fail)" stroke="var(--surface)" strokeWidth={1} radius={[4, 4, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <h3 style={{ margin: "4px 0 0" }}>DMARC pass rate</h3>
          <div className="chart chart-small" aria-label="DMARC pass rate per day">
            <ResponsiveContainer>
              <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--grid)" />
                <XAxis dataKey="day" tickFormatter={shortDay} {...axis} />
                <YAxis domain={[0, 100]} tickFormatter={(v) => `${v}%`} width={56} axisLine={false} tickLine={false} tick={yTick} />
                <Tooltip content={<PctTooltip />} cursor={{ stroke: "var(--text-2)", strokeDasharray: "3 3" }} />
                <Line dataKey="pass_pct" stroke="var(--series-pass)" strokeWidth={2} dot={false} connectNulls
                      activeDot={{ r: 4, stroke: "var(--surface)", strokeWidth: 2 }} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </div>
  );
}
