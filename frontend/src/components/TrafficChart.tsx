import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TimelinePoint } from "../types";
import { formatClock } from "../lib/format";

interface TrafficChartProps {
  timeline: TimelinePoint[];
  threshold: number;
}

export function TrafficChart({ timeline, threshold }: TrafficChartProps) {
  const data = timeline.map((point) => ({
    ...point,
    time: formatClock(point.timestamp),
  }));

  return (
    <div className="chart-wrap">
      {data.length === 0 ? (
        <div className="empty-chart">
          <span className="pulse-ring" />
          <p>Awaiting traffic windows</p>
          <small>Start a demo to stream network telemetry.</small>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 12, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#4de3b0" stopOpacity={0.34} />
                <stop offset="100%" stopColor="#4de3b0" stopOpacity={0.01} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1d3530" strokeDasharray="3 6" vertical={false} />
            <XAxis
              dataKey="time"
              stroke="#617b73"
              tick={{ fill: "#7f9991", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
              minTickGap={35}
            />
            <YAxis
              domain={[0, 100]}
              stroke="#617b73"
              tick={{ fill: "#7f9991", fontSize: 10 }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                background: "#0c1b18",
                border: "1px solid #284a41",
                borderRadius: 10,
                color: "#d9f4eb",
                fontSize: 12,
              }}
              labelStyle={{ color: "#8fb7aa", marginBottom: 6 }}
              formatter={(value: number, name: string) => [
                name === "max_score" ? `${value.toFixed(1)} score` : value,
                name === "max_score" ? "Anomaly score" : name,
              ]}
            />
            <ReferenceLine
              y={threshold}
              stroke="#d8a34d"
              strokeDasharray="4 5"
              label={{
                value: "alert threshold",
                position: "insideTopRight",
                fill: "#d8a34d",
                fontSize: 10,
              }}
            />
            <Area
              type="monotone"
              dataKey="max_score"
              stroke="#4de3b0"
              strokeWidth={2}
              fill="url(#scoreFill)"
              isAnimationActive={false}
              dot={false}
              activeDot={{ r: 4, fill: "#4de3b0", stroke: "#07110f", strokeWidth: 2 }}
            />
            <Line
              type="monotone"
              dataKey="sources"
              stroke="#5f93d6"
              strokeWidth={1.5}
              dot={false}
              strokeDasharray="3 4"
              isAnimationActive={false}
            />
          </ComposedChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

