import type { FlowWindow } from "../types";
import { formatBytes, formatClock, formatNumber } from "../lib/format";

interface FlowTableProps {
  flows: FlowWindow[];
}

export function FlowTable({ flows }: FlowTableProps) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Window (local)</th>
            <th>Source</th>
            <th>Packets</th>
            <th>Volume</th>
            <th>Flows</th>
            <th>Unique ports</th>
            <th>Score</th>
            <th>State</th>
          </tr>
        </thead>
        <tbody>
          {flows.length === 0 ? (
            <tr>
              <td colSpan={8} className="table-empty">
                No flow windows captured yet.
              </td>
            </tr>
          ) : (
            flows.map((flow) => (
              <tr key={flow.id} className={flow.is_anomaly ? "anomalous-row" : ""}>
                <td className="mono muted">{formatClock(flow.window_start)}</td>
                <td className="mono">{flow.source_ip}</td>
                <td>{formatNumber(flow.packet_count)}</td>
                <td>{formatBytes(flow.byte_count)}</td>
                <td>{formatNumber(flow.flow_count)}</td>
                <td>{formatNumber(flow.features.unique_dst_ports ?? 0)}</td>
                <td>
                  <span className={`score-pill ${flow.is_anomaly ? "is-hot" : ""}`}>
                    {flow.score.toFixed(0)}
                  </span>
                </td>
                <td>
                  <span className={`state-dot ${flow.is_anomaly ? "hot" : ""}`} />
                  {flow.is_anomaly ? "Anomaly" : "Normal"}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
