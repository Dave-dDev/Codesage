import {
  ArrowDownRight,
  ArrowUpRight,
  Check,
  ShieldOff,
  X,
} from "lucide-react";
import type { AlertDetail } from "../types";
import { formatBytes, formatClock, formatNumber } from "../lib/format";

interface AlertDrawerProps {
  alert: AlertDetail | null;
  busy: boolean;
  onClose: () => void;
  onTriage: (status: "acknowledged" | "benign") => void;
}

export function AlertDrawer({ alert, busy, onClose, onTriage }: AlertDrawerProps) {
  if (!alert) return null;
  const maxDeviation = Math.max(...alert.reasons.map((reason) => Math.abs(reason.z_score)), 1);

  return (
    <div className="drawer-backdrop" onMouseDown={onClose}>
      <aside className="alert-drawer" onMouseDown={(event) => event.stopPropagation()}>
        <div className={`drawer-accent severity-${alert.severity}`} />
        <header className="drawer-header">
          <div>
            <span className={`severity-label severity-${alert.severity}`}>
              {alert.severity} severity
            </span>
            <h2>{alert.title}</h2>
            <p>
              Source <code>{alert.source_ip}</code> · window{" "}
              {formatClock(alert.flow.window_start)}
            </p>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close alert">
            <X size={17} />
          </button>
        </header>

        <div className="drawer-score-row">
          <div>
            <span>Anomaly score</span>
            <strong>{alert.score.toFixed(1)}</strong>
          </div>
          <div className="score-gauge">
            <span style={{ width: `${alert.score}%` }} />
          </div>
          <span className={`status-chip status-${alert.status}`}>{alert.status}</span>
        </div>

        <section className="drawer-section">
          <div className="section-heading">
            <h3>Why it fired</h3>
            <span>Top deviations from baseline</span>
          </div>
          <div className="reason-list">
            {alert.reasons.map((reason) => (
              <div className="reason-item" key={reason.name}>
                <div className="reason-topline">
                  <span>
                    {reason.direction === "above" ? (
                      <ArrowUpRight size={14} className="direction-up" />
                    ) : (
                      <ArrowDownRight size={14} className="direction-down" />
                    )}
                    {reason.label}
                  </span>
                  <strong>{reason.z_score.toFixed(1)}σ</strong>
                </div>
                <div className="reason-bar">
                  <span
                    style={{
                      width: `${Math.min(
                        100,
                        (Math.abs(reason.z_score) / maxDeviation) * 100,
                      )}%`,
                    }}
                  />
                </div>
                <div className="reason-values">
                  <span>Observed {formatNumber(reason.value)}</span>
                  <span>Baseline {formatNumber(reason.baseline)}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="drawer-section">
          <div className="section-heading">
            <h3>Window evidence</h3>
            <span>Packet metadata only</span>
          </div>
          <div className="evidence-grid">
            <div>
              <span>Packets</span>
              <strong>{formatNumber(alert.flow.packet_count)}</strong>
            </div>
            <div>
              <span>Bytes</span>
              <strong>{formatBytes(alert.flow.byte_count)}</strong>
            </div>
            <div>
              <span>Flows</span>
              <strong>{formatNumber(alert.flow.flow_count)}</strong>
            </div>
            <div>
              <span>Unique ports</span>
              <strong>{formatNumber(alert.flow.features.unique_dst_ports ?? 0)}</strong>
            </div>
          </div>
        </section>

        <footer className="drawer-actions">
          <button
            type="button"
            className="control-button"
            onClick={() => onTriage("benign")}
            disabled={busy}
          >
            <ShieldOff size={15} />
            Mark benign
          </button>
          <button
            type="button"
            className="control-button primary"
            onClick={() => onTriage("acknowledged")}
            disabled={busy}
          >
            <Check size={15} />
            Acknowledge
          </button>
        </footer>
      </aside>
    </div>
  );
}
