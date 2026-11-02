import { AlertTriangle, ChevronRight, ShieldCheck } from "lucide-react";
import type { Alert } from "../types";
import { relativeTime } from "../lib/format";

interface AlertFeedProps {
  alerts: Alert[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

export function AlertFeed({ alerts, selectedId, onSelect }: AlertFeedProps) {
  return (
    <div className="alert-feed">
      {alerts.length === 0 ? (
        <div className="empty-state">
          <ShieldCheck size={26} />
          <p>No anomalies yet</p>
          <small>The detection engine is watching the wire.</small>
        </div>
      ) : (
        alerts.map((alert) => (
          <button
            type="button"
            key={alert.id}
            className={`alert-row severity-${alert.severity} ${
              selectedId === alert.id ? "selected" : ""
            }`}
            onClick={() => onSelect(alert.id)}
          >
            <span className="alert-icon">
              <AlertTriangle size={15} />
            </span>
            <span className="alert-copy">
              <span className="alert-title-line">
                <strong>{alert.title}</strong>
                <time>{relativeTime(alert.created_at)}</time>
              </span>
              <span className="alert-meta">
                <code>{alert.source_ip}</code>
                <span className={`status-chip status-${alert.status}`}>{alert.status}</span>
              </span>
            </span>
            <span className="alert-score">
              {alert.score.toFixed(0)}
              <ChevronRight size={14} />
            </span>
          </button>
        ))
      )}
    </div>
  );
}
