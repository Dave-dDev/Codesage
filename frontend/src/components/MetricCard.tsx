import type { ReactNode } from "react";

interface MetricCardProps {
  icon: ReactNode;
  label: string;
  value: string;
  detail: string;
  tone?: "teal" | "amber" | "red" | "blue";
}

export function MetricCard({ icon, label, value, detail, tone = "teal" }: MetricCardProps) {
  return (
    <div className={`metric-card tone-${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div className="metric-copy">
        <span className="metric-label">{label}</span>
        <strong>{value}</strong>
        <span className="metric-detail">{detail}</span>
      </div>
    </div>
  );
}
