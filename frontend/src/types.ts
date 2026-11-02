export interface TimelinePoint {
  timestamp: string;
  max_score: number;
  packets: number;
  bytes: number;
  sources: number;
}

export interface Summary {
  packets_per_second: number;
  active_sources: number;
  total_windows: number;
  alerts_last_15m: number;
  alert_ratio: number;
  model_threshold: number;
  demo_running: boolean;
  demo_scenario: string | null;
  timeline: TimelinePoint[];
}

export interface FeatureReason {
  name: string;
  label: string;
  value: number;
  baseline: number;
  z_score: number;
  direction: "above" | "below";
}

export interface Alert {
  id: number;
  flow_window_id: number;
  source_ip: string;
  severity: "low" | "medium" | "high" | "critical";
  score: number;
  title: string;
  reasons: FeatureReason[];
  status: "new" | "acknowledged" | "benign";
  created_at: string;
  updated_at: string;
}

export interface FlowWindow {
  id: number;
  source_ip: string;
  window_start: string;
  window_end: string;
  packet_count: number;
  byte_count: number;
  flow_count: number;
  score: number;
  is_anomaly: boolean;
  features: Record<string, number>;
}

export interface AlertDetail extends Alert {
  flow: FlowWindow;
}

export interface ModelInfo {
  model_type: string;
  feature_count: number;
  training_windows: number;
  threshold_score: number;
  features: string[];
  trained_at: string;
}

export interface DemoStatus {
  running: boolean;
  scenario: string | null;
  windows_delivered: number;
  message?: string | null;
}
