import type {
  Alert,
  AlertDetail,
  DemoStatus,
  FlowWindow,
  ModelInfo,
  Summary,
} from "../types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  summary: () => request<Summary>("/api/summary"),
  alerts: (limit = 12) => request<Alert[]>(`/api/alerts?limit=${limit}`),
  alert: (id: number) => request<AlertDetail>(`/api/alerts/${id}`),
  updateAlert: (id: number, status: Alert["status"]) =>
    request<Alert>(`/api/alerts/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  flows: (limit = 40) => request<FlowWindow[]>(`/api/flows?limit=${limit}`),
  model: () => request<ModelInfo>("/api/model/info"),
  startDemo: (scenario: "normal" | "mixed", speed: number) =>
    request<DemoStatus>("/api/demo/start", {
      method: "POST",
      body: JSON.stringify({ scenario, speed, reset: true }),
    }),
  stopDemo: () => request<DemoStatus>("/api/demo/stop", { method: "POST" }),
};
