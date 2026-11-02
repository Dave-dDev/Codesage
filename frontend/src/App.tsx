import { useCallback, useEffect, useRef, useState } from "react";
import {
  Activity,
  Braces,
  CircleDot,
  Gauge,
  Network,
  Radio,
  Radar,
  ShieldAlert,
  Wifi,
} from "lucide-react";
import { api } from "./lib/api";
import type { Alert, AlertDetail, FlowWindow, ModelInfo, Summary } from "./types";
import { AlertDrawer } from "./components/AlertDrawer";
import { AlertFeed } from "./components/AlertFeed";
import { DemoControls } from "./components/DemoControls";
import { FlowTable } from "./components/FlowTable";
import { MetricCard } from "./components/MetricCard";
import { TrafficChart } from "./components/TrafficChart";
import { formatNumber } from "./lib/format";

type ConnectionState = "connecting" | "live" | "offline";

export default function App() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [flows, setFlows] = useState<FlowWindow[]>([]);
  const [model, setModel] = useState<ModelInfo | null>(null);
  const [selected, setSelected] = useState<AlertDetail | null>(null);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [busy, setBusy] = useState(false);
  const [speed, setSpeed] = useState(2);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);
  const selectedIdRef = useRef<number | null>(null);

  useEffect(() => {
    selectedIdRef.current = selected?.id ?? null;
  }, [selected]);

  const refresh = useCallback(async () => {
    try {
      const [nextSummary, nextAlerts, nextFlows, nextModel] = await Promise.all([
        api.summary(),
        api.alerts(10),
        api.flows(30),
        api.model(),
      ]);
      if (!mounted.current) return;
      setSummary(nextSummary);
      setAlerts(nextAlerts);
      setFlows(nextFlows);
      setModel(nextModel);
      const selectedId = selectedIdRef.current;
      if (selectedId !== null) {
        const updated = nextAlerts.find((item) => item.id === selectedId);
        if (updated) {
          setSelected((current) =>
            current && current.id === selectedId ? { ...current, ...updated } : current,
          );
        }
      }
    } catch (cause) {
      if (mounted.current) {
        setError(cause instanceof Error ? cause.message : "Unable to reach the NetSentry API");
      }
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    const poll = window.setInterval(() => void refresh(), 2500);
    return () => {
      mounted.current = false;
      window.clearInterval(poll);
    };
  }, [refresh]);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retryTimer: number | undefined;
    let closed = false;

    const connect = () => {
      if (closed) return;
      setConnection("connecting");
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(`${protocol}//${window.location.host}/ws/live`);
      socket.onopen = () => setConnection("live");
      socket.onclose = () => {
        setConnection("offline");
        if (!closed) retryTimer = window.setTimeout(connect, 2500);
      };
      socket.onerror = () => socket?.close();
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as { type: string };
          if (message.type === "alert" || message.type === "demo") {
            void refresh();
          }
        } catch {
          // Ignore malformed frames.
        }
      };
    };

    connect();
    return () => {
      closed = true;
      if (retryTimer) window.clearTimeout(retryTimer);
      socket?.close();
    };
  }, [refresh]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSelected(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const openAlert = async (id: number) => {
    try {
      setSelected(await api.alert(id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load alert");
    }
  };

  const triage = async (status: "acknowledged" | "benign") => {
    if (!selected) return;
    setBusy(true);
    try {
      await api.updateAlert(selected.id, status);
      setSelected({ ...selected, status });
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to update alert");
    } finally {
      setBusy(false);
    }
  };

  const startDemo = async (scenario: "normal" | "mixed") => {
    setBusy(true);
    setError(null);
    try {
      await api.startDemo(scenario, speed);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to start replay");
    } finally {
      setBusy(false);
    }
  };

  const stopDemo = async () => {
    setBusy(true);
    try {
      await api.stopDemo();
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to stop replay");
    } finally {
      setBusy(false);
    }
  };

  const statusLabel =
    connection === "live" ? "Live" : connection === "connecting" ? "Connecting" : "Offline";

  return (
    <div className="app-shell">
      <div className="ambient-grid" />
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">
            <Radar size={23} />
          </div>
          <div>
            <strong>NETSENTRY<span>AI</span></strong>
            <small>Network anomaly intelligence</small>
          </div>
        </div>
        <div className="topbar-right">
          <div className={`connection-pill ${connection}`}>
            <span />
            {statusLabel}
          </div>
          {model && (
            <div className="model-pill" title={`${model.model_type} · trained ${model.trained_at}`}>
              <Braces size={14} />
              IFOREST · {model.feature_count} features
            </div>
          )}
          <DemoControls
            running={summary?.demo_running ?? false}
            scenario={summary?.demo_scenario ?? null}
            busy={busy}
            speed={speed}
            onSpeedChange={setSpeed}
            onStart={startDemo}
            onStop={stopDemo}
          />
        </div>
      </header>

      {error && (
        <div className="error-banner">
          <Wifi size={15} />
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

      <main>
        <section className="page-intro">
          <div>
            <span className="eyebrow">
              <CircleDot size={12} />
              Operations console
            </span>
            <h1>Watch the wire. <em>Find the signal.</em></h1>
            <p>
              Unsupervised detection over packet metadata, with evidence-first triage for every
              anomaly.
            </p>
          </div>
          <div className={`replay-status ${summary?.demo_running ? "active" : ""}`}>
            <Radio size={16} />
            <div>
              <span>{summary?.demo_running ? "Replay running" : "Replay idle"}</span>
              <strong>
                {summary?.demo_running
                  ? `${summary.demo_scenario} scenario`
                  : "Start a scenario to stream telemetry"}
              </strong>
            </div>
          </div>
        </section>

        <section className="metrics-grid">
          <MetricCard
            icon={<Activity size={19} />}
            label="Traffic rate"
            value={summary ? `${formatNumber(summary.packets_per_second)} pps` : "—"}
            detail="Rolling 30-second average"
          />
          <MetricCard
            icon={<Network size={19} />}
            label="Active sources"
            value={summary ? formatNumber(summary.active_sources) : "—"}
            detail="Distinct hosts in last 30s"
            tone="blue"
          />
          <MetricCard
            icon={<ShieldAlert size={19} />}
            label="Alerts / 15m"
            value={summary ? formatNumber(summary.alerts_last_15m) : "—"}
            detail={summary ? `${summary.alert_ratio.toFixed(1)}% anomalous windows` : "No windows yet"}
            tone="red"
          />
          <MetricCard
            icon={<Gauge size={19} />}
            label="Detection threshold"
            value={summary ? `${summary.model_threshold.toFixed(0)} / 100` : "—"}
            detail="Isolation Forest score floor"
            tone="amber"
          />
        </section>

        <section className="dashboard-grid">
          <article className="panel chart-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Live telemetry</span>
                <h2>Anomaly signal</h2>
              </div>
              <div className="chart-legend">
                <span className="legend-score">Score</span>
                <span className="legend-sources">Sources</span>
              </div>
            </div>
            <TrafficChart
              timeline={summary?.timeline ?? []}
              threshold={summary?.model_threshold ?? 50}
            />
            <div className="chart-footer">
              <span>{summary?.total_windows ?? 0} source-windows analyzed</span>
              <span>Metadata only · no payload inspection</span>
            </div>
          </article>

          <article className="panel alerts-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Triage queue</span>
                <h2>Recent alerts</h2>
              </div>
              <span className="count-badge">{alerts.filter((item) => item.status === "new").length} new</span>
            </div>
            <AlertFeed alerts={alerts} selectedId={selected?.id ?? null} onSelect={openAlert} />
          </article>
        </section>

        <section className="panel flows-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Forensic view</span>
              <h2>Source-window explorer</h2>
            </div>
            <span className="panel-note">5-second aggregation windows</span>
          </div>
          <FlowTable flows={flows} />
        </section>
      </main>

      <footer className="app-footer">
        <span>NetSentry AI · FastAPI + Isolation Forest + WebSocket</span>
        <span>Demo data is synthetic. Anomalies are not proof of compromise.</span>
      </footer>

      <AlertDrawer
        alert={selected}
        busy={busy}
        onClose={() => setSelected(null)}
        onTriage={triage}
      />
    </div>
  );
}


