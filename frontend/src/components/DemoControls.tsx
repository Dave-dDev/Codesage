import { Activity, ChevronDown, Radar, Square, Zap } from "lucide-react";

interface DemoControlsProps {
  running: boolean;
  scenario: string | null;
  busy: boolean;
  speed: number;
  onSpeedChange: (speed: number) => void;
  onStart: (scenario: "normal" | "mixed") => void;
  onStop: () => void;
}

export function DemoControls({
  running,
  scenario,
  busy,
  speed,
  onSpeedChange,
  onStart,
  onStop,
}: DemoControlsProps) {
  return (
    <div className="demo-controls">
      <div className="speed-control">
        <Zap size={14} />
        <select
          aria-label="Replay speed"
          value={speed}
          onChange={(event) => onSpeedChange(Number(event.target.value))}
          disabled={running || busy}
        >
          <option value={1}>1x</option>
          <option value={2}>2x</option>
          <option value={3}>3x</option>
          <option value={5}>5x</option>
        </select>
        <ChevronDown size={13} className="select-chevron" />
      </div>
      <button
        type="button"
        className={`control-button ${running && scenario === "normal" ? "active" : ""}`}
        onClick={() => onStart("normal")}
        disabled={busy}
      >
        <Activity size={15} />
        Normal
      </button>
      <button
        type="button"
        className={`control-button primary ${running && scenario === "mixed" ? "active" : ""}`}
        onClick={() => onStart("mixed")}
        disabled={busy}
      >
        <Radar size={15} />
        Run attack replay
      </button>
      <button
        type="button"
        className="icon-button"
        aria-label="Stop replay"
        onClick={onStop}
        disabled={!running || busy}
      >
        <Square size={14} fill="currentColor" />
      </button>
    </div>
  );
}
