// RAGLOX v3.0 - Progress Bar Component
// Bottom progress indicator showing current phase and elapsed time
// Based on Manus.im design

import { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Clock, 
  CheckCircle2, 
  Loader2, 
  ChevronUp, 
  ChevronDown,
  Terminal,
  Play,
  Pause
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface ProgressPhase {
  id: string;
  name: string;
  status: "pending" | "running" | "completed" | "failed";
  description?: string;
  startTime?: string;
  endTime?: string;
}

interface ProgressBarProps {
  currentPhase: number;
  totalPhases: number;
  phaseName: string;
  startTime?: string;
  phases?: ProgressPhase[];
  isRunning?: boolean;
  onPause?: () => void;
  onResume?: () => void;
  className?: string;
}

export function ProgressBar({
  currentPhase,
  totalPhases,
  phaseName,
  startTime,
  phases = [],
  isRunning = true,
  onPause,
  onResume,
  className,
}: ProgressBarProps) {
  const [elapsedTime, setElapsedTime] = useState("00:00");
  const [isExpanded, setIsExpanded] = useState(false);

  // Calculate elapsed time
  useEffect(() => {
    if (!startTime || !isRunning) return;

    const updateTime = () => {
      const start = new Date(startTime).getTime();
      const now = Date.now();
      const diff = Math.floor((now - start) / 1000);
      
      const minutes = Math.floor(diff / 60);
      const seconds = diff % 60;
      
      setElapsedTime(
        `${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`
      );
    };

    updateTime();
    const interval = setInterval(updateTime, 1000);

    return () => clearInterval(interval);
  }, [startTime, isRunning]);

  // Calculate progress percentage
  const progress = useMemo(() => {
    if (totalPhases === 0) return 0;
    return Math.min((currentPhase / totalPhases) * 100, 100);
  }, [currentPhase, totalPhases]);

  // Check if all phases are completed
  const isCompleted = currentPhase >= totalPhases;

  return (
    <div className={cn("w-full", className)}>
      {/* Main Progress Bar */}
      <div
        className="relative rounded-lg overflow-hidden"
        style={{
          background: "rgba(38, 38, 38, 0.95)",
          backdropFilter: "blur(8px)",
          border: "1px solid rgba(255, 255, 255, 0.06)",
        }}
      >
        {/* Progress Background */}
        <div className="absolute inset-0 overflow-hidden">
          <motion.div
            className="h-full"
            style={{
              background: isCompleted
                ? "linear-gradient(90deg, rgba(74, 222, 128, 0.15) 0%, rgba(74, 222, 128, 0.05) 100%)"
                : "linear-gradient(90deg, rgba(74, 158, 255, 0.15) 0%, rgba(74, 158, 255, 0.05) 100%)",
            }}
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.5, ease: "easeOut" }}
          />
        </div>

        {/* Content */}
        <div className="relative px-4 py-3 flex items-center justify-between">
          {/* Left Section - Status */}
          <div className="flex items-center gap-3">
            {/* Status Icon */}
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{
                background: isCompleted
                  ? "rgba(74, 222, 128, 0.15)"
                  : "rgba(74, 158, 255, 0.15)",
              }}
            >
              {isCompleted ? (
                <CheckCircle2 className="w-4 h-4" style={{ color: "#4ade80" }} />
              ) : isRunning ? (
                <Loader2 className="w-4 h-4 animate-spin" style={{ color: "#4a9eff" }} />
              ) : (
                <Pause className="w-4 h-4" style={{ color: "#f59e0b" }} />
              )}
            </div>

            {/* Phase Info */}
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium" style={{ color: "#e8e8e8" }}>
                  {phaseName}
                </span>
                {!isCompleted && (
                  <span className="text-xs" style={{ color: "#888888" }}>
                    {currentPhase}/{totalPhases}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1.5 mt-0.5">
                <Terminal className="w-3 h-3" style={{ color: "#666666" }} />
                <span className="text-xs" style={{ color: "#666666" }}>
                  {isCompleted ? "Task completed" : "RAGLOX is using Terminal"}
                </span>
              </div>
            </div>
          </div>

          {/* Right Section - Time & Controls */}
          <div className="flex items-center gap-3">
            {/* Elapsed Time */}
            <div className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" style={{ color: "#666666" }} />
              <span
                className="text-sm font-mono"
                style={{ color: "#888888" }}
              >
                {elapsedTime}
              </span>
            </div>

            {/* Play/Pause Button */}
            {!isCompleted && (onPause || onResume) && (
              <button
                onClick={isRunning ? onPause : onResume}
                className="w-7 h-7 rounded flex items-center justify-center transition-colors"
                style={{ color: "#888888" }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.background = "rgba(255,255,255,0.08)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = "transparent")
                }
              >
                {isRunning ? (
                  <Pause className="w-3.5 h-3.5" />
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
              </button>
            )}

            {/* Expand Button (if phases provided) */}
            {phases.length > 0 && (
              <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="w-7 h-7 rounded flex items-center justify-center transition-colors"
                style={{ color: "#888888" }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.background = "rgba(255,255,255,0.08)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = "transparent")
                }
              >
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4" />
                ) : (
                  <ChevronUp className="w-4 h-4" />
                )}
              </button>
            )}
          </div>
        </div>

        {/* Progress Line at Bottom */}
        <div className="h-0.5" style={{ background: "rgba(255,255,255,0.06)" }}>
          <motion.div
            className="h-full"
            style={{
              background: isCompleted ? "#4ade80" : "#4a9eff",
            }}
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.5, ease: "easeOut" }}
          />
        </div>
      </div>

      {/* Expanded Phase List */}
      <AnimatePresence>
        {isExpanded && phases.length > 0 && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden mt-2"
          >
            <div
              className="rounded-lg p-2 space-y-1"
              style={{
                background: "rgba(30, 30, 30, 0.95)",
                border: "1px solid rgba(255, 255, 255, 0.06)",
              }}
            >
              {phases.map((phase, index) => (
                <PhaseItem key={phase.id} phase={phase} index={index} />
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Phase Item Component
function PhaseItem({ phase, index }: { phase: ProgressPhase; index: number }) {
  const getStatusIcon = () => {
    switch (phase.status) {
      case "completed":
        return <CheckCircle2 className="w-3.5 h-3.5" style={{ color: "#4ade80" }} />;
      case "running":
        return <Loader2 className="w-3.5 h-3.5 animate-spin" style={{ color: "#4a9eff" }} />;
      case "failed":
        return <div className="w-3.5 h-3.5 rounded-full" style={{ background: "#ef4444" }} />;
      default:
        return <div className="w-3.5 h-3.5 rounded-full" style={{ background: "#333333" }} />;
    }
  };

  return (
    <div
      className="flex items-center gap-3 px-3 py-2 rounded-lg transition-colors"
      style={{
        background: phase.status === "running" ? "rgba(74, 158, 255, 0.08)" : "transparent",
      }}
    >
      {/* Status Icon */}
      <div className="flex-shrink-0">{getStatusIcon()}</div>

      {/* Phase Info */}
      <div className="flex-1 min-w-0">
        <span
          className="text-sm"
          style={{
            color: phase.status === "completed" ? "#888888" : "#e8e8e8",
          }}
        >
          {phase.name}
        </span>
        {phase.description && (
          <p className="text-xs truncate" style={{ color: "#666666" }}>
            {phase.description}
          </p>
        )}
      </div>

      {/* Phase Number */}
      <span className="text-xs flex-shrink-0" style={{ color: "#555555" }}>
        #{index + 1}
      </span>
    </div>
  );
}

export default ProgressBar;
