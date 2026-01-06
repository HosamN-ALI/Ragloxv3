// RAGLOX v3.0 - Playback Controls Component
// Navigate between executed commands (Read-Only Terminal Playback)
// Based on Manus.im design

import { useState, useMemo } from "react";
import { motion } from "framer-motion";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Play,
  Pause,
  SkipBack,
  SkipForward,
  Zap
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface CommandEntry {
  id: string;
  command: string;
  output: string[];
  timestamp: string;
  status: "success" | "error" | "running";
  duration?: number; // in milliseconds
}

interface PlaybackControlsProps {
  commands: CommandEntry[];
  currentIndex: number;
  onNavigate: (index: number) => void;
  onJumpToLive: () => void;
  isLive?: boolean;
  isPlaying?: boolean;
  onPlayPause?: () => void;
  className?: string;
}

export function PlaybackControls({
  commands,
  currentIndex,
  onNavigate,
  onJumpToLive,
  isLive = false,
  isPlaying = false,
  onPlayPause,
  className,
}: PlaybackControlsProps) {
  const totalCommands = commands.length;
  const hasCommands = totalCommands > 0;
  const isAtStart = currentIndex === 0;
  const isAtEnd = currentIndex >= totalCommands - 1;

  // Current command info
  const currentCommand = useMemo(() => {
    if (!hasCommands || currentIndex < 0 || currentIndex >= totalCommands) {
      return null;
    }
    return commands[currentIndex];
  }, [commands, currentIndex, hasCommands, totalCommands]);

  // Navigation handlers
  const goToFirst = () => onNavigate(0);
  const goToPrevious = () => onNavigate(Math.max(0, currentIndex - 1));
  const goToNext = () => onNavigate(Math.min(totalCommands - 1, currentIndex + 1));
  const goToLast = () => onNavigate(totalCommands - 1);

  if (!hasCommands) {
    return null;
  }

  return (
    <div
      className={cn(
        "flex items-center justify-between px-3 py-2 rounded-lg",
        className
      )}
      style={{
        background: "rgba(30, 30, 30, 0.95)",
        border: "1px solid rgba(255, 255, 255, 0.06)",
      }}
    >
      {/* Left Section - Command Info */}
      <div className="flex items-center gap-3 min-w-0 flex-1">
        {/* Command Counter */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-medium" style={{ color: "#888888" }}>
            Command
          </span>
          <span className="text-xs font-mono" style={{ color: "#e8e8e8" }}>
            {currentIndex + 1}/{totalCommands}
          </span>
        </div>

        {/* Current Command Preview */}
        {currentCommand && (
          <div className="flex-1 min-w-0 overflow-hidden">
            <code
              className="text-xs font-mono truncate block"
              style={{ color: "#4a9eff" }}
              title={currentCommand.command}
            >
              $ {currentCommand.command}
            </code>
          </div>
        )}
      </div>

      {/* Center Section - Navigation Controls */}
      <div className="flex items-center gap-1">
        {/* First */}
        <ControlButton
          onClick={goToFirst}
          disabled={isAtStart}
          title="First command"
        >
          <ChevronsLeft className="w-3.5 h-3.5" />
        </ControlButton>

        {/* Previous */}
        <ControlButton
          onClick={goToPrevious}
          disabled={isAtStart}
          title="Previous command"
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </ControlButton>

        {/* Play/Pause (if auto-play is supported) */}
        {onPlayPause && (
          <ControlButton onClick={onPlayPause} title={isPlaying ? "Pause" : "Play"}>
            {isPlaying ? (
              <Pause className="w-3.5 h-3.5" />
            ) : (
              <Play className="w-3.5 h-3.5" />
            )}
          </ControlButton>
        )}

        {/* Next */}
        <ControlButton
          onClick={goToNext}
          disabled={isAtEnd}
          title="Next command"
        >
          <ChevronRight className="w-3.5 h-3.5" />
        </ControlButton>

        {/* Last */}
        <ControlButton
          onClick={goToLast}
          disabled={isAtEnd}
          title="Last command"
        >
          <ChevronsRight className="w-3.5 h-3.5" />
        </ControlButton>
      </div>

      {/* Right Section - Live Button */}
      <div className="flex items-center gap-2 ml-3">
        <button
          onClick={onJumpToLive}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-200",
            isLive
              ? "bg-green-500/15 text-green-500"
              : "bg-muted text-muted-foreground hover:bg-muted/80"
          )}
        >
          <Zap className={cn("w-3 h-3", isLive && "animate-pulse")} />
          <span>Live</span>
        </button>
      </div>
    </div>
  );
}

// Control Button Component
interface ControlButtonProps {
  onClick: () => void;
  disabled?: boolean;
  title?: string;
  children: React.ReactNode;
}

function ControlButton({ onClick, disabled = false, title, children }: ControlButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={cn(
        "w-7 h-7 rounded flex items-center justify-center transition-all duration-150",
        disabled
          ? "opacity-30 cursor-not-allowed"
          : "hover:bg-white/8 active:scale-95"
      )}
      style={{ color: disabled ? "#444444" : "#888888" }}
      onMouseEnter={(e) => {
        if (!disabled) {
          e.currentTarget.style.color = "#e8e8e8";
        }
      }}
      onMouseLeave={(e) => {
        if (!disabled) {
          e.currentTarget.style.color = "#888888";
        }
      }}
    >
      {children}
    </button>
  );
}

// Timeline Bar Component (Optional - for visual progress)
interface TimelineBarProps {
  commands: CommandEntry[];
  currentIndex: number;
  onSeek: (index: number) => void;
  className?: string;
}

export function TimelineBar({ commands, currentIndex, onSeek, className }: TimelineBarProps) {
  const totalCommands = commands.length;

  if (totalCommands === 0) {
    return null;
  }

  return (
    <div
      className={cn("px-3 py-2", className)}
      style={{
        background: "rgba(20, 20, 20, 0.95)",
        borderTop: "1px solid rgba(255, 255, 255, 0.06)",
      }}
    >
      <div className="flex items-center gap-1">
        {commands.map((cmd, index) => (
          <motion.button
            key={cmd.id}
            onClick={() => onSeek(index)}
            className="flex-1 h-1.5 rounded-full transition-all duration-150"
            style={{
              background:
                index < currentIndex
                  ? cmd.status === "error"
                    ? "#ef4444"
                    : "#4ade80"
                  : index === currentIndex
                  ? "#4a9eff"
                  : "#333333",
              minWidth: "8px",
            }}
            whileHover={{ scaleY: 1.5 }}
            title={`${cmd.command} (${cmd.status})`}
          />
        ))}
      </div>
    </div>
  );
}

export default PlaybackControls;
