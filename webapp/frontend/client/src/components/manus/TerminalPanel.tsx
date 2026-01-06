// RAGLOX v3.0 - Terminal Panel Component
// Simplified header, softer colors, institutional quality
// Updated for real-time WebSocket integration
// Enhanced with playback controls for navigating command history

import { useRef, useEffect, useState, useMemo, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Terminal,
  Copy,
  Maximize2,
  Minimize2,
  X,
  Monitor,
  GitBranch,
  Check,
  Wifi,
  WifiOff,
  Trash2,
  Download,
  Play,
  Pause,
  SkipBack,
  SkipForward,
  Rewind,
  FastForward,
  ChevronUp,
  ChevronDown,
  Clock,
  History,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import type { ConnectionStatus } from "@/types";

// Command history entry
export interface CommandHistoryEntry {
  id: string;
  command: string;
  output: string[];
  timestamp: string;
  exitCode?: number;
  duration?: number;
}

interface TerminalPanelProps {
  title?: string;
  executingCommand?: string;
  output: string[];
  isLive?: boolean;
  branch?: string;
  onClose?: () => void;
  onMaximize?: () => void;
  onClear?: () => void;
  className?: string;
  // Connection status
  connectionStatus?: ConnectionStatus;
  // Playback controls
  commandHistory?: CommandHistoryEntry[];
  onReplayCommand?: (command: string) => void;
  enablePlayback?: boolean;
}

export function TerminalPanel({
  title = "Terminal",
  executingCommand,
  output,
  isLive = true,
  branch = "main",
  onClose,
  onMaximize,
  onClear,
  className,
  connectionStatus = "disconnected",
  commandHistory = [],
  onReplayCommand,
  enablePlayback = false,
}: TerminalPanelProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [isMaximized, setIsMaximized] = useState(false);
  const [copied, setCopied] = useState(false);
  
  // Playback state
  const [showHistory, setShowHistory] = useState(false);
  const [selectedCommandIndex, setSelectedCommandIndex] = useState(-1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const playbackIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Compute if terminal has content
  const hasOutput = useMemo(() => output.length > 0, [output]);
  
  // Compute commands from output for playback
  const extractedCommands = useMemo(() => {
    const commands: CommandHistoryEntry[] = [];
    let currentCommand: string | null = null;
    let currentOutput: string[] = [];
    let commandCount = 0;
    
    output.forEach((line, index) => {
      // Detect command lines (starts with $ or has prompt pattern)
      const isCommand = line.includes('$ ') || line.startsWith('$ ');
      
      if (isCommand) {
        // Save previous command if exists
        if (currentCommand) {
          commands.push({
            id: `cmd-${commandCount}`,
            command: currentCommand,
            output: currentOutput,
            timestamp: new Date().toISOString(),
          });
          commandCount++;
        }
        // Extract command from the line
        const match = line.match(/\$\s+(.+)/);
        currentCommand = match ? match[1] : line.replace(/.*\$\s*/, '');
        currentOutput = [];
      } else if (currentCommand) {
        currentOutput.push(line);
      }
    });
    
    // Don't forget the last command
    if (currentCommand) {
      commands.push({
        id: `cmd-${commandCount}`,
        command: currentCommand,
        output: currentOutput,
        timestamp: new Date().toISOString(),
      });
    }
    
    return commandHistory.length > 0 ? commandHistory : commands;
  }, [output, commandHistory]);

  // Playback controls
  const handlePrevCommand = useCallback(() => {
    if (extractedCommands.length === 0) return;
    setSelectedCommandIndex(prev => 
      prev <= 0 ? extractedCommands.length - 1 : prev - 1
    );
  }, [extractedCommands.length]);

  const handleNextCommand = useCallback(() => {
    if (extractedCommands.length === 0) return;
    setSelectedCommandIndex(prev => 
      prev >= extractedCommands.length - 1 ? 0 : prev + 1
    );
  }, [extractedCommands.length]);

  const handleReplay = useCallback(() => {
    if (selectedCommandIndex >= 0 && extractedCommands[selectedCommandIndex]) {
      onReplayCommand?.(extractedCommands[selectedCommandIndex].command);
      toast.success(`Replaying: ${extractedCommands[selectedCommandIndex].command}`);
    }
  }, [selectedCommandIndex, extractedCommands, onReplayCommand]);

  const togglePlayback = useCallback(() => {
    if (isPlaying) {
      if (playbackIntervalRef.current) {
        clearInterval(playbackIntervalRef.current);
        playbackIntervalRef.current = null;
      }
      setIsPlaying(false);
    } else {
      setIsPlaying(true);
      if (selectedCommandIndex < 0) {
        setSelectedCommandIndex(0);
      }
      playbackIntervalRef.current = setInterval(() => {
        setSelectedCommandIndex(prev => {
          if (prev >= extractedCommands.length - 1) {
            setIsPlaying(false);
            if (playbackIntervalRef.current) {
              clearInterval(playbackIntervalRef.current);
              playbackIntervalRef.current = null;
            }
            return prev;
          }
          return prev + 1;
        });
      }, 2000 / playbackSpeed);
    }
  }, [isPlaying, selectedCommandIndex, extractedCommands.length, playbackSpeed]);

  // Cleanup playback interval on unmount
  useEffect(() => {
    return () => {
      if (playbackIntervalRef.current) {
        clearInterval(playbackIntervalRef.current);
      }
    };
  }, []);

  // Auto-scroll to bottom when new output arrives
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [output]);

  const handleCopy = () => {
    const text = output.join("\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleMaximize = () => {
    setIsMaximized(!isMaximized);
    onMaximize?.();
  };

  return (
    <div
      className={cn(
        "flex flex-col h-full overflow-hidden",
        isMaximized && "fixed inset-0 z-50",
        className
      )}
      style={{
        background: '#141414',
        borderLeft: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      {/* Simplified Header - Single Line */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        <div className="flex items-center gap-3">
          <Monitor className="w-4 h-4" style={{ color: '#888888' }} />
          <span className="font-medium text-sm" style={{ color: '#e8e8e8' }}>{title}</span>

          {/* Connection Status Indicator */}
          <div className="flex items-center gap-1.5 ml-2">
            {connectionStatus === "connected" && isLive ? (
              <>
                <div
                  className="w-2 h-2 rounded-full"
                  style={{
                    background: '#4ade80',
                    boxShadow: '0 0 8px rgba(74, 222, 128, 0.5)',
                    animation: 'pulse 2s infinite'
                  }}
                />
                <span className="text-xs" style={{ color: '#4ade80' }}>live</span>
              </>
            ) : connectionStatus === "connecting" ? (
              <>
                <div
                  className="w-2 h-2 rounded-full animate-pulse"
                  style={{ background: '#f59e0b' }}
                />
                <span className="text-xs" style={{ color: '#f59e0b' }}>connecting</span>
              </>
            ) : connectionStatus === "disabled" ? (
              <>
                <WifiOff className="w-3 h-3" style={{ color: '#888888' }} />
                <span className="text-xs" style={{ color: '#888888' }}>demo</span>
              </>
            ) : (
              <>
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ background: '#888888' }}
                />
                <span className="text-xs" style={{ color: '#888888' }}>offline</span>
              </>
            )}
          </div>
        </div>

        {/* Window Controls */}
        <div className="flex items-center gap-1">
          {/* Clear Button */}
          {onClear && hasOutput && (
            <button
              className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
              style={{ color: '#888888' }}
              onClick={onClear}
              title="Clear terminal"
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
            style={{ color: '#888888' }}
            onClick={handleCopy}
            title="Copy output"
            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            {copied ? <Check className="w-3.5 h-3.5" style={{ color: '#4ade80' }} /> : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button
            className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
            style={{ color: '#888888' }}
            onClick={handleMaximize}
            title={isMaximized ? "Minimize" : "Maximize"}
            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            {isMaximized ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
          {onClose && (
            <button
              className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
              style={{ color: '#888888' }}
              onClick={onClose}
              title="Close"
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Terminal Content */}
      <div
        ref={terminalRef}
        className="flex-1 overflow-auto p-4"
        style={{
          backgroundColor: '#0d0d0d',
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
          fontSize: '13px',
          lineHeight: '1.6',
          fontWeight: 400
        }}
      >
        {output.length === 0 ? (
          <div className="flex items-center justify-center h-full text-center">
            <div style={{ color: '#555555' }}>
              <Terminal className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">Terminal output will appear here</p>
              <p className="text-xs mt-1">Waiting for commands...</p>
            </div>
          </div>
        ) : (
          <>
            {output.map((line, index) => (
              <TerminalLine key={index} line={line} />
            ))}

            {/* Blinking cursor when live and connected */}
            {isLive && connectionStatus === "connected" && (
              <span
                className="inline-block w-2 h-4 ml-1"
                style={{
                  background: '#4ade80',
                  animation: 'blink 1s step-end infinite'
                }}
              />
            )}
          </>
        )}
      </div>

      {/* Command History Panel */}
      <AnimatePresence>
        {showHistory && extractedCommands.length > 0 && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
            style={{
              background: 'rgba(0, 0, 0, 0.4)',
              borderTop: '1px solid rgba(255,255,255,0.06)',
              maxHeight: '200px',
            }}
          >
            <div className="p-2 overflow-y-auto max-h-[180px]">
              <div className="text-xs font-medium mb-2 px-2" style={{ color: '#888888' }}>
                Command History ({extractedCommands.length})
              </div>
              {extractedCommands.map((entry, index) => (
                <button
                  key={entry.id}
                  onClick={() => setSelectedCommandIndex(index)}
                  className={cn(
                    "w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-colors",
                    selectedCommandIndex === index && "bg-primary/10"
                  )}
                  style={{ color: selectedCommandIndex === index ? '#4a9eff' : '#a0a0a0' }}
                  onMouseEnter={(e) => {
                    if (selectedCommandIndex !== index) {
                      e.currentTarget.style.background = 'rgba(255,255,255,0.04)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (selectedCommandIndex !== index) {
                      e.currentTarget.style.background = 'transparent';
                    }
                  }}
                >
                  <span className="text-xs w-5" style={{ color: '#666666' }}>#{index + 1}</span>
                  <code className="text-xs truncate flex-1" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    {entry.command}
                  </code>
                  {entry.duration && (
                    <span className="text-xs" style={{ color: '#666666' }}>
                      {entry.duration}ms
                    </span>
                  )}
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Footer with Playback Controls */}
      <div
        className="flex items-center justify-between px-4 py-2"
        style={{
          background: 'rgba(0, 0, 0, 0.3)',
          borderTop: '1px solid rgba(255,255,255,0.06)'
        }}
      >
        {/* Branch indicator */}
        <div className="flex items-center gap-1.5">
          <GitBranch className="w-3.5 h-3.5" style={{ color: '#888888' }} />
          <span className="text-xs" style={{ color: '#888888' }}>{branch}</span>
        </div>

        {/* Playback Controls - only show if enablePlayback and has commands */}
        {enablePlayback && extractedCommands.length > 0 && (
          <div className="flex items-center gap-1">
            {/* History Toggle */}
            <button
              onClick={() => setShowHistory(!showHistory)}
              className={cn(
                "w-6 h-6 rounded flex items-center justify-center transition-all duration-150",
                showHistory && "bg-primary/10"
              )}
              style={{ color: showHistory ? '#4a9eff' : '#888888' }}
              title="Show command history"
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = showHistory ? 'rgba(74, 158, 255, 0.1)' : 'transparent'}
            >
              <History className="w-3.5 h-3.5" />
            </button>
            
            {/* Previous Command */}
            <button
              onClick={handlePrevCommand}
              className="w-6 h-6 rounded flex items-center justify-center transition-all duration-150"
              style={{ color: '#888888' }}
              title="Previous command"
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <SkipBack className="w-3.5 h-3.5" />
            </button>

            {/* Play/Pause */}
            <button
              onClick={togglePlayback}
              className="w-6 h-6 rounded flex items-center justify-center transition-all duration-150"
              style={{ color: isPlaying ? '#4ade80' : '#888888' }}
              title={isPlaying ? "Pause playback" : "Start playback"}
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            </button>

            {/* Next Command */}
            <button
              onClick={handleNextCommand}
              className="w-6 h-6 rounded flex items-center justify-center transition-all duration-150"
              style={{ color: '#888888' }}
              title="Next command"
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <SkipForward className="w-3.5 h-3.5" />
            </button>

            {/* Replay Selected */}
            {selectedCommandIndex >= 0 && onReplayCommand && (
              <button
                onClick={handleReplay}
                className="ml-1 px-2 h-6 rounded flex items-center gap-1 transition-all duration-150"
                style={{ 
                  color: '#4a9eff',
                  background: 'rgba(74, 158, 255, 0.1)',
                  fontSize: '11px',
                }}
                title="Replay selected command"
                onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(74, 158, 255, 0.2)'}
                onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(74, 158, 255, 0.1)'}
              >
                <FastForward className="w-3 h-3" />
                Replay
              </button>
            )}

            {/* Command Counter */}
            <span className="text-xs ml-2" style={{ color: '#666666' }}>
              {selectedCommandIndex >= 0 ? selectedCommandIndex + 1 : '-'}/{extractedCommands.length}
            </span>
          </div>
        )}

        {/* Executing command indicator */}
        {executingCommand && !enablePlayback && (
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5" style={{ color: '#4a9eff' }} />
            <code className="text-xs" style={{ color: '#e8e8e8' }}>{executingCommand}</code>
          </div>
        )}
      </div>

      {/* CSS for animations */}
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; box-shadow: 0 0 8px rgba(74, 222, 128, 0.5); }
          50% { opacity: 0.7; box-shadow: 0 0 16px rgba(74, 222, 128, 0.8); }
        }
        @keyframes blink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
      `}</style>
    </div>
  );
}

// Terminal Line Component with syntax highlighting
function TerminalLine({ line }: { line: string }) {
  // Detect prompt lines (ubuntu@sandbox:~ $)
  const isPrompt = line.includes('@') && line.includes('$');
  // Detect command output headers
  const isHeader = line.startsWith('Filesystem') || line.startsWith('total ');

  if (isPrompt) {
    const parts = line.split('$');
    return (
      <div className="whitespace-pre-wrap">
        <span style={{ color: '#6b9eff' }}>{parts[0]}$</span>
        <span style={{ color: '#e8e8e8' }}>{parts[1] || ''}</span>
      </div>
    );
  }

  if (isHeader) {
    return (
      <div className="whitespace-pre-wrap" style={{ color: '#888888' }}>
        {line}
      </div>
    );
  }

  // Regular output
  return (
    <div className="whitespace-pre-wrap" style={{ color: '#a0a0a0' }}>
      {line}
    </div>
  );
}

export default TerminalPanel;
