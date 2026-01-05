// RAGLOX v3.0 - Terminal Panel Component
// Simplified header, softer colors, institutional quality
// Updated for real-time WebSocket integration

import { useRef, useEffect, useState, useMemo } from "react";
import { motion } from "framer-motion";
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
  Download
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import type { ConnectionStatus } from "@/types";

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
}: TerminalPanelProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [isMaximized, setIsMaximized] = useState(false);
  const [copied, setCopied] = useState(false);

  // Compute if terminal has content
  const hasOutput = useMemo(() => output.length > 0, [output]);

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

      {/* Simplified Footer */}
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

        {/* Executing command indicator */}
        {executingCommand && (
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
