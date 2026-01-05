// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Terminal Panel Component
// Manus-inspired terminal display with xterm.js
// Shows command execution and output in real-time
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { Terminal as XTerminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { 
  Terminal, 
  X, 
  Maximize2, 
  Minimize2,
  Play,
  Square,
  Copy,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { motion, AnimatePresence } from 'framer-motion'
import '@xterm/xterm/css/xterm.css'

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

interface TerminalPanelProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  subtitle?: string
  command?: string
  output?: string
  isExecuting?: boolean
  className?: string
}



// ═══════════════════════════════════════════════════════════════
// Terminal Header Component
// ═══════════════════════════════════════════════════════════════

interface TerminalHeaderProps {
  title: string
  subtitle?: string
  isExecuting: boolean
  isMaximized: boolean
  onMaximize: () => void
  onClose: () => void
  onCopy: () => void
}

function TerminalHeader({ 
  title, 
  subtitle, 
  isExecuting, 
  isMaximized,
  onMaximize, 
  onClose,
  onCopy 
}: TerminalHeaderProps) {
  return (
    <div className="flex items-center justify-between px-4 py-3 bg-zinc-900 border-b border-zinc-700">
      {/* Left: Title and Status */}
      <div className="flex items-center gap-3">
        {/* Terminal Icon with Status */}
        <div className="flex items-center gap-2">
          <div className={cn(
            "p-1.5 rounded-lg",
            isExecuting ? "bg-green-500/20" : "bg-zinc-800"
          )}>
            <Terminal className={cn(
              "h-4 w-4",
              isExecuting ? "text-green-400" : "text-zinc-400"
            )} />
          </div>
          
          {/* Status Indicator */}
          <div className={cn(
            "h-2 w-2 rounded-full",
            isExecuting ? "bg-green-400 animate-pulse" : "bg-zinc-500"
          )} />
        </div>
        
        {/* Title */}
        <div>
          <h3 className="text-sm font-medium text-white">{title}</h3>
          {subtitle && (
            <p className="text-xs text-zinc-400">{subtitle}</p>
          )}
        </div>
        
        {/* Executing Badge */}
        {isExecuting && (
          <motion.span
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            className="flex items-center gap-1.5 px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded-full"
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            Executing
          </motion.span>
        )}
      </div>
      
      {/* Right: Actions */}
      <div className="flex items-center gap-1">
        <button
          onClick={onCopy}
          className="p-1.5 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors"
          title="Copy output"
        >
          <Copy className="h-4 w-4" />
        </button>
        <button
          onClick={onMaximize}
          className="p-1.5 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors"
          title={isMaximized ? "Minimize" : "Maximize"}
        >
          {isMaximized ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
        </button>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg hover:bg-red-500/20 text-zinc-400 hover:text-red-400 transition-colors"
          title="Close"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Command Line Display
// ═══════════════════════════════════════════════════════════════

interface CommandLineProps {
  command: string
  isExecuting: boolean
}

function CommandLine({ command, isExecuting }: CommandLineProps) {
  return (
    <div className="px-4 py-2 bg-zinc-800/50 border-b border-zinc-700/50">
      <div className="flex items-center gap-2 font-mono text-sm">
        <span className="text-green-400">$</span>
        <span className="text-zinc-300">{command}</span>
        {isExecuting && (
          <motion.span
            animate={{ opacity: [1, 0] }}
            transition={{ repeat: Infinity, duration: 0.8 }}
            className="text-green-400"
          >
            ▊
          </motion.span>
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Progress Bar
// ═══════════════════════════════════════════════════════════════

interface ProgressBarProps {
  isExecuting: boolean
  progress?: number
}

function ProgressBar({ isExecuting, progress = 0 }: ProgressBarProps) {
  return (
    <div className="px-4 py-2 bg-zinc-900 border-t border-zinc-700">
      <div className="flex items-center gap-3">
        {/* Controls */}
        <div className="flex items-center gap-1">
          <button className="p-1 rounded hover:bg-zinc-800 text-zinc-400">
            {isExecuting ? <Square className="h-3 w-3" /> : <Play className="h-3 w-3" />}
          </button>
        </div>
        
        {/* Progress */}
        <div className="flex-1 h-1 bg-zinc-800 rounded-full overflow-hidden">
          {isExecuting ? (
            <motion.div
              className="h-full bg-green-500"
              initial={{ x: '-100%' }}
              animate={{ x: '100%' }}
              transition={{ repeat: Infinity, duration: 1.5, ease: 'linear' }}
              style={{ width: '50%' }}
            />
          ) : (
            <div 
              className="h-full bg-green-500 transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          )}
        </div>
        
        {/* Status */}
        <span className="text-xs text-zinc-500 font-mono">
          {isExecuting ? 'running...' : 'ready'}
        </span>
        
        {/* Live indicator */}
        <div className="flex items-center gap-1">
          <span className={cn(
            "h-2 w-2 rounded-full",
            isExecuting ? "bg-green-400" : "bg-zinc-500"
          )} />
          <span className="text-xs text-zinc-400">live</span>
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Terminal Panel Component
// ═══════════════════════════════════════════════════════════════

export function TerminalPanel({
  isOpen,
  onClose,
  title = "RAGLOX Terminal",
  subtitle,
  command = "",
  output = "",
  isExecuting = false,
  className
}: TerminalPanelProps) {
  const terminalRef = React.useRef<HTMLDivElement>(null)
  const xtermRef = React.useRef<XTerminal | null>(null)
  const fitAddonRef = React.useRef<FitAddon | null>(null)
  const [isMaximized, setIsMaximized] = React.useState(false)
  
  // Initialize xterm
  React.useEffect(() => {
    if (!isOpen || !terminalRef.current) return
    
    // Create terminal instance
    const term = new XTerminal({
      theme: {
        background: '#18181b', // zinc-900
        foreground: '#e4e4e7', // zinc-200
        cursor: '#22c55e', // green-500
        cursorAccent: '#18181b',
        selectionBackground: '#3f3f46', // zinc-700
        black: '#18181b',
        red: '#ef4444',
        green: '#22c55e',
        yellow: '#eab308',
        blue: '#3b82f6',
        magenta: '#a855f7',
        cyan: '#06b6d4',
        white: '#e4e4e7',
        brightBlack: '#52525b',
        brightRed: '#f87171',
        brightGreen: '#4ade80',
        brightYellow: '#facc15',
        brightBlue: '#60a5fa',
        brightMagenta: '#c084fc',
        brightCyan: '#22d3ee',
        brightWhite: '#fafafa',
      },
      fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.4,
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: 10000,
    })
    
    // Add addons
    const fitAddon = new FitAddon()
    const webLinksAddon = new WebLinksAddon()
    
    term.loadAddon(fitAddon)
    term.loadAddon(webLinksAddon)
    
    // Open terminal
    term.open(terminalRef.current)
    fitAddon.fit()
    
    // Store refs
    xtermRef.current = term
    fitAddonRef.current = fitAddon
    
    // Cleanup
    return () => {
      term.dispose()
    }
  }, [isOpen])
  
  // Handle resize
  React.useEffect(() => {
    const handleResize = () => {
      fitAddonRef.current?.fit()
    }
    
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])
  
  // Update output
  React.useEffect(() => {
    if (xtermRef.current && output) {
      xtermRef.current.clear()
      xtermRef.current.write(output)
    }
  }, [output])
  
  // Fit on maximize change
  React.useEffect(() => {
    setTimeout(() => {
      fitAddonRef.current?.fit()
    }, 100)
  }, [isMaximized])
  
  // Copy handler
  const handleCopy = React.useCallback(() => {
    if (xtermRef.current) {
      const selection = xtermRef.current.getSelection()
      if (selection) {
        navigator.clipboard.writeText(selection)
      } else {
        navigator.clipboard.writeText(output)
      }
    }
  }, [output])
  
  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: 20 }}
          transition={{ duration: 0.2 }}
          className={cn(
            "flex flex-col bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden shadow-2xl",
            isMaximized ? "fixed inset-4 z-50" : "h-full",
            className
          )}
        >
          {/* Header */}
          <TerminalHeader
            title={title}
            subtitle={subtitle}
            isExecuting={isExecuting}
            isMaximized={isMaximized}
            onMaximize={() => setIsMaximized(!isMaximized)}
            onClose={onClose}
            onCopy={handleCopy}
          />
          
          {/* Command Line */}
          {command && (
            <CommandLine command={command} isExecuting={isExecuting} />
          )}
          
          {/* Terminal Content */}
          <div 
            ref={terminalRef}
            className="flex-1 overflow-hidden p-2"
            style={{ minHeight: 200 }}
          />
          
          {/* Progress Bar */}
          <ProgressBar isExecuting={isExecuting} />
        </motion.div>
      )}
    </AnimatePresence>
  )
}

// ═══════════════════════════════════════════════════════════════
// Simple Terminal Output (Non-interactive)
// ═══════════════════════════════════════════════════════════════

interface SimpleTerminalOutputProps {
  output: string
  command?: string
  className?: string
}

export function SimpleTerminalOutput({ output, command, className }: SimpleTerminalOutputProps) {
  return (
    <div className={cn(
      "bg-zinc-900 rounded-lg border border-zinc-700 overflow-hidden font-mono text-sm",
      className
    )}>
      {command && (
        <div className="px-3 py-2 bg-zinc-800 border-b border-zinc-700">
          <span className="text-green-400">$ </span>
          <span className="text-zinc-300">{command}</span>
        </div>
      )}
      <pre className="p-3 text-zinc-300 whitespace-pre-wrap overflow-x-auto">
        {output}
      </pre>
    </div>
  )
}

export default TerminalPanel
