// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Session Terminal Component
// Interactive shell access for Loot & Access workspace
// Design: Focused xterm.js window with professional styling
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { useEffect, useRef, useCallback } from 'react'
import {
  Terminal as TerminalIcon,
  Maximize2,
  Minimize2,
  X,
  Copy,
  Trash2,
  Power,
  User,
  Server,
  Clock,
  Activity,
  Zap,
} from 'lucide-react'
import { Terminal } from '@xterm/xterm'
import { cn } from '@/lib/utils'
import type { Session, SessionType, SessionStatus } from '@/types'

// ═══════════════════════════════════════════════════════════════
// Session Type Configuration
// ═══════════════════════════════════════════════════════════════

interface SessionTypeConfig {
  color: string
  bgColor: string
  icon: React.ElementType
  label: string
}

const sessionTypeConfig: Record<SessionType, SessionTypeConfig> = {
  shell: { color: 'text-green-400', bgColor: 'bg-green-500/10', icon: TerminalIcon, label: 'Shell' },
  meterpreter: { color: 'text-red-400', bgColor: 'bg-red-500/10', icon: Zap, label: 'Meterpreter' },
  ssh: { color: 'text-blue-400', bgColor: 'bg-blue-500/10', icon: TerminalIcon, label: 'SSH' },
  rdp: { color: 'text-purple-400', bgColor: 'bg-purple-500/10', icon: Server, label: 'RDP' },
  wmi: { color: 'text-orange-400', bgColor: 'bg-orange-500/10', icon: Server, label: 'WMI' },
  winrm: { color: 'text-cyan-400', bgColor: 'bg-cyan-500/10', icon: Server, label: 'WinRM' },
  smb: { color: 'text-yellow-400', bgColor: 'bg-yellow-500/10', icon: Server, label: 'SMB' },
}

// ═══════════════════════════════════════════════════════════════
// Session Status Configuration
// ═══════════════════════════════════════════════════════════════

const sessionStatusConfig: Record<SessionStatus, { color: string; pulse: boolean }> = {
  active: { color: 'bg-green-500', pulse: false },
  idle: { color: 'bg-yellow-500', pulse: true },
  dead: { color: 'bg-red-500', pulse: false },
}

// ═══════════════════════════════════════════════════════════════
// Session Status Indicator
// ═══════════════════════════════════════════════════════════════

function SessionStatusIndicator({ status }: { status: SessionStatus }) {
  const config = sessionStatusConfig[status]
  
  return (
    <div className="relative">
      <div className={cn('w-2 h-2 rounded-full', config.color)} />
      {config.pulse && (
        <div className={cn('absolute inset-0 w-2 h-2 rounded-full animate-ping', config.color, 'opacity-75')} />
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Session Card for List View
// ═══════════════════════════════════════════════════════════════

interface SessionCardProps {
  session: Session
  isActive: boolean
  onSelect: () => void
}

function SessionCard({ session, isActive, onSelect }: SessionCardProps) {
  const typeConfig = sessionTypeConfig[session.type]
  const TypeIcon = typeConfig.icon
  
  const formatTime = (ts: string) => {
    const date = new Date(ts)
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
  }
  
  return (
    <button
      onClick={onSelect}
      className={cn(
        'w-full p-3 rounded-xl border transition-all text-left',
        'hover:bg-zinc-800/50',
        isActive
          ? 'border-royal-blue bg-royal-blue/5 ring-1 ring-royal-blue/50'
          : 'border-zinc-800 bg-zinc-900/50'
      )}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <div className={cn('p-1.5 rounded-lg', typeConfig.bgColor)}>
            <TypeIcon className={cn('h-4 w-4', typeConfig.color)} />
          </div>
          <span className="text-sm font-semibold text-text-primary-dark">
            {typeConfig.label}
          </span>
        </div>
        <SessionStatusIndicator status={session.status} />
      </div>
      
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs">
          <User className="h-3 w-3 text-text-muted-dark" />
          <span className="text-text-secondary-dark font-mono">
            {session.user || 'unknown'}
          </span>
          <span className={cn(
            'px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase',
            session.privilege === 'root' || session.privilege === 'SYSTEM'
              ? 'bg-red-500/20 text-red-400'
              : 'bg-blue-500/20 text-blue-400'
          )}>
            {session.privilege}
          </span>
        </div>
        
        <div className="flex items-center gap-2 text-xs text-text-muted-dark">
          <Server className="h-3 w-3" />
          <span className="font-mono truncate">{session.target_id}</span>
        </div>
        
        <div className="flex items-center gap-2 text-xs text-text-muted-dark">
          <Clock className="h-3 w-3" />
          <span>Est. {formatTime(session.established_at)}</span>
          <Activity className="h-3 w-3 ml-2" />
          <span>Act. {formatTime(session.last_activity)}</span>
        </div>
      </div>
    </button>
  )
}

// ═══════════════════════════════════════════════════════════════
// Terminal Header Component
// ═══════════════════════════════════════════════════════════════

interface TerminalHeaderProps {
  session: Session
  isMaximized: boolean
  onToggleMaximize: () => void
  onClose: () => void
  onKill: () => void
  onCopy: () => void
  onClear: () => void
}

function TerminalHeader({
  session,
  isMaximized,
  onToggleMaximize,
  onClose,
  onKill,
  onCopy,
  onClear,
}: TerminalHeaderProps) {
  const typeConfig = sessionTypeConfig[session.type]
  const TypeIcon = typeConfig.icon
  
  return (
    <div className="flex items-center justify-between px-4 py-2 bg-zinc-800 border-b border-zinc-700">
      <div className="flex items-center gap-3">
        <div className={cn('p-1.5 rounded-lg', typeConfig.bgColor)}>
          <TypeIcon className={cn('h-4 w-4', typeConfig.color)} />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-text-primary-dark">
              {session.user || 'shell'}@{session.target_id.slice(0, 8)}
            </span>
            <span className={cn(
              'px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase',
              session.privilege === 'root' || session.privilege === 'SYSTEM'
                ? 'bg-red-500/20 text-red-400'
                : 'bg-blue-500/20 text-blue-400'
            )}>
              {session.privilege}
            </span>
            <SessionStatusIndicator status={session.status} />
          </div>
          <span className="text-xs text-text-muted-dark font-mono">
            Session: {session.session_id.slice(0, 12)}...
          </span>
        </div>
      </div>
      
      <div className="flex items-center gap-1">
        <button
          onClick={onCopy}
          className="p-1.5 rounded hover:bg-zinc-700 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
          title="Copy Output"
        >
          <Copy className="h-4 w-4" />
        </button>
        <button
          onClick={onClear}
          className="p-1.5 rounded hover:bg-zinc-700 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
          title="Clear Terminal"
        >
          <Trash2 className="h-4 w-4" />
        </button>
        <button
          onClick={onToggleMaximize}
          className="p-1.5 rounded hover:bg-zinc-700 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
          title={isMaximized ? 'Restore' : 'Maximize'}
        >
          {isMaximized ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
        </button>
        <button
          onClick={onKill}
          className="p-1.5 rounded hover:bg-red-500/20 text-text-muted-dark hover:text-red-400 transition-colors"
          title="Kill Session"
        >
          <Power className="h-4 w-4" />
        </button>
        <button
          onClick={onClose}
          className="p-1.5 rounded hover:bg-zinc-700 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
          title="Close Window"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Terminal Component
// ═══════════════════════════════════════════════════════════════

interface SessionTerminalWindowProps {
  session: Session
  isMaximized?: boolean
  onToggleMaximize?: () => void
  onClose?: () => void
  onKill?: () => void
  onCommand?: (command: string) => void
}

export function SessionTerminalWindow({
  session,
  isMaximized = false,
  onToggleMaximize,
  onClose,
  onKill,
  onCommand,
}: SessionTerminalWindowProps) {
  const terminalRef = useRef<HTMLDivElement>(null)
  const terminalInstance = useRef<Terminal | null>(null)
  const inputBuffer = useRef<string>('')
  
  // Initialize terminal
  useEffect(() => {
    if (!terminalRef.current) return
    
    // Clean up existing terminal
    if (terminalInstance.current) {
      terminalInstance.current.dispose()
    }
    
    // Create new terminal with professional styling
    const term = new Terminal({
      theme: {
        background: '#0f0f0f',
        foreground: '#e4e4e7',
        cursor: '#3b82f6',
        cursorAccent: '#0f0f0f',
        selectionBackground: '#3b82f6',
        selectionForeground: '#ffffff',
        black: '#18181b',
        red: '#f87171',
        green: '#4ade80',
        yellow: '#facc15',
        blue: '#60a5fa',
        magenta: '#c084fc',
        cyan: '#22d3ee',
        white: '#e4e4e7',
        brightBlack: '#3f3f46',
        brightRed: '#fca5a5',
        brightGreen: '#86efac',
        brightYellow: '#fde047',
        brightBlue: '#93c5fd',
        brightMagenta: '#d8b4fe',
        brightCyan: '#67e8f9',
        brightWhite: '#fafafa',
      },
      fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.2,
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: 5000,
    })
    
    term.open(terminalRef.current)
    terminalInstance.current = term
    
    // Write welcome message
    const typeConfig = sessionTypeConfig[session.type]
    term.writeln('')
    term.writeln(`\x1b[36m╔═══════════════════════════════════════════════════════════╗\x1b[0m`)
    term.writeln(`\x1b[36m║\x1b[0m  RAGLOX v3.0 - ${typeConfig.label} Session                       \x1b[36m║\x1b[0m`)
    term.writeln(`\x1b[36m╚═══════════════════════════════════════════════════════════╝\x1b[0m`)
    term.writeln('')
    term.writeln(`\x1b[33mSession ID:\x1b[0m ${session.session_id}`)
    term.writeln(`\x1b[33mUser:\x1b[0m       ${session.user || 'unknown'} (\x1b[${session.privilege === 'root' ? '31' : '34'}m${session.privilege}\x1b[0m)`)
    term.writeln(`\x1b[33mTarget:\x1b[0m     ${session.target_id}`)
    term.writeln(`\x1b[33mType:\x1b[0m       ${session.type.toUpperCase()}`)
    term.writeln(`\x1b[33mStatus:\x1b[0m     \x1b[32m${session.status}\x1b[0m`)
    term.writeln('')
    term.writeln(`\x1b[90mType commands below. Use Ctrl+C to interrupt.\x1b[0m`)
    term.writeln('')
    
    // Write initial prompt
    const prompt = session.privilege === 'root' || session.privilege === 'SYSTEM'
      ? `\x1b[31m${session.user || 'root'}@target\x1b[0m:\x1b[34m~\x1b[0m# `
      : `\x1b[32m${session.user || 'user'}@target\x1b[0m:\x1b[34m~\x1b[0m$ `
    term.write(prompt)
    
    // Handle key input
    term.onKey(({ key, domEvent }) => {
      const printable = !domEvent.altKey && !domEvent.ctrlKey && !domEvent.metaKey
      
      if (domEvent.key === 'Enter') {
        term.writeln('')
        if (inputBuffer.current.trim()) {
          // Execute command
          const command = inputBuffer.current.trim()
          onCommand?.(command)
          
          // Simulate command output (in real app, this comes from backend)
          simulateCommandOutput(term, command, session)
        }
        inputBuffer.current = ''
        term.write(prompt)
      } else if (domEvent.key === 'Backspace') {
        if (inputBuffer.current.length > 0) {
          inputBuffer.current = inputBuffer.current.slice(0, -1)
          term.write('\b \b')
        }
      } else if (domEvent.ctrlKey && domEvent.key === 'c') {
        term.writeln('^C')
        inputBuffer.current = ''
        term.write(prompt)
      } else if (domEvent.ctrlKey && domEvent.key === 'l') {
        term.clear()
        term.write(prompt)
      } else if (printable) {
        inputBuffer.current += key
        term.write(key)
      }
    })
    
    // Fit terminal to container
    const fitTerminal = () => {
      // Simple resize - in production use xterm-addon-fit
      term.resize(Math.floor(terminalRef.current!.offsetWidth / 9), Math.floor((terminalRef.current!.offsetHeight - 8) / 17))
    }
    
    fitTerminal()
    window.addEventListener('resize', fitTerminal)
    
    return () => {
      window.removeEventListener('resize', fitTerminal)
      term.dispose()
    }
  }, [session])
  
  const handleCopy = useCallback(() => {
    if (terminalInstance.current) {
      const selection = terminalInstance.current.getSelection()
      if (selection) {
        navigator.clipboard.writeText(selection)
      }
    }
  }, [])
  
  const handleClear = useCallback(() => {
    terminalInstance.current?.clear()
  }, [])
  
  return (
    <div className={cn(
      'flex flex-col rounded-xl border border-zinc-700 overflow-hidden',
      isMaximized ? 'fixed inset-4 z-50' : 'h-full'
    )}>
      <TerminalHeader
        session={session}
        isMaximized={isMaximized}
        onToggleMaximize={onToggleMaximize || (() => {})}
        onClose={onClose || (() => {})}
        onKill={onKill || (() => {})}
        onCopy={handleCopy}
        onClear={handleClear}
      />
      <div 
        ref={terminalRef} 
        className="flex-1 bg-[#0f0f0f] p-2 overflow-hidden"
        style={{ minHeight: '300px' }}
      />
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Simulate Command Output (Demo purposes)
// ═══════════════════════════════════════════════════════════════

function simulateCommandOutput(term: Terminal, command: string, session: Session) {
  const cmd = command.toLowerCase().trim()
  
  if (cmd === 'whoami') {
    term.writeln(session.user || 'unknown')
  } else if (cmd === 'id') {
    if (session.privilege === 'root') {
      term.writeln('uid=0(root) gid=0(root) groups=0(root)')
    } else {
      term.writeln(`uid=1000(${session.user}) gid=1000(${session.user}) groups=1000(${session.user}),4(adm),24(cdrom)`)
    }
  } else if (cmd === 'pwd') {
    term.writeln(session.privilege === 'root' ? '/root' : `/home/${session.user || 'user'}`)
  } else if (cmd === 'ls' || cmd === 'ls -la') {
    term.writeln('total 32')
    term.writeln('drwxr-xr-x  5 user user 4096 Jan  2 12:00 .')
    term.writeln('drwxr-xr-x  3 root root 4096 Jan  1 00:00 ..')
    term.writeln('-rw-------  1 user user  220 Jan  1 00:00 .bash_history')
    term.writeln('-rw-r--r--  1 user user 3771 Jan  1 00:00 .bashrc')
    term.writeln('\x1b[33m-rw-r--r--  1 user user   64 Jan  2 10:30 .db_creds\x1b[0m')
    term.writeln('drwx------  2 user user 4096 Jan  2 08:00 .ssh')
  } else if (cmd === 'cat .db_creds' || cmd === 'cat ~/.db_creds') {
    term.writeln('\x1b[32mDB_USER=dbadmin\x1b[0m')
    term.writeln('\x1b[32mDB_PASS=super_secret_db_password\x1b[0m')
  } else if (cmd === 'uname -a') {
    term.writeln('Linux vulnerable-target 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux')
  } else if (cmd === 'cat /etc/passwd') {
    term.writeln('root:x:0:0:root:/root:/bin/bash')
    term.writeln('testuser:x:1000:1000:Test User:/home/testuser:/bin/bash')
    term.writeln('admin:x:1001:1001:Admin User:/home/admin:/bin/bash')
    term.writeln('backup:x:1002:1002:Backup User:/home/backup:/bin/bash')
  } else if (cmd === 'help') {
    term.writeln('\x1b[36mAvailable demo commands:\x1b[0m')
    term.writeln('  whoami        - Print current user')
    term.writeln('  id            - Print user ID info')
    term.writeln('  pwd           - Print working directory')
    term.writeln('  ls [-la]      - List files')
    term.writeln('  cat <file>    - Display file contents')
    term.writeln('  uname -a      - System information')
    term.writeln('  cat /etc/passwd - User accounts')
    term.writeln('  clear / Ctrl+L - Clear terminal')
  } else if (cmd === '' || cmd === 'clear') {
    // Do nothing for empty command
  } else {
    term.writeln(`\x1b[31mCommand not found: ${command}\x1b[0m`)
    term.writeln('\x1b[90mType "help" for available commands\x1b[0m')
  }
}

// ═══════════════════════════════════════════════════════════════
// Session Manager Component (List + Terminal)
// ═══════════════════════════════════════════════════════════════

export interface SessionManagerProps {
  sessions: Session[]
  onKillSession?: (sessionId: string) => void
  onCommand?: (sessionId: string, command: string) => void
}

export function SessionManager({ sessions, onKillSession, onCommand }: SessionManagerProps) {
  const [activeSessionId, setActiveSessionId] = React.useState<string | null>(
    sessions.length > 0 ? sessions[0].session_id : null
  )
  const [isTerminalMaximized, setIsTerminalMaximized] = React.useState(false)
  
  const activeSession = sessions.find(s => s.session_id === activeSessionId)
  
  // Update active session if current one is removed
  useEffect(() => {
    if (activeSessionId && !sessions.find(s => s.session_id === activeSessionId)) {
      setActiveSessionId(sessions.length > 0 ? sessions[0].session_id : null)
    }
  }, [sessions, activeSessionId])
  
  if (sessions.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <TerminalIcon className="h-12 w-12 text-text-muted-dark mb-4" />
        <h3 className="text-lg font-medium text-text-secondary-dark mb-2">
          No Active Sessions
        </h3>
        <p className="text-sm text-text-muted-dark max-w-md">
          Exploit a target to establish an interactive session.
        </p>
      </div>
    )
  }
  
  return (
    <div className="flex h-full gap-4">
      {/* Session List */}
      <div className={cn(
        'w-72 flex-shrink-0 space-y-2 overflow-y-auto pr-2',
        'scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-transparent',
        isTerminalMaximized && 'hidden'
      )}>
        <h3 className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider mb-3">
          Active Sessions ({sessions.length})
        </h3>
        {sessions.map(session => (
          <SessionCard
            key={session.session_id}
            session={session}
            isActive={session.session_id === activeSessionId}
            onSelect={() => setActiveSessionId(session.session_id)}
          />
        ))}
      </div>
      
      {/* Terminal Window */}
      <div className="flex-1 min-w-0">
        {activeSession ? (
          <SessionTerminalWindow
            session={activeSession}
            isMaximized={isTerminalMaximized}
            onToggleMaximize={() => setIsTerminalMaximized(!isTerminalMaximized)}
            onClose={() => setActiveSessionId(null)}
            onKill={() => {
              onKillSession?.(activeSession.session_id)
              setActiveSessionId(null)
            }}
            onCommand={(cmd) => onCommand?.(activeSession.session_id, cmd)}
          />
        ) : (
          <div className="flex items-center justify-center h-full bg-zinc-900/30 rounded-xl border border-zinc-800">
            <p className="text-text-muted-dark">Select a session to open terminal</p>
          </div>
        )}
      </div>
    </div>
  )
}

export default SessionManager
