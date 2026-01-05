// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Global Console Component
// Minimal, floating console bar
// Inspired by Manus.im / Modern Agentic Design
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  ChevronUp,
  ChevronDown,
  Terminal,
  AlertCircle,
  AlertTriangle,
  Info,
  Bug,
  Trash2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatTimestamp } from '@/lib/utils'
import { Button } from '@/components/ui/Button'
import { useEventStore, selectLastLog } from '@/stores/eventStore'
import type { TaskExecutionLog } from '@/types'

const logIcons = {
  debug: Bug,
  info: Info,
  warning: AlertTriangle,
  error: AlertCircle,
}

const logColors = {
  debug: 'text-text-muted-dark',
  info: 'text-royal-blue',
  warning: 'text-warning',
  error: 'text-critical',
}

export function GlobalConsole() {
  const isConsoleExpanded = useEventStore((state) => state.isConsoleExpanded)
  const toggleConsole = useEventStore((state) => state.toggleConsole)
  const logs = useEventStore((state) => state.logs)
  const clearLogs = useEventStore((state) => state.clearLogs)
  const isSidebarCollapsed = useEventStore((state) => state.isSidebarCollapsed)
  const lastLog = useEventStore(selectLastLog)
  const consoleRef = React.useRef<HTMLDivElement>(null)
  
  // Auto-scroll to bottom when new logs arrive
  React.useEffect(() => {
    if (isConsoleExpanded && consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [logs.length, isConsoleExpanded])
  
  return (
    <div
      className={cn(
        'fixed bottom-0 right-0 z-30 glass border-t border-white/5',
        'transition-all duration-300 ease-out',
        isSidebarCollapsed ? 'left-[72px]' : 'left-56',
        isConsoleExpanded ? 'h-60' : 'h-10'
      )}
    >
      {/* Header Bar - Minimal */}
      <div
        className="flex h-10 items-center justify-between px-4 cursor-pointer hover:bg-white/5 transition-colors"
        onClick={toggleConsole}
      >
        <div className="flex items-center gap-3">
          <Terminal className="h-3.5 w-3.5 text-text-muted-dark" />
          <span className="text-xs font-medium text-text-secondary-dark">Console</span>
          
          {/* Last log preview (when collapsed) */}
          {!isConsoleExpanded && lastLog && (
            <LogPreview log={lastLog} />
          )}
        </div>
        
        <div className="flex items-center gap-2">
          {logs.length > 0 && (
            <span className="text-[10px] text-text-muted-dark">
              {logs.length} logs
            </span>
          )}
          
          {isConsoleExpanded && (
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 rounded-lg hover:bg-white/5"
              onClick={(e) => {
                e.stopPropagation()
                clearLogs()
              }}
              title="Clear logs"
            >
              <Trash2 className="h-3 w-3" />
            </Button>
          )}
          
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 rounded-lg hover:bg-white/5"
            onClick={(e) => {
              e.stopPropagation()
              toggleConsole()
            }}
          >
            {isConsoleExpanded ? (
              <ChevronDown className="h-3 w-3" />
            ) : (
              <ChevronUp className="h-3 w-3" />
            )}
          </Button>
        </div>
      </div>
      
      {/* Expanded Console Content */}
      {isConsoleExpanded && (
        <div
          ref={consoleRef}
          className="h-[calc(100%-2.5rem)] overflow-y-auto font-mono text-xs px-4 py-2"
        >
          {logs.length === 0 ? (
            <div className="flex items-center justify-center h-full text-text-muted-dark">
              <span className="text-xs">Waiting for logs...</span>
            </div>
          ) : (
            <div className="space-y-0.5">
              {logs.map((log) => (
                <LogEntry key={log.id} log={log} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Log Preview (single line for collapsed state)
function LogPreview({ log }: { log: TaskExecutionLog }) {
  const Icon = logIcons[log.level]
  
  return (
    <div className="flex items-center gap-2 text-xs overflow-hidden max-w-lg ml-2">
      <Icon className={cn('h-3 w-3 flex-shrink-0', logColors[log.level])} />
      <span className="text-text-muted-dark/70 font-mono text-[10px]">
        {formatTimestamp(log.timestamp)}
      </span>
      <span className={cn('truncate text-[11px]', logColors[log.level])}>
        {log.message}
      </span>
    </div>
  )
}

// Full Log Entry (for expanded console) - Compact
function LogEntry({ log }: { log: TaskExecutionLog }) {
  const Icon = logIcons[log.level]
  
  return (
    <div className="flex items-start gap-2 py-1 hover:bg-white/5 px-2 -mx-2 rounded transition-colors">
      <Icon className={cn('h-3 w-3 flex-shrink-0 mt-0.5', logColors[log.level])} />
      
      <span className="text-text-muted-dark/60 text-[10px] flex-shrink-0 w-16">
        {formatTimestamp(log.timestamp)}
      </span>
      
      {log.specialist && (
        <span className="text-royal-blue/70 text-[10px] flex-shrink-0 w-24 truncate">
          {log.specialist}
        </span>
      )}
      
      <span className={cn('flex-1 text-[11px]', logColors[log.level])}>
        {log.message}
      </span>
    </div>
  )
}
