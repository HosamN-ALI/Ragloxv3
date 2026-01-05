// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Event Card Component
// Manus-inspired collapsible event cards with command execution
// Shows AI reasoning, knowledge recalled, and command outputs
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  ChevronDown,
  ChevronRight,
  Terminal,
  Brain,
  BookOpen,
  CheckCircle2,
  Loader2,
  AlertTriangle,
  XCircle,
  Clock,
  Target,
  Key,
  Shield,
  Network,
  FileText,
  ExternalLink,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { motion, AnimatePresence } from 'framer-motion'
import { SimpleTerminalOutput } from './TerminalPanel'

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

export type EventStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'awaiting'
export type EventType = 
  | 'command_execution' 
  | 'knowledge_recall' 
  | 'ai_reasoning' 
  | 'target_discovered'
  | 'vuln_found'
  | 'credential_harvested'
  | 'session_established'
  | 'approval_required'
  | 'goal_achieved'
  | 'error'

export interface KnowledgeItem {
  id: string
  title: string
  source?: string
  relevance?: number
}

export interface CommandExecution {
  command: string
  output?: string
  exitCode?: number
  duration?: number
}

export interface EventCardData {
  id: string
  type: EventType
  title: string
  description?: string
  status: EventStatus
  timestamp: string
  // Optional nested data
  knowledgeRecalled?: KnowledgeItem[]
  commandExecution?: CommandExecution
  aiReasoning?: string
  metadata?: Record<string, unknown>
}

interface EventCardProps {
  event: EventCardData
  defaultExpanded?: boolean
  onTerminalClick?: (command: string, output?: string) => void
  className?: string
}

// ═══════════════════════════════════════════════════════════════
// Event Type Configuration
// ═══════════════════════════════════════════════════════════════

interface EventTypeConfig {
  icon: React.ElementType
  color: string
  bgColor: string
  label: string
}

const eventTypeConfig: Record<EventType, EventTypeConfig> = {
  command_execution: { 
    icon: Terminal, 
    color: 'text-green-400', 
    bgColor: 'bg-green-500/10',
    label: 'Executing command'
  },
  knowledge_recall: { 
    icon: BookOpen, 
    color: 'text-yellow-400', 
    bgColor: 'bg-yellow-500/10',
    label: 'Knowledge recalled'
  },
  ai_reasoning: { 
    icon: Brain, 
    color: 'text-purple-400', 
    bgColor: 'bg-purple-500/10',
    label: 'AI Analysis'
  },
  target_discovered: { 
    icon: Target, 
    color: 'text-blue-400', 
    bgColor: 'bg-blue-500/10',
    label: 'Target discovered'
  },
  vuln_found: { 
    icon: AlertTriangle, 
    color: 'text-orange-400', 
    bgColor: 'bg-orange-500/10',
    label: 'Vulnerability found'
  },
  credential_harvested: { 
    icon: Key, 
    color: 'text-yellow-400', 
    bgColor: 'bg-yellow-500/10',
    label: 'Credential harvested'
  },
  session_established: { 
    icon: Network, 
    color: 'text-green-400', 
    bgColor: 'bg-green-500/10',
    label: 'Session established'
  },
  approval_required: { 
    icon: Shield, 
    color: 'text-amber-400', 
    bgColor: 'bg-amber-500/10',
    label: 'Approval required'
  },
  goal_achieved: { 
    icon: CheckCircle2, 
    color: 'text-emerald-400', 
    bgColor: 'bg-emerald-500/10',
    label: 'Goal achieved'
  },
  error: { 
    icon: XCircle, 
    color: 'text-red-400', 
    bgColor: 'bg-red-500/10',
    label: 'Error'
  },
}

// ═══════════════════════════════════════════════════════════════
// Status Icon Component
// ═══════════════════════════════════════════════════════════════

function StatusIndicator({ status }: { status: EventStatus }) {
  switch (status) {
    case 'completed':
      return <CheckCircle2 className="h-4 w-4 text-green-400" />
    case 'in_progress':
      return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
    case 'pending':
      return <Clock className="h-4 w-4 text-zinc-500" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-400" />
    case 'awaiting':
      return <Clock className="h-4 w-4 text-amber-400 animate-pulse" />
    default:
      return null
  }
}

// ═══════════════════════════════════════════════════════════════
// Knowledge Recalled Section
// ═══════════════════════════════════════════════════════════════

interface KnowledgeRecalledProps {
  items: KnowledgeItem[]
  isExpanded: boolean
  onToggle: () => void
}

function KnowledgeRecalled({ items, isExpanded, onToggle }: KnowledgeRecalledProps) {
  return (
    <div className="mt-2">
      <button
        onClick={(e) => {
          e.stopPropagation()
          onToggle()
        }}
        className="flex items-center gap-2 text-xs text-yellow-400 hover:text-yellow-300 transition-colors"
      >
        <BookOpen className="h-3.5 w-3.5" />
        <span>Knowledge recalled({items.length})</span>
        {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
      </button>
      
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="mt-2 pl-5 space-y-1">
              {items.map((item) => (
                <div 
                  key={item.id}
                  className="flex items-center gap-2 py-1 px-2 rounded bg-yellow-500/5 border border-yellow-500/20 text-xs"
                >
                  <FileText className="h-3 w-3 text-yellow-400" />
                  <span className="text-yellow-200">{item.title}</span>
                  {item.source && (
                    <span className="text-zinc-500">• {item.source}</span>
                  )}
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Command Execution Badge
// ═══════════════════════════════════════════════════════════════

interface CommandBadgeProps {
  command: string
  isExecuting: boolean
  onClick?: () => void
}

function CommandBadge({ command, isExecuting, onClick }: CommandBadgeProps) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onClick?.()
      }}
      className={cn(
        "flex items-center gap-2 mt-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-all",
        "bg-zinc-800 border border-zinc-700 hover:border-zinc-600",
        "text-zinc-300 hover:text-white",
        onClick && "cursor-pointer hover:bg-zinc-700"
      )}
    >
      <Terminal className={cn(
        "h-3.5 w-3.5",
        isExecuting ? "text-green-400" : "text-zinc-400"
      )} />
      <span className="text-green-400">$</span>
      <span className="truncate max-w-[200px]">{command}</span>
      {onClick && (
        <ExternalLink className="h-3 w-3 text-zinc-500" />
      )}
    </button>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Event Card Component
// ═══════════════════════════════════════════════════════════════

export function EventCard({ 
  event, 
  defaultExpanded = false,
  onTerminalClick,
  className 
}: EventCardProps) {
  const [isExpanded, setIsExpanded] = React.useState(defaultExpanded)
  const [isKnowledgeExpanded, setIsKnowledgeExpanded] = React.useState(false)
  
  const config = eventTypeConfig[event.type]
  const Icon = config.icon
  const hasContent = event.description || event.commandExecution || event.aiReasoning || event.knowledgeRecalled?.length
  
  const formatTimestamp = (ts: string) => {
    try {
      const date = new Date(ts)
      return date.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        hour12: false 
      })
    } catch {
      return ts
    }
  }
  
  return (
    <motion.div
      layout
      className={cn(
        "rounded-xl border transition-all duration-200",
        event.status === 'awaiting' && "border-amber-500/50 bg-amber-500/5",
        event.status === 'in_progress' && "border-blue-500/50 bg-blue-500/5",
        event.status !== 'awaiting' && event.status !== 'in_progress' && "border-zinc-800 bg-zinc-900/50 hover:bg-zinc-900/80",
        className
      )}
    >
      {/* Header - Always visible */}
      <button
        onClick={() => hasContent && setIsExpanded(!isExpanded)}
        className="w-full text-left p-4"
        disabled={!hasContent}
      >
        <div className="flex items-start gap-3">
          {/* Status Icon */}
          <div className="flex-shrink-0 mt-0.5">
            <StatusIndicator status={event.status} />
          </div>
          
          {/* Content */}
          <div className="flex-1 min-w-0">
            {/* Title Row */}
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="text-sm font-medium text-white">
                {event.title}
              </h4>
              
              {/* Event Type Badge */}
              <span className={cn(
                "flex items-center gap-1 px-2 py-0.5 rounded-full text-xs",
                config.bgColor, config.color
              )}>
                <Icon className="h-3 w-3" />
                {config.label}
              </span>
            </div>
            
            {/* Preview Description (collapsed state) */}
            {!isExpanded && event.description && (
              <p className="mt-1 text-xs text-zinc-400 line-clamp-2">
                {event.description}
              </p>
            )}
            
            {/* Command Badge (always visible if exists) */}
            {event.commandExecution && (
              <CommandBadge
                command={event.commandExecution.command}
                isExecuting={event.status === 'in_progress'}
                onClick={onTerminalClick ? () => onTerminalClick(
                  event.commandExecution!.command,
                  event.commandExecution!.output
                ) : undefined}
              />
            )}
            
            {/* Knowledge Recalled Badge (collapsible) */}
            {event.knowledgeRecalled && event.knowledgeRecalled.length > 0 && (
              <KnowledgeRecalled
                items={event.knowledgeRecalled}
                isExpanded={isKnowledgeExpanded}
                onToggle={() => setIsKnowledgeExpanded(!isKnowledgeExpanded)}
              />
            )}
          </div>
          
          {/* Timestamp and Expand */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className="text-xs text-zinc-500 font-mono">
              {formatTimestamp(event.timestamp)}
            </span>
            {hasContent && (
              <div className="text-zinc-500">
                {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              </div>
            )}
          </div>
        </div>
      </button>
      
      {/* Expanded Content */}
      <AnimatePresence>
        {isExpanded && hasContent && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-3">
              {/* Full Description */}
              {event.description && (
                <p className="text-sm text-zinc-300 pl-7">
                  {event.description}
                </p>
              )}
              
              {/* AI Reasoning */}
              {event.aiReasoning && (
                <div className="pl-7">
                  <div className="flex items-center gap-2 mb-2">
                    <Brain className="h-3.5 w-3.5 text-purple-400" />
                    <span className="text-xs text-purple-400 font-medium">AI Reasoning</span>
                  </div>
                  <p className="text-xs text-zinc-400 bg-purple-500/5 border border-purple-500/20 rounded-lg p-3">
                    {event.aiReasoning}
                  </p>
                </div>
              )}
              
              {/* Command Output */}
              {event.commandExecution?.output && (
                <div className="pl-7">
                  <SimpleTerminalOutput
                    command={event.commandExecution.command}
                    output={event.commandExecution.output}
                  />
                </div>
              )}
              
              {/* Metadata */}
              {event.metadata && Object.keys(event.metadata).length > 0 && (
                <div className="pl-7">
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    {Object.entries(event.metadata).map(([key, value]) => 
                      value ? (
                        <div key={key} className="flex flex-col">
                          <span className="text-zinc-500 uppercase text-[10px] tracking-wider">
                            {key.replace(/_/g, ' ')}
                          </span>
                          <span className="text-zinc-300 font-mono truncate">
                            {String(value)}
                          </span>
                        </div>
                      ) : null
                    )}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Event List Component
// ═══════════════════════════════════════════════════════════════

interface EventListProps {
  events: EventCardData[]
  onTerminalClick?: (command: string, output?: string) => void
  className?: string
}

export function EventList({ events, onTerminalClick, className }: EventListProps) {
  return (
    <div className={cn("space-y-2", className)}>
      {events.map((event, index) => (
        <EventCard
          key={event.id}
          event={event}
          defaultExpanded={index === 0 && event.status === 'in_progress'}
          onTerminalClick={onTerminalClick}
        />
      ))}
    </div>
  )
}

export default EventCard
