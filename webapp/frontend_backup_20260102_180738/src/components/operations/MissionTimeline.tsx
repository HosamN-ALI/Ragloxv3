// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Mission Timeline Component
// Structured progress visualization for Active Operations workspace
// Design: Palantir-inspired, replaces chaotic logs with organized timeline
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  CheckCircle2,
  Circle,
  Clock,
  AlertTriangle,
  XCircle,
  Loader2,
  Shield,
  Target,
  Network,
  Key,
  Terminal,
  FileSearch,
  Crosshair,
  Zap,
  ChevronDown,
  ChevronRight,
  Eye,
  FileText,
  ArrowRight,
  Filter,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useMissionStore, type TimelineEvent, type TimelineEventType, type MissionPhase } from '@/stores/missionStore'

// ═══════════════════════════════════════════════════════════════
// Event Type Configuration
// ═══════════════════════════════════════════════════════════════

interface EventTypeConfig {
  icon: React.ElementType
  color: string
  bgColor: string
  borderColor: string
}

const eventTypeConfig: Record<TimelineEventType, EventTypeConfig> = {
  phase_start: { icon: Zap, color: 'text-cyan-400', bgColor: 'bg-cyan-500/10', borderColor: 'border-cyan-500/30' },
  phase_complete: { icon: CheckCircle2, color: 'text-green-400', bgColor: 'bg-green-500/10', borderColor: 'border-green-500/30' },
  target_discovered: { icon: Target, color: 'text-blue-400', bgColor: 'bg-blue-500/10', borderColor: 'border-blue-500/30' },
  port_discovered: { icon: Network, color: 'text-blue-300', bgColor: 'bg-blue-500/10', borderColor: 'border-blue-500/30' },
  vuln_found: { icon: AlertTriangle, color: 'text-orange-400', bgColor: 'bg-orange-500/10', borderColor: 'border-orange-500/30' },
  exploit_attempt: { icon: Crosshair, color: 'text-yellow-400', bgColor: 'bg-yellow-500/10', borderColor: 'border-yellow-500/30' },
  exploit_success: { icon: CheckCircle2, color: 'text-green-400', bgColor: 'bg-green-500/10', borderColor: 'border-green-500/30' },
  exploit_failed: { icon: XCircle, color: 'text-red-400', bgColor: 'bg-red-500/10', borderColor: 'border-red-500/30' },
  session_established: { icon: Terminal, color: 'text-green-400', bgColor: 'bg-green-500/10', borderColor: 'border-green-500/30' },
  credential_harvested: { icon: Key, color: 'text-yellow-400', bgColor: 'bg-yellow-500/10', borderColor: 'border-yellow-500/30' },
  file_extracted: { icon: FileText, color: 'text-purple-400', bgColor: 'bg-purple-500/10', borderColor: 'border-purple-500/30' },
  lateral_movement: { icon: ArrowRight, color: 'text-blue-400', bgColor: 'bg-blue-500/10', borderColor: 'border-blue-500/30' },
  approval_required: { icon: Shield, color: 'text-amber-400', bgColor: 'bg-amber-500/10', borderColor: 'border-amber-500/30' },
  approval_granted: { icon: CheckCircle2, color: 'text-green-400', bgColor: 'bg-green-500/10', borderColor: 'border-green-500/30' },
  approval_denied: { icon: XCircle, color: 'text-red-400', bgColor: 'bg-red-500/10', borderColor: 'border-red-500/30' },
  goal_achieved: { icon: CheckCircle2, color: 'text-emerald-400', bgColor: 'bg-emerald-500/10', borderColor: 'border-emerald-500/30' },
  error: { icon: XCircle, color: 'text-red-400', bgColor: 'bg-red-500/10', borderColor: 'border-red-500/30' },
}

// ═══════════════════════════════════════════════════════════════
// Status Icon Component
// ═══════════════════════════════════════════════════════════════

function StatusIcon({ status }: { status: TimelineEvent['status'] }) {
  switch (status) {
    case 'completed':
      return <CheckCircle2 className="h-4 w-4 text-green-400" />
    case 'in_progress':
      return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
    case 'pending':
      return <Circle className="h-4 w-4 text-zinc-500" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-400" />
    case 'awaiting':
      return <Clock className="h-4 w-4 text-amber-400 animate-pulse" />
    default:
      return <Circle className="h-4 w-4 text-zinc-500" />
  }
}

// ═══════════════════════════════════════════════════════════════
// Phase Badge Component
// ═══════════════════════════════════════════════════════════════

const phaseConfig: Record<MissionPhase, { label: string; color: string }> = {
  setup: { label: 'Setup', color: 'bg-zinc-500/20 text-zinc-400' },
  reconnaissance: { label: 'Recon', color: 'bg-blue-500/20 text-blue-400' },
  enumeration: { label: 'Enum', color: 'bg-cyan-500/20 text-cyan-400' },
  exploitation: { label: 'Exploit', color: 'bg-orange-500/20 text-orange-400' },
  post_exploitation: { label: 'Post-Ex', color: 'bg-purple-500/20 text-purple-400' },
  completed: { label: 'Done', color: 'bg-green-500/20 text-green-400' },
  aborted: { label: 'Aborted', color: 'bg-red-500/20 text-red-400' },
}

function PhaseBadge({ phase }: { phase: MissionPhase }) {
  const config = phaseConfig[phase]
  return (
    <span className={cn(
      'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider',
      config.color
    )}>
      {config.label}
    </span>
  )
}

// ═══════════════════════════════════════════════════════════════
// Timeline Event Item Component
// ═══════════════════════════════════════════════════════════════

interface TimelineEventItemProps {
  event: TimelineEvent
  isLast: boolean
  expanded: boolean
  onToggle: () => void
}

function TimelineEventItem({ event, isLast, expanded, onToggle }: TimelineEventItemProps) {
  const config = eventTypeConfig[event.type]
  const Icon = config.icon
  const hasMetadata = event.metadata && Object.keys(event.metadata).length > 0
  
  const formatTimestamp = (ts: string) => {
    const date = new Date(ts)
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit',
      hour12: false 
    })
  }
  
  return (
    <div className="relative group">
      {/* Vertical Line Connector */}
      {!isLast && (
        <div className={cn(
          'absolute left-[19px] top-10 w-0.5 h-full -translate-x-1/2',
          event.status === 'completed' ? 'bg-zinc-700' : 'bg-zinc-800'
        )} />
      )}
      
      {/* Event Card */}
      <div 
        className={cn(
          'relative flex gap-4 p-3 rounded-xl transition-all duration-200',
          'hover:bg-zinc-800/50',
          event.status === 'awaiting' && 'ring-1 ring-amber-500/50 bg-amber-500/5',
          event.status === 'in_progress' && 'ring-1 ring-blue-500/50 bg-blue-500/5'
        )}
      >
        {/* Event Icon */}
        <div className={cn(
          'relative z-10 flex-shrink-0 flex items-center justify-center w-10 h-10 rounded-xl border',
          config.bgColor,
          config.borderColor
        )}>
          <Icon className={cn('h-5 w-5', config.color)} />
        </div>
        
        {/* Event Content */}
        <div className="flex-1 min-w-0">
          {/* Header */}
          <div className="flex items-center gap-2 mb-1">
            <StatusIcon status={event.status} />
            <h4 className="text-sm font-semibold text-text-primary-dark truncate">
              {event.title}
            </h4>
            <PhaseBadge phase={event.phase} />
          </div>
          
          {/* Description */}
          <p className="text-xs text-text-secondary-dark mb-2 line-clamp-2">
            {event.description}
          </p>
          
          {/* Metadata (expandable) */}
          {hasMetadata && (
            <button
              onClick={onToggle}
              className="flex items-center gap-1 text-xs text-text-muted-dark hover:text-text-secondary-dark transition-colors"
            >
              {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              <Eye className="h-3 w-3" />
              <span>Details</span>
            </button>
          )}
          
          {expanded && hasMetadata && (
            <div className="mt-2 p-2 rounded-lg bg-zinc-800/80 border border-zinc-700">
              <div className="grid grid-cols-2 gap-2 text-xs">
                {Object.entries(event.metadata!).map(([key, value]) => (
                  value && (
                    <div key={key} className="flex flex-col">
                      <span className="text-text-muted-dark uppercase text-[10px] tracking-wider">
                        {key.replace(/_/g, ' ')}
                      </span>
                      <span className="text-text-secondary-dark font-mono truncate">
                        {String(value)}
                      </span>
                    </div>
                  )
                ))}
              </div>
            </div>
          )}
          
          {/* Timestamp */}
          <div className="mt-2 text-[10px] text-text-muted-dark font-mono">
            {formatTimestamp(event.timestamp)}
          </div>
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Phase Progress Section
// ═══════════════════════════════════════════════════════════════

interface PhaseProgressProps {
  currentPhase: MissionPhase
  timeline: TimelineEvent[]
}

function PhaseProgress({ currentPhase, timeline }: PhaseProgressProps) {
  const phases: MissionPhase[] = ['setup', 'reconnaissance', 'enumeration', 'exploitation', 'post_exploitation', 'completed']
  const currentIndex = phases.indexOf(currentPhase)
  
  const getPhaseStatus = (_phase: MissionPhase, index: number): 'completed' | 'current' | 'pending' => {
    if (index < currentIndex) return 'completed'
    if (index === currentIndex) return 'current'
    return 'pending'
  }
  
  const getPhaseEventCount = (phaseToCount: MissionPhase): number => {
    return timeline.filter(e => e.phase === phaseToCount).length
  }
  
  return (
    <div className="mb-6 p-4 rounded-xl bg-zinc-900/50 border border-zinc-800">
      <h3 className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider mb-4">
        Mission Progress
      </h3>
      
      <div className="flex items-center gap-2">
        {phases.slice(0, -1).map((phase, index) => {
          const status = getPhaseStatus(phase, index)
          const eventCount = getPhaseEventCount(phase)
          const config = phaseConfig[phase]
          
          return (
            <React.Fragment key={phase}>
              {/* Phase Node */}
              <div className="flex flex-col items-center gap-1">
                <div className={cn(
                  'flex items-center justify-center w-8 h-8 rounded-lg border transition-all',
                  status === 'completed' && 'bg-green-500/20 border-green-500/50',
                  status === 'current' && 'bg-blue-500/20 border-blue-500/50 animate-pulse',
                  status === 'pending' && 'bg-zinc-800 border-zinc-700'
                )}>
                  {status === 'completed' ? (
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                  ) : status === 'current' ? (
                    <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
                  ) : (
                    <Circle className="h-4 w-4 text-zinc-500" />
                  )}
                </div>
                <span className={cn(
                  'text-[9px] font-medium uppercase tracking-wider',
                  status === 'completed' && 'text-green-400',
                  status === 'current' && 'text-blue-400',
                  status === 'pending' && 'text-zinc-500'
                )}>
                  {config.label}
                </span>
                {eventCount > 0 && (
                  <span className="text-[9px] text-text-muted-dark">
                    {eventCount}
                  </span>
                )}
              </div>
              
              {/* Connector */}
              {index < phases.length - 2 && (
                <div className={cn(
                  'flex-1 h-0.5 rounded-full',
                  status === 'completed' ? 'bg-green-500/50' : 'bg-zinc-700'
                )} />
              )}
            </React.Fragment>
          )
        })}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Decision Room (HITL Modal Trigger)
// ═══════════════════════════════════════════════════════════════

interface DecisionRoomProps {
  pendingApproval: TimelineEvent | null
  onOpenDecision: () => void
}

function DecisionRoom({ pendingApproval, onOpenDecision }: DecisionRoomProps) {
  if (!pendingApproval) return null
  
  return (
    <div className="mb-6 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 animate-pulse-slow">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-amber-500/20">
            <Shield className="h-5 w-5 text-amber-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-amber-400">
              Decision Required
            </h3>
            <p className="text-xs text-text-secondary-dark">
              {pendingApproval.description}
            </p>
          </div>
        </div>
        
        <button
          onClick={onOpenDecision}
          className={cn(
            'px-4 py-2 rounded-lg font-semibold text-sm transition-all',
            'bg-amber-500 text-black hover:bg-amber-400',
            'focus:outline-none focus:ring-2 focus:ring-amber-500/50'
          )}
        >
          Review Action
        </button>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Filter Controls
// ═══════════════════════════════════════════════════════════════

interface FilterControlsProps {
  selectedTypes: TimelineEventType[]
  onToggleType: (type: TimelineEventType) => void
  selectedPhases: MissionPhase[]
  onTogglePhase: (phase: MissionPhase) => void
}

function FilterControls({ selectedTypes, onToggleType, selectedPhases, onTogglePhase }: FilterControlsProps) {
  const [isOpen, setIsOpen] = React.useState(false)
  
  const importantTypes: TimelineEventType[] = [
    'vuln_found', 'exploit_success', 'session_established', 'credential_harvested', 'approval_required', 'error'
  ]
  
  return (
    <div className="mb-4">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          'flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs transition-all',
          'bg-zinc-800 border border-zinc-700 hover:border-zinc-600',
          'text-text-secondary-dark'
        )}
      >
        <Filter className="h-3.5 w-3.5" />
        <span>Filter Events</span>
        {(selectedTypes.length > 0 || selectedPhases.length > 0) && (
          <span className="px-1.5 py-0.5 rounded-full bg-royal-blue/20 text-royal-blue text-[10px] font-semibold">
            {selectedTypes.length + selectedPhases.length}
          </span>
        )}
        <ChevronDown className={cn('h-3 w-3 transition-transform', isOpen && 'rotate-180')} />
      </button>
      
      {isOpen && (
        <div className="mt-2 p-3 rounded-lg bg-zinc-800/80 border border-zinc-700">
          <div className="text-[10px] text-text-muted-dark uppercase tracking-wider mb-2">
            Event Types
          </div>
          <div className="flex flex-wrap gap-1.5 mb-3">
            {importantTypes.map(type => {
              const config = eventTypeConfig[type]
              const Icon = config.icon
              const isSelected = selectedTypes.includes(type)
              
              return (
                <button
                  key={type}
                  onClick={() => onToggleType(type)}
                  className={cn(
                    'flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium transition-all',
                    isSelected
                      ? cn(config.bgColor, config.color, 'border', config.borderColor)
                      : 'bg-zinc-700/50 text-zinc-400 hover:bg-zinc-700'
                  )}
                >
                  <Icon className="h-3 w-3" />
                  {type.replace(/_/g, ' ')}
                </button>
              )
            })}
          </div>
          
          <div className="text-[10px] text-text-muted-dark uppercase tracking-wider mb-2">
            Phases
          </div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(phaseConfig).map(([phase, config]) => {
              const isSelected = selectedPhases.includes(phase as MissionPhase)
              
              return (
                <button
                  key={phase}
                  onClick={() => onTogglePhase(phase as MissionPhase)}
                  className={cn(
                    'px-2 py-1 rounded text-[10px] font-medium transition-all',
                    isSelected ? config.color : 'bg-zinc-700/50 text-zinc-400 hover:bg-zinc-700'
                  )}
                >
                  {config.label}
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Mission Timeline Component
// ═══════════════════════════════════════════════════════════════

export interface MissionTimelineProps {
  onOpenDecision?: () => void
  maxEvents?: number
  showFilters?: boolean
  showProgress?: boolean
}

export function MissionTimeline({
  onOpenDecision,
  maxEvents = 50,
  showFilters = true,
  showProgress = true,
}: MissionTimelineProps) {
  const { timeline, missionPhase } = useMissionStore()
  const [expandedEvents, setExpandedEvents] = React.useState<Set<string>>(new Set())
  const [selectedTypes, setSelectedTypes] = React.useState<TimelineEventType[]>([])
  const [selectedPhases, setSelectedPhases] = React.useState<MissionPhase[]>([])
  
  // Find pending approval event
  const pendingApproval = timeline.find(e => e.type === 'approval_required' && e.status === 'awaiting')
  
  // Filter and limit events
  const filteredEvents = React.useMemo(() => {
    let events = [...timeline].reverse() // Newest first
    
    if (selectedTypes.length > 0) {
      events = events.filter(e => selectedTypes.includes(e.type))
    }
    
    if (selectedPhases.length > 0) {
      events = events.filter(e => selectedPhases.includes(e.phase))
    }
    
    return events.slice(0, maxEvents)
  }, [timeline, selectedTypes, selectedPhases, maxEvents])
  
  const toggleExpanded = (eventId: string) => {
    setExpandedEvents(prev => {
      const next = new Set(prev)
      if (next.has(eventId)) {
        next.delete(eventId)
      } else {
        next.add(eventId)
      }
      return next
    })
  }
  
  const toggleType = (type: TimelineEventType) => {
    setSelectedTypes(prev => 
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    )
  }
  
  const togglePhase = (phase: MissionPhase) => {
    setSelectedPhases(prev =>
      prev.includes(phase) ? prev.filter(p => p !== phase) : [...prev, phase]
    )
  }
  
  if (timeline.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <FileSearch className="h-12 w-12 text-text-muted-dark mb-4" />
        <h3 className="text-lg font-medium text-text-secondary-dark mb-2">
          No Activity Yet
        </h3>
        <p className="text-sm text-text-muted-dark max-w-md">
          Start a mission to see real-time progress updates here.
        </p>
      </div>
    )
  }
  
  return (
    <div className="flex flex-col h-full">
      {/* Phase Progress Bar */}
      {showProgress && (
        <PhaseProgress currentPhase={missionPhase} timeline={timeline} />
      )}
      
      {/* Decision Room (HITL Alert) */}
      <DecisionRoom 
        pendingApproval={pendingApproval || null} 
        onOpenDecision={onOpenDecision || (() => {})} 
      />
      
      {/* Filter Controls */}
      {showFilters && (
        <FilterControls
          selectedTypes={selectedTypes}
          onToggleType={toggleType}
          selectedPhases={selectedPhases}
          onTogglePhase={togglePhase}
        />
      )}
      
      {/* Event Count */}
      <div className="flex items-center justify-between mb-4 text-xs text-text-muted-dark">
        <span>
          Showing {filteredEvents.length} of {timeline.length} events
        </span>
        {filteredEvents.length < timeline.length && (
          <button
            onClick={() => {
              setSelectedTypes([])
              setSelectedPhases([])
            }}
            className="text-royal-blue hover:text-royal-blue/80 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>
      
      {/* Timeline Events */}
      <div className="flex-1 overflow-y-auto space-y-2 pr-2 scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-transparent">
        {filteredEvents.map((event, index) => (
          <TimelineEventItem
            key={event.id}
            event={event}
            isLast={index === filteredEvents.length - 1}
            expanded={expandedEvents.has(event.id)}
            onToggle={() => toggleExpanded(event.id)}
          />
        ))}
      </div>
    </div>
  )
}

export default MissionTimeline
