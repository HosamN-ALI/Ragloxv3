// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - ActivityFeed Component (Thought Stream)
// Vertical timeline with step-by-step execution
// Inspired by Manus.im / Modern Agentic Design
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Target,
  Bug,
  Terminal,
  Trophy,
  AlertTriangle,
  RefreshCw,
  Wifi,
  FileText,
  CheckCircle2,
  Circle,
  XCircle,
  Loader2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatTimestamp } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'
import type { ActivityItem, ActivityType, Severity } from '@/types'

// Activity icons
const activityIcons: Record<ActivityType, React.ElementType> = {
  target_discovered: Target,
  vuln_found: Bug,
  session_established: Terminal,
  goal_achieved: Trophy,
  task_started: RefreshCw,
  task_completed: CheckCircle2,
  task_failed: XCircle,
  approval_required: AlertTriangle,
  status_change: Wifi,
  log: FileText,
}

// Severity badges - light backgrounds
const severityStyles: Record<Severity, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-50', text: 'text-red-700' },
  high: { bg: 'bg-amber-50', text: 'text-amber-700' },
  medium: { bg: 'bg-blue-50', text: 'text-blue-700' },
  low: { bg: 'bg-emerald-50', text: 'text-emerald-700' },
  info: { bg: 'bg-slate-100', text: 'text-slate-600' },
}

export function ActivityFeed() {
  const { activities } = useEventStore()
  
  return (
    <div className="rounded-2xl glass border border-white/5 shadow-lg overflow-hidden h-full">
      {/* Card Header */}
      <div className="flex items-center justify-between px-5 py-4">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-text-primary-dark">Execution Stream</h3>
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-white/5 text-[10px] font-medium text-text-muted-dark">
            <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse"></span>
            Live
          </span>
        </div>
        <span className="text-xs text-text-muted-dark">
          {activities.length} events
        </span>
      </div>
      
      {/* Timeline */}
      <div className="max-h-[440px] overflow-y-auto px-5 pb-5">
        {activities.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-text-muted-dark">
            <div className="p-4 rounded-2xl bg-white/5 mb-4">
              <Loader2 className="h-8 w-8 opacity-30 animate-spin" />
            </div>
            <p className="text-sm font-medium">Waiting for events...</p>
            <p className="text-xs mt-1 text-text-muted-dark/70">Activity will appear here as it occurs</p>
          </div>
        ) : (
          <div className="relative">
            {/* Vertical Timeline Line */}
            <div className="absolute left-[15px] top-2 bottom-2 w-px bg-gradient-to-b from-royal-blue/50 via-border-dark to-transparent" />
            
            <div className="space-y-1">
              {activities.map((activity, index) => (
                <TimelineItem 
                  key={activity.id} 
                  activity={activity} 
                  isFirst={index === 0}
                  isActive={index === 0}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// Timeline Item Component
function TimelineItem({ activity, isFirst, isActive }: { 
  activity: ActivityItem
  isFirst: boolean
  isActive: boolean 
}) {
  const Icon = activityIcons[activity.type] || FileText
  
  // Determine status icon
  const isCompleted = activity.type === 'task_completed' || activity.type === 'goal_achieved' || activity.type === 'session_established'
  const isFailed = activity.type === 'task_failed'
  const isInProgress = activity.type === 'task_started' && isFirst
  
  const StatusIcon = isCompleted ? CheckCircle2 : isFailed ? XCircle : isInProgress ? Loader2 : Circle
  
  return (
    <div className={cn(
      'relative flex items-start gap-4 py-3 px-2 -mx-2 rounded-xl',
      'transition-all duration-200',
      isActive && 'bg-white/5'
    )}>
      {/* Timeline Node */}
      <div className="relative z-10 flex-shrink-0">
        <div className={cn(
          'w-[30px] h-[30px] rounded-full flex items-center justify-center',
          isCompleted && 'bg-emerald-50',
          isFailed && 'bg-red-50',
          isInProgress && 'bg-blue-50',
          !isCompleted && !isFailed && !isInProgress && 'bg-white/10'
        )}>
          <StatusIcon className={cn(
            'h-4 w-4',
            isCompleted && 'text-success',
            isFailed && 'text-critical',
            isInProgress && 'text-royal-blue animate-spin',
            !isCompleted && !isFailed && !isInProgress && 'text-text-muted-dark'
          )} />
        </div>
        
        {/* Ripple effect for active item */}
        {isActive && isInProgress && (
          <div className="absolute inset-0 rounded-full bg-royal-blue/20 animate-ripple" />
        )}
      </div>
      
      {/* Content */}
      <div className="flex-1 min-w-0 pt-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-text-primary-dark">
            {activity.title}
          </span>
          {activity.severity && (
            <span className={cn(
              'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium',
              severityStyles[activity.severity].bg,
              severityStyles[activity.severity].text
            )}>
              {activity.severity}
            </span>
          )}
        </div>
        
        {activity.description && (
          <p className="text-xs text-text-muted-dark mt-0.5 line-clamp-1">
            {activity.description}
          </p>
        )}
        
        <span className="text-[10px] text-text-muted-dark/70 mt-1 block font-mono">
          {formatTimestamp(activity.timestamp)}
        </span>
      </div>
      
      {/* Activity Type Icon */}
      <div className="flex-shrink-0 pt-1">
        <Icon className="h-3.5 w-3.5 text-text-muted-dark/50" />
      </div>
    </div>
  )
}
