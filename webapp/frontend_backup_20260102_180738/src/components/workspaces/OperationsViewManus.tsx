// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Workspace B: Active Operations View (Manus Style)
// Dual-panel layout with AI chat and terminal/event stream
// Inspired by Manus.im design patterns
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { useState, useCallback } from 'react'
import { useShallow } from 'zustand/shallow'
import {
  Activity,
  Shield,
  AlertTriangle,
  Target,
  Zap,
  CheckCircle2,
  Settings2,
  LayoutPanelLeft,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useMissionStore, type TimelineEvent } from '@/stores/missionStore'
import { useEventStore } from '@/stores/eventStore'
import { DualPanelLayout } from '@/components/manus'
import type { ChatMessage, EventCardData, PlanData, PlanTask } from '@/components/manus'
import { EmergencyStop, StatusIndicator } from '@/components/control/EmergencyStop'
import { HITLApprovalModal } from '@/components/dashboard/HITLApprovalModal'
import type { ApprovalRequest } from '@/types'

// ═══════════════════════════════════════════════════════════════
// Convert Timeline Events to EventCardData
// ═══════════════════════════════════════════════════════════════

function timelineEventToEventCard(event: TimelineEvent): EventCardData {
  // Map timeline event types to event card types
  const typeMap: Record<string, EventCardData['type']> = {
    target_discovered: 'target_discovered',
    vuln_found: 'vuln_found',
    credential_harvested: 'credential_harvested',
    session_established: 'session_established',
    approval_required: 'approval_required',
    goal_achieved: 'goal_achieved',
    error: 'error',
    phase_start: 'command_execution',
    phase_complete: 'goal_achieved',
    exploit_attempt: 'command_execution',
    exploit_success: 'goal_achieved',
    exploit_failed: 'error',
  }
  
  return {
    id: event.id,
    type: typeMap[event.type] || 'command_execution',
    title: event.title,
    description: event.description,
    status: event.status,
    timestamp: event.timestamp,
    metadata: event.metadata,
    // Add command execution if present
    commandExecution: (event.metadata as Record<string, unknown>)?.command ? {
      command: String((event.metadata as Record<string, unknown>).command),
      output: (event.metadata as Record<string, unknown>).output ? String((event.metadata as Record<string, unknown>).output) : undefined,
    } : undefined,
  }
}

// ═══════════════════════════════════════════════════════════════
// Convert Mission Data to Plan
// ═══════════════════════════════════════════════════════════════

function missionToPlan(timeline: TimelineEvent[], phase: string): PlanData {
  // Group events by phase
  const phases = ['setup', 'reconnaissance', 'enumeration', 'exploitation', 'post_exploitation', 'completed']
  
  const tasks: PlanTask[] = phases.map((p) => {
    const phaseEvents = timeline.filter(e => e.phase === p)
    const completedCount = phaseEvents.filter(e => e.status === 'completed').length
    const totalCount = phaseEvents.length
    
    let status: PlanTask['status'] = 'pending'
    if (p === phase) {
      status = 'in_progress'
    } else if (phases.indexOf(p) < phases.indexOf(phase)) {
      status = 'completed'
    }
    
    return {
      id: `phase-${p}`,
      title: p.charAt(0).toUpperCase() + p.slice(1).replace('_', ' '),
      description: `${completedCount} of ${totalCount || '?'} tasks`,
      status,
      progress: totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0,
      subtasks: phaseEvents.slice(0, 5).map(e => ({
        id: e.id,
        title: e.title,
        status: e.status as PlanTask['status'],
      })),
    }
  })
  
  const completedTasks = tasks.filter(t => t.status === 'completed').length
  
  return {
    id: 'mission-plan',
    title: 'Mission Plan',
    computerName: "RAGLOX's Computer",
    isUsingTerminal: true,
    tasks,
    totalTasks: tasks.length,
    completedTasks,
  }
}

// ═══════════════════════════════════════════════════════════════
// Quick Stats Bar Component
// ═══════════════════════════════════════════════════════════════

function QuickStatsBar() {
  const missionPhase = useMissionStore((s) => s.missionPhase)
  const missionStats = useEventStore((s) => s.missionStats)
  
  const stats = [
    { 
      icon: Zap, 
      label: 'Phase', 
      value: missionPhase.replace('_', ' '), 
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10'
    },
    { 
      icon: Target, 
      label: 'Targets', 
      value: missionStats.targets_discovered, 
      color: 'text-blue-400',
      bgColor: 'bg-blue-500/10'
    },
    { 
      icon: AlertTriangle, 
      label: 'Vulns', 
      value: missionStats.vulns_found, 
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10'
    },
    { 
      icon: CheckCircle2, 
      label: 'Goals', 
      value: `${missionStats.goals_achieved}/${missionStats.goals_total}`, 
      color: 'text-green-400',
      bgColor: 'bg-green-500/10'
    },
  ]
  
  return (
    <div className="flex items-center gap-2 px-4 py-2 bg-zinc-900 border-b border-zinc-800">
      {stats.map((stat, index) => (
        <React.Fragment key={stat.label}>
          <div className="flex items-center gap-2">
            <div className={cn("p-1.5 rounded-lg", stat.bgColor)}>
              <stat.icon className={cn("h-3.5 w-3.5", stat.color)} />
            </div>
            <div className="text-xs">
              <span className="text-zinc-500">{stat.label}: </span>
              <span className={cn("font-semibold capitalize", stat.color)}>
                {stat.value}
              </span>
            </div>
          </div>
          {index < stats.length - 1 && (
            <div className="w-px h-4 bg-zinc-700" />
          )}
        </React.Fragment>
      ))}
      
      {/* Spacer */}
      <div className="flex-1" />
      
      {/* Emergency Stop Button */}
      <EmergencyStop mode="confirm" showControls={false} />
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Operations View (Manus Style)
// ═══════════════════════════════════════════════════════════════

export interface OperationsViewManusProps {
  onApprove?: (actionId: string, comments?: string) => Promise<void>
  onReject?: (actionId: string, comments?: string) => Promise<void>
}

export function OperationsViewManus({ onApprove: _onApprove, onReject: _onReject }: OperationsViewManusProps) {
  const { systemStatus, currentApproval, missionPhase } = useMissionStore(
    useShallow((s) => ({ 
      systemStatus: s.systemStatus, 
      currentApproval: s.currentApproval,
      missionPhase: s.missionPhase,
    }))
  )
  const timeline = useMissionStore((s) => s.timeline)
  const pendingApprovals = useEventStore((s) => s.pendingApprovals)
  const chatMessages = useEventStore((s) => s.chatMessages)
  const addChatMessage = useEventStore((s) => s.addChatMessage)
  
  const [showApprovalModal, setShowApprovalModal] = useState(false)
  const [selectedApproval, setSelectedApproval] = useState<ApprovalRequest | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [isPlanExpanded, setIsPlanExpanded] = useState(false)
  
  // Convert store messages to chat messages
  const messages: ChatMessage[] = React.useMemo(() => {
    // Start with an AI greeting
    const aiGreeting: ChatMessage = {
      id: 'greeting',
      role: 'assistant',
      content: 'RAGLOX AI is ready. I\'ll help you with reconnaissance, exploitation, and post-exploitation tasks. What would you like to do?',
      timestamp: new Date().toISOString(),
    }
    
    // Convert timeline events to embedded events
    const recentEvents = timeline.slice(-5).map(timelineEventToEventCard)
    
    // Add events to greeting if any
    if (recentEvents.length > 0) {
      aiGreeting.events = recentEvents
    }
    
    // Add plan if mission is active
    if (missionPhase !== 'setup') {
      aiGreeting.plan = missionToPlan(timeline, missionPhase)
    }
    
    // Convert chat messages from store
    const convertedMessages: ChatMessage[] = chatMessages.map(msg => ({
      id: msg.id,
      role: msg.role as ChatMessage['role'],
      content: msg.content,
      timestamp: msg.timestamp,
    }))
    
    return [aiGreeting, ...convertedMessages]
  }, [timeline, missionPhase, chatMessages])
  
  // Handle sending messages
  const handleSendMessage = useCallback(async (content: string) => {
    // Add user message
    addChatMessage({
      role: 'user',
      content,
    })
    
    setIsLoading(true)
    
    // Simulate AI response (in production, this would call the backend)
    setTimeout(() => {
      addChatMessage({
        role: 'assistant',
        content: `I understand you want to "${content}". Let me analyze the current mission state and execute the appropriate actions.`,
      })
      setIsLoading(false)
    }, 1500)
  }, [addChatMessage])
  
  // Handle terminal click - used by DualPanelLayout internally
  // const handleTerminalClick = useCallback((command: string, output?: string) => {
  //   console.log('Terminal command clicked:', command, output)
  // }, [])
  
  // Handle plan expand - triggered when user clicks plan badge
  // const handlePlanExpand = useCallback((plan: PlanData) => {
  //   setIsPlanExpanded(true)
  //   console.log('Plan expanded:', plan)
  // }, [])
  
  // Active approval
  const activeApproval = currentApproval || (pendingApprovals.length > 0 ? pendingApprovals[0] : null)
  
  // Current plan
  const currentPlan = missionToPlan(timeline, missionPhase)
  
  return (
    <div className="h-full flex flex-col bg-zinc-950">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-zinc-900 border-b border-zinc-800">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-royal-blue/10">
            <Activity className="h-5 w-5 text-royal-blue" />
          </div>
          <div>
            <h1 className="text-sm font-semibold text-white">Active Operations</h1>
            <p className="text-xs text-zinc-500">AI-driven mission execution</p>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          {/* Pending Approvals Badge */}
          {pendingApprovals.length > 0 && (
            <button
              onClick={() => {
                if (activeApproval) {
                  setSelectedApproval(activeApproval)
                  setShowApprovalModal(true)
                }
              }}
              className="flex items-center gap-2 px-3 py-1.5 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-400 text-xs font-medium hover:bg-amber-500/20 transition-colors"
            >
              <Shield className="h-3.5 w-3.5" />
              {pendingApprovals.length} Pending
            </button>
          )}
          
          {/* Status Indicator */}
          <StatusIndicator status={systemStatus} />
          
          {/* Layout Toggle */}
          <button className="p-2 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors">
            <LayoutPanelLeft className="h-4 w-4" />
          </button>
          
          {/* Settings */}
          <button className="p-2 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors">
            <Settings2 className="h-4 w-4" />
          </button>
        </div>
      </div>
      
      {/* Quick Stats Bar */}
      <QuickStatsBar />
      
      {/* Main Dual Panel Layout */}
      <div className="flex-1 min-h-0">
        <DualPanelLayout
          messages={messages}
          onSendMessage={handleSendMessage}
          isLoading={isLoading}
          plan={currentPlan}
          isPlanExpanded={isPlanExpanded}
          onPlanToggle={() => setIsPlanExpanded(!isPlanExpanded)}
          defaultLeftSize={45}
          minLeftSize={30}
          maxLeftSize={60}
        />
      </div>
      
      {/* HITL Approval Modal */}
      {showApprovalModal && selectedApproval && (
        <HITLApprovalModal
          approval={selectedApproval}
          onClose={() => {
            setShowApprovalModal(false)
            setSelectedApproval(null)
          }}
        />
      )}
    </div>
  )
}

export default OperationsViewManus
