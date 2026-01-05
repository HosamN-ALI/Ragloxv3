// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Workspace B: Active Operations View
// Mission timeline, HITL decisions, and real-time operations
// ═══════════════════════════════════════════════════════════════

import { useState } from 'react'
import { useShallow } from 'zustand/shallow'
import {
  Activity,
  Shield,
  AlertTriangle,
  Clock,
  Target,
  Zap,
  CheckCircle2,
  ChevronRight,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useMissionStore } from '@/stores/missionStore'
import { useEventStore } from '@/stores/eventStore'
import { MissionTimeline } from '@/components/operations/MissionTimeline'
import { EmergencyStop, StatusIndicator } from '@/components/control/EmergencyStop'
import { HITLApprovalModal } from '@/components/dashboard/HITLApprovalModal'
import type { ApprovalRequest } from '@/types'

// ═══════════════════════════════════════════════════════════════
// HITL Decision Room Component
// ═══════════════════════════════════════════════════════════════

interface DecisionRoomProps {
  approval: ApprovalRequest | null
  onOpenModal: () => void
}

function DecisionRoom({ approval, onOpenModal }: DecisionRoomProps) {
  if (!approval) {
    return (
      <div className="p-6 rounded-2xl bg-zinc-900/50 border border-zinc-800 text-center">
        <Shield className="h-12 w-12 text-text-muted-dark mx-auto mb-3" />
        <h3 className="text-lg font-semibold text-text-secondary-dark mb-2">
          No Pending Decisions
        </h3>
        <p className="text-sm text-text-muted-dark">
          Human-in-the-loop approval requests will appear here
        </p>
      </div>
    )
  }
  
  const riskColors = {
    low: 'border-blue-500/30 bg-blue-500/10',
    medium: 'border-yellow-500/30 bg-yellow-500/10',
    high: 'border-orange-500/30 bg-orange-500/10',
    critical: 'border-red-500/30 bg-red-500/10 animate-pulse',
  }
  
  return (
    <div className={cn(
      'p-6 rounded-2xl border-2 transition-all',
      riskColors[approval.risk_level]
    )}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={cn(
            'p-3 rounded-xl',
            approval.risk_level === 'critical' && 'bg-red-500/20',
            approval.risk_level === 'high' && 'bg-orange-500/20',
            approval.risk_level === 'medium' && 'bg-yellow-500/20',
            approval.risk_level === 'low' && 'bg-blue-500/20'
          )}>
            <AlertTriangle className={cn(
              'h-6 w-6',
              approval.risk_level === 'critical' && 'text-red-400',
              approval.risk_level === 'high' && 'text-orange-400',
              approval.risk_level === 'medium' && 'text-yellow-400',
              approval.risk_level === 'low' && 'text-blue-400'
            )} />
          </div>
          <div>
            <h3 className="text-lg font-bold text-text-primary-dark">
              Decision Required
            </h3>
            <p className="text-sm text-text-muted-dark">
              {approval.action_type.toUpperCase()} action needs approval
            </p>
          </div>
        </div>
        
        {/* Risk Badge */}
        <span className={cn(
          'px-3 py-1.5 rounded-lg text-sm font-bold uppercase',
          approval.risk_level === 'critical' && 'bg-red-500/20 text-red-400',
          approval.risk_level === 'high' && 'bg-orange-500/20 text-orange-400',
          approval.risk_level === 'medium' && 'bg-yellow-500/20 text-yellow-400',
          approval.risk_level === 'low' && 'bg-blue-500/20 text-blue-400'
        )}>
          {approval.risk_level} Risk
        </span>
      </div>
      
      {/* Content */}
      <div className="space-y-4">
        {/* Target Info */}
        {approval.target_ip && (
          <div className="flex items-center gap-2 text-sm">
            <Target className="h-4 w-4 text-text-muted-dark" />
            <span className="text-text-muted-dark">Target:</span>
            <span className="font-mono text-text-secondary-dark">
              {approval.target_ip}
              {approval.target_hostname && ` (${approval.target_hostname})`}
            </span>
          </div>
        )}
        
        {/* Action Description */}
        <div className="p-4 rounded-xl bg-zinc-800/50">
          <p className="text-sm text-text-secondary-dark">
            {approval.action_description}
          </p>
        </div>
        
        {/* Risk Reasons */}
        {approval.risk_reasons.length > 0 && (
          <div>
            <p className="text-xs text-text-muted-dark uppercase tracking-wider mb-2">
              Risk Factors
            </p>
            <ul className="space-y-1">
              {approval.risk_reasons.map((reason, idx) => (
                <li key={idx} className="flex items-center gap-2 text-sm text-text-muted-dark">
                  <span className="w-1.5 h-1.5 rounded-full bg-text-muted-dark" />
                  {reason}
                </li>
              ))}
            </ul>
          </div>
        )}
        
        {/* Command Preview */}
        {approval.command_preview && (
          <div>
            <p className="text-xs text-text-muted-dark uppercase tracking-wider mb-2">
              Command Preview
            </p>
            <code className="block p-3 rounded-lg bg-zinc-800/80 text-xs font-mono text-text-secondary-dark overflow-x-auto">
              {approval.command_preview}
            </code>
          </div>
        )}
      </div>
      
      {/* Actions */}
      <div className="flex gap-3 mt-6">
        <button
          onClick={onOpenModal}
          className={cn(
            'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl',
            'bg-royal-blue text-white font-semibold',
            'hover:bg-royal-blue/80 transition-all'
          )}
        >
          <Shield className="h-4 w-4" />
          Review & Decide
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Quick Stats Component
// ═══════════════════════════════════════════════════════════════

function QuickStats() {
  const { timeline, missionPhase } = useMissionStore(
    useShallow((s) => ({ timeline: s.timeline, missionPhase: s.missionPhase }))
  )
  const missionStats = useEventStore((s) => s.missionStats)
  
  const phaseEvents = timeline.filter(e => e.phase === missionPhase)
  const completedEvents = phaseEvents.filter(e => e.status === 'completed')
  const pendingEvents = phaseEvents.filter(e => e.status === 'pending' || e.status === 'awaiting')
  
  return (
    <div className="grid grid-cols-4 gap-3 mb-6">
      {/* Current Phase */}
      <div className="p-4 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-2">
          <Zap className="h-4 w-4 text-cyan-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Phase</span>
        </div>
        <span className="text-base font-bold text-text-primary-dark capitalize">
          {missionPhase.replace('_', ' ')}
        </span>
      </div>
      
      {/* Completed Tasks */}
      <div className="p-4 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-2">
          <CheckCircle2 className="h-4 w-4 text-green-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Completed</span>
        </div>
        <span className="text-2xl font-bold text-green-400">{completedEvents.length}</span>
      </div>
      
      {/* Pending Actions */}
      <div className="p-4 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-2">
          <Clock className="h-4 w-4 text-amber-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Pending</span>
        </div>
        <span className="text-2xl font-bold text-amber-400">{pendingEvents.length}</span>
      </div>
      
      {/* Goals Progress */}
      <div className="p-4 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-2">
          <Target className="h-4 w-4 text-purple-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Goals</span>
        </div>
        <span className="text-2xl font-bold text-purple-400">
          {missionStats.goals_achieved}/{missionStats.goals_total}
        </span>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Operations View Component
// ═══════════════════════════════════════════════════════════════

export interface OperationsViewProps {
  onApprove?: (actionId: string, comments?: string) => Promise<void>
  onReject?: (actionId: string, comments?: string) => Promise<void>
}

export function OperationsView({ onApprove: _onApprove, onReject: _onReject }: OperationsViewProps) {
  const { systemStatus, currentApproval } = useMissionStore(
    useShallow((s) => ({ systemStatus: s.systemStatus, currentApproval: s.currentApproval }))
  )
  const pendingApprovals = useEventStore((s) => s.pendingApprovals)
  
  const [showApprovalModal, setShowApprovalModal] = useState(false)
  const [selectedApproval, setSelectedApproval] = useState<ApprovalRequest | null>(null)
  
  // Use store's current approval or first from event store
  const activeApproval = currentApproval || (pendingApprovals.length > 0 ? pendingApprovals[0] : null)
  
  const handleOpenDecision = () => {
    if (activeApproval) {
      setSelectedApproval(activeApproval)
      setShowApprovalModal(true)
    }
  }
  
  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-text-primary-dark mb-1">
            Active Operations
          </h1>
          <p className="text-sm text-text-muted-dark">
            Mission timeline, decisions, and real-time progress
          </p>
        </div>
        
        {/* Status Indicator */}
        <StatusIndicator status={systemStatus} />
      </div>
      
      {/* Quick Stats */}
      <QuickStats />
      
      {/* Main Content Grid */}
      <div className="flex-1 grid grid-cols-3 gap-6 min-h-0">
        {/* Mission Timeline (2 columns) */}
        <div className="col-span-2 flex flex-col min-h-0">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="h-5 w-5 text-royal-blue" />
            <h2 className="text-lg font-semibold text-text-primary-dark">
              Mission Timeline
            </h2>
          </div>
          
          <div className="flex-1 overflow-hidden rounded-2xl bg-zinc-900/30 border border-zinc-800 p-4">
            <MissionTimeline
              onOpenDecision={handleOpenDecision}
              showFilters={true}
              showProgress={true}
            />
          </div>
        </div>
        
        {/* Right Column: Decision Room + Emergency Stop */}
        <div className="flex flex-col gap-6 min-h-0">
          {/* Decision Room */}
          <div className="flex-1 overflow-y-auto">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-5 w-5 text-amber-400" />
              <h2 className="text-lg font-semibold text-text-primary-dark">
                Decision Room
              </h2>
              {pendingApprovals.length > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 text-xs font-semibold">
                  {pendingApprovals.length}
                </span>
              )}
            </div>
            
            <DecisionRoom
              approval={activeApproval}
              onOpenModal={handleOpenDecision}
            />
          </div>
          
          {/* Emergency Stop */}
          <div>
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="h-5 w-5 text-red-400" />
              <h2 className="text-lg font-semibold text-text-primary-dark">
                System Control
              </h2>
            </div>
            
            <EmergencyStop
              mode="hold"
              showControls={true}
            />
          </div>
        </div>
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

export default OperationsView
