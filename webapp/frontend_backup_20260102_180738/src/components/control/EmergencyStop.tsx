// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Emergency Stop (Kill Switch) Component
// Critical control for immediate mission abort
// Design: 2-step confirmation / Hold-to-abort for safety
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { useState, useRef, useCallback, useEffect } from 'react'
import {
  OctagonX,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Pause,
  Play,
  RefreshCw,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useMissionStore, type SystemStatus } from '@/stores/missionStore'

// ═══════════════════════════════════════════════════════════════
// Status Configuration
// ═══════════════════════════════════════════════════════════════

interface StatusConfig {
  label: string
  color: string
  bgColor: string
  borderColor: string
  ringColor: string
  pulse: boolean
  icon: React.ElementType
}

const statusConfig: Record<SystemStatus, StatusConfig> = {
  standby: {
    label: 'System Armed',
    color: 'text-green-400',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/30',
    ringColor: 'ring-green-500/50',
    pulse: false,
    icon: CheckCircle2,
  },
  active: {
    label: 'Active Attack',
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
    ringColor: 'ring-red-500/50',
    pulse: true,
    icon: ShieldAlert,
  },
  awaiting_approval: {
    label: 'Awaiting Decision',
    color: 'text-amber-400',
    bgColor: 'bg-amber-500/10',
    borderColor: 'border-amber-500/30',
    ringColor: 'ring-amber-500/50',
    pulse: true,
    icon: AlertTriangle,
  },
  paused: {
    label: 'Mission Paused',
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/30',
    ringColor: 'ring-yellow-500/50',
    pulse: false,
    icon: Pause,
  },
  emergency_stop: {
    label: 'EMERGENCY STOP',
    color: 'text-red-500',
    bgColor: 'bg-red-500/20',
    borderColor: 'border-red-500',
    ringColor: 'ring-red-500',
    pulse: true,
    icon: OctagonX,
  },
}

// ═══════════════════════════════════════════════════════════════
// Status Indicator Component
// ═══════════════════════════════════════════════════════════════

interface StatusIndicatorProps {
  status: SystemStatus
  compact?: boolean
}

export function StatusIndicator({ status, compact = false }: StatusIndicatorProps) {
  const config = statusConfig[status]
  const Icon = config.icon
  
  return (
    <div className={cn(
      'flex items-center gap-2 px-3 py-2 rounded-xl border transition-all',
      config.bgColor,
      config.borderColor,
      config.pulse && 'animate-pulse'
    )}>
      {/* Status Light */}
      <div className="relative">
        <div className={cn(
          'w-3 h-3 rounded-full',
          status === 'standby' && 'bg-green-500',
          status === 'active' && 'bg-red-500',
          status === 'awaiting_approval' && 'bg-amber-500',
          status === 'paused' && 'bg-yellow-500',
          status === 'emergency_stop' && 'bg-red-600'
        )} />
        {config.pulse && (
          <div className={cn(
            'absolute inset-0 w-3 h-3 rounded-full animate-ping opacity-75',
            status === 'active' && 'bg-red-500',
            status === 'awaiting_approval' && 'bg-amber-500',
            status === 'emergency_stop' && 'bg-red-600'
          )} />
        )}
      </div>
      
      {!compact && (
        <>
          <Icon className={cn('h-4 w-4', config.color)} />
          <span className={cn('text-sm font-semibold uppercase tracking-wider', config.color)}>
            {config.label}
          </span>
        </>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Hold-to-Abort Button Component
// ═══════════════════════════════════════════════════════════════

interface HoldToAbortProps {
  onAbort: (reason: string) => void
  holdDuration?: number // milliseconds
  disabled?: boolean
}

function HoldToAbortButton({ onAbort, holdDuration = 2000, disabled = false }: HoldToAbortProps) {
  const [holdProgress, setHoldProgress] = useState(0)
  const [isHolding, setIsHolding] = useState(false)
  const holdTimerRef = useRef<number | null>(null)
  const startTimeRef = useRef<number>(0)
  
  const startHold = useCallback(() => {
    if (disabled) return
    setIsHolding(true)
    startTimeRef.current = Date.now()
    
    const updateProgress = () => {
      const elapsed = Date.now() - startTimeRef.current
      const progress = Math.min(elapsed / holdDuration, 1)
      setHoldProgress(progress)
      
      if (progress >= 1) {
        onAbort('Emergency stop activated by operator')
        setIsHolding(false)
        setHoldProgress(0)
      } else {
        holdTimerRef.current = requestAnimationFrame(updateProgress)
      }
    }
    
    holdTimerRef.current = requestAnimationFrame(updateProgress)
  }, [disabled, holdDuration, onAbort])
  
  const cancelHold = useCallback(() => {
    if (holdTimerRef.current) {
      cancelAnimationFrame(holdTimerRef.current)
    }
    setIsHolding(false)
    setHoldProgress(0)
  }, [])
  
  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (holdTimerRef.current) {
        cancelAnimationFrame(holdTimerRef.current)
      }
    }
  }, [])
  
  return (
    <button
      onMouseDown={startHold}
      onMouseUp={cancelHold}
      onMouseLeave={cancelHold}
      onTouchStart={startHold}
      onTouchEnd={cancelHold}
      disabled={disabled}
      className={cn(
        'relative overflow-hidden',
        'w-24 h-24 rounded-full border-4 transition-all',
        'flex flex-col items-center justify-center',
        'focus:outline-none focus:ring-4',
        disabled
          ? 'bg-zinc-800 border-zinc-700 cursor-not-allowed opacity-50'
          : isHolding
            ? 'bg-red-600 border-red-400 scale-95'
            : 'bg-red-500/20 border-red-500 hover:bg-red-500/30 hover:border-red-400',
        'focus:ring-red-500/50'
      )}
      aria-label="Emergency Stop - Hold to activate"
    >
      {/* Progress Ring */}
      <svg
        className="absolute inset-0 w-full h-full -rotate-90"
        viewBox="0 0 100 100"
      >
        <circle
          cx="50"
          cy="50"
          r="46"
          fill="none"
          stroke={isHolding ? 'rgba(239, 68, 68, 0.3)' : 'transparent'}
          strokeWidth="4"
        />
        <circle
          cx="50"
          cy="50"
          r="46"
          fill="none"
          stroke="rgb(239, 68, 68)"
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={`${holdProgress * 289} 289`}
          className="transition-none"
        />
      </svg>
      
      {/* Icon & Text */}
      <OctagonX className={cn(
        'h-8 w-8 relative z-10 transition-transform',
        isHolding ? 'text-white scale-110' : 'text-red-400'
      )} />
      <span className={cn(
        'text-[10px] font-bold uppercase tracking-wider mt-1 relative z-10',
        isHolding ? 'text-white' : 'text-red-400'
      )}>
        {isHolding ? `${Math.round((1 - holdProgress) * holdDuration / 1000)}s` : 'HOLD'}
      </span>
    </button>
  )
}

// ═══════════════════════════════════════════════════════════════
// Two-Step Confirmation Modal
// ═══════════════════════════════════════════════════════════════

interface ConfirmationModalProps {
  isOpen: boolean
  onConfirm: (reason: string) => void
  onCancel: () => void
}

function ConfirmationModal({ isOpen, onConfirm, onCancel }: ConfirmationModalProps) {
  const [reason, setReason] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  
  if (!isOpen) return null
  
  const handleConfirm = () => {
    if (!confirmed) {
      setConfirmed(true)
    } else {
      onConfirm(reason || 'Emergency stop activated by operator')
      setConfirmed(false)
      setReason('')
    }
  }
  
  const handleCancel = () => {
    setConfirmed(false)
    setReason('')
    onCancel()
  }
  
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className={cn(
        'w-full max-w-md p-6 rounded-2xl border-2',
        'bg-zinc-900',
        confirmed ? 'border-red-500' : 'border-amber-500'
      )}>
        {/* Warning Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className={cn(
            'p-3 rounded-xl',
            confirmed ? 'bg-red-500/20' : 'bg-amber-500/20'
          )}>
            <OctagonX className={cn(
              'h-8 w-8',
              confirmed ? 'text-red-400' : 'text-amber-400'
            )} />
          </div>
          <div>
            <h2 className={cn(
              'text-xl font-bold',
              confirmed ? 'text-red-400' : 'text-amber-400'
            )}>
              {confirmed ? 'CONFIRM EMERGENCY STOP' : 'Emergency Stop'}
            </h2>
            <p className="text-sm text-text-muted-dark">
              {confirmed 
                ? 'This will immediately terminate all operations' 
                : 'Are you sure you want to abort the mission?'}
            </p>
          </div>
        </div>
        
        {/* Warning Message */}
        <div className={cn(
          'p-4 rounded-xl mb-6',
          confirmed ? 'bg-red-500/10 border border-red-500/30' : 'bg-amber-500/10 border border-amber-500/30'
        )}>
          <p className={cn(
            'text-sm',
            confirmed ? 'text-red-300' : 'text-amber-300'
          )}>
            {confirmed 
              ? '⚠️ All active sessions will be terminated. All pending tasks will be cancelled. This action cannot be undone.'
              : 'This will stop all reconnaissance, exploitation, and post-exploitation activities.'}
          </p>
        </div>
        
        {/* Reason Input */}
        <div className="mb-6">
          <label className="block text-xs text-text-muted-dark uppercase tracking-wider mb-2">
            Reason (Optional)
          </label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Enter reason for emergency stop..."
            className={cn(
              'w-full px-4 py-3 rounded-xl text-sm resize-none',
              'bg-zinc-800 border border-zinc-700 text-text-primary-dark',
              'placeholder:text-text-muted-dark',
              'focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500/50'
            )}
            rows={2}
          />
        </div>
        
        {/* Actions */}
        <div className="flex gap-3">
          <button
            onClick={handleCancel}
            className={cn(
              'flex-1 px-4 py-3 rounded-xl font-semibold text-sm transition-all',
              'bg-zinc-800 border border-zinc-700 text-text-secondary-dark',
              'hover:bg-zinc-700 hover:border-zinc-600'
            )}
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            className={cn(
              'flex-1 px-4 py-3 rounded-xl font-semibold text-sm transition-all',
              confirmed
                ? 'bg-red-600 text-white hover:bg-red-500 animate-pulse'
                : 'bg-amber-500 text-black hover:bg-amber-400'
            )}
          >
            {confirmed ? '🛑 CONFIRM STOP' : 'Continue'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Emergency Stop Control Panel
// ═══════════════════════════════════════════════════════════════

export interface EmergencyStopProps {
  onEmergencyStop?: () => void
  onPause?: () => void
  onResume?: () => void
  onReset?: () => void
  mode?: 'hold' | 'confirm' | 'both'
  showControls?: boolean
}

export function EmergencyStop({
  onEmergencyStop,
  onPause,
  onResume,
  onReset,
  mode = 'both',
  showControls = true,
}: EmergencyStopProps) {
  const { 
    systemStatus, 
    emergencyStopActive, 
    emergencyStopReason,
    activateEmergencyStop, 
    resetEmergencyStop,
    pauseMission,
    resumeMission,
  } = useMissionStore()
  
  const [showModal, setShowModal] = useState(false)
  
  const handleAbort = useCallback((reason: string) => {
    activateEmergencyStop(reason)
    onEmergencyStop?.()
    setShowModal(false)
  }, [activateEmergencyStop, onEmergencyStop])
  
  const handlePause = useCallback(() => {
    pauseMission()
    onPause?.()
  }, [pauseMission, onPause])
  
  const handleResume = useCallback(() => {
    resumeMission()
    onResume?.()
  }, [resumeMission, onResume])
  
  const handleReset = useCallback(() => {
    resetEmergencyStop()
    onReset?.()
  }, [resetEmergencyStop, onReset])
  
  const canEmergencyStop = systemStatus !== 'standby' && systemStatus !== 'emergency_stop'
  const canPause = systemStatus === 'active' || systemStatus === 'awaiting_approval'
  const canResume = systemStatus === 'paused'
  const canReset = systemStatus === 'emergency_stop'
  
  return (
    <div className="flex flex-col items-center p-6 rounded-2xl bg-zinc-900/50 border border-zinc-800">
      {/* Status Indicator */}
      <StatusIndicator status={systemStatus} />
      
      {/* Emergency Stop Button */}
      <div className="my-8">
        {mode === 'hold' || mode === 'both' ? (
          <HoldToAbortButton
            onAbort={handleAbort}
            disabled={!canEmergencyStop}
          />
        ) : (
          <button
            onClick={() => setShowModal(true)}
            disabled={!canEmergencyStop}
            className={cn(
              'w-24 h-24 rounded-full border-4 transition-all',
              'flex flex-col items-center justify-center',
              'focus:outline-none focus:ring-4 focus:ring-red-500/50',
              canEmergencyStop
                ? 'bg-red-500/20 border-red-500 hover:bg-red-500/30 hover:border-red-400'
                : 'bg-zinc-800 border-zinc-700 cursor-not-allowed opacity-50'
            )}
          >
            <OctagonX className="h-8 w-8 text-red-400" />
            <span className="text-[10px] font-bold uppercase tracking-wider mt-1 text-red-400">
              STOP
            </span>
          </button>
        )}
      </div>
      
      {/* Emergency Stop Reason (if activated) */}
      {emergencyStopActive && emergencyStopReason && (
        <div className="w-full p-4 mb-4 rounded-xl bg-red-500/10 border border-red-500/30">
          <p className="text-xs text-text-muted-dark uppercase tracking-wider mb-1">
            Stop Reason
          </p>
          <p className="text-sm text-red-300">{emergencyStopReason}</p>
        </div>
      )}
      
      {/* Secondary Controls */}
      {showControls && (
        <div className="flex gap-3 w-full">
          {canPause && (
            <button
              onClick={handlePause}
              className={cn(
                'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl',
                'bg-yellow-500/10 border border-yellow-500/30 text-yellow-400',
                'hover:bg-yellow-500/20 transition-all font-semibold text-sm'
              )}
            >
              <Pause className="h-4 w-4" />
              Pause
            </button>
          )}
          
          {canResume && (
            <button
              onClick={handleResume}
              className={cn(
                'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl',
                'bg-green-500/10 border border-green-500/30 text-green-400',
                'hover:bg-green-500/20 transition-all font-semibold text-sm'
              )}
            >
              <Play className="h-4 w-4" />
              Resume
            </button>
          )}
          
          {canReset && (
            <button
              onClick={handleReset}
              className={cn(
                'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl',
                'bg-blue-500/10 border border-blue-500/30 text-blue-400',
                'hover:bg-blue-500/20 transition-all font-semibold text-sm'
              )}
            >
              <RefreshCw className="h-4 w-4" />
              Reset
            </button>
          )}
        </div>
      )}
      
      {/* Instructions */}
      <p className="mt-6 text-xs text-text-muted-dark text-center max-w-[200px]">
        {mode === 'hold' || mode === 'both'
          ? 'Hold the button for 2 seconds to activate emergency stop'
          : 'Click to open emergency stop confirmation'}
      </p>
      
      {/* Confirmation Modal (for 'confirm' and 'both' modes) */}
      {(mode === 'confirm' || mode === 'both') && (
        <ConfirmationModal
          isOpen={showModal}
          onConfirm={handleAbort}
          onCancel={() => setShowModal(false)}
        />
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Compact Emergency Stop for Header/Toolbar
// ═══════════════════════════════════════════════════════════════

export function EmergencyStopCompact() {
  const { systemStatus, activateEmergencyStop } = useMissionStore()
  const [showModal, setShowModal] = useState(false)
  
  const canStop = systemStatus !== 'standby' && systemStatus !== 'emergency_stop'
  
  return (
    <>
      <div className="flex items-center gap-3">
        <StatusIndicator status={systemStatus} compact />
        
        <button
          onClick={() => setShowModal(true)}
          disabled={!canStop}
          className={cn(
            'flex items-center gap-2 px-3 py-2 rounded-xl border transition-all',
            canStop
              ? 'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20'
              : 'bg-zinc-800 border-zinc-700 text-zinc-500 cursor-not-allowed'
          )}
        >
          <OctagonX className="h-4 w-4" />
          <span className="text-xs font-semibold uppercase">Stop</span>
        </button>
      </div>
      
      <ConfirmationModal
        isOpen={showModal}
        onConfirm={(reason) => {
          activateEmergencyStop(reason)
          setShowModal(false)
        }}
        onCancel={() => setShowModal(false)}
      />
    </>
  )
}

export default EmergencyStop
