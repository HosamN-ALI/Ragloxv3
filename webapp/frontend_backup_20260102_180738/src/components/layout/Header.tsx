// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Header Component
// Transparent, minimal header with blur effect
// Inspired by Manus.im / Modern Agentic Design
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  OctagonX,
  Bot,
  Bell,
  Wifi,
  WifiOff,
  AlertTriangle,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/Button'
import { useEventStore, selectConnectionStatus } from '@/stores/eventStore'
import { MissionSelector } from '@/components/mission/MissionSelector'

export function Header() {
  const connectionStatus = useEventStore(selectConnectionStatus)
  const pendingApprovals = useEventStore((state) => state.pendingApprovals)
  const toggleAIPanel = useEventStore((state) => state.toggleAIPanel)
  const isAIPanelOpen = useEventStore((state) => state.isAIPanelOpen)
  const isSidebarCollapsed = useEventStore((state) => state.isSidebarCollapsed)
  const [isStopModalOpen, setIsStopModalOpen] = React.useState(false)
  const [confirmText, setConfirmText] = React.useState('')
  
  const handleEmergencyStop = async () => {
    if (confirmText !== 'ABORT') {
      // Visual feedback - the input will show error state
      return
    }
    
    console.log('Emergency stop triggered')
    setIsStopModalOpen(false)
    setConfirmText('')
    
    try {
      const response = await fetch('/api/missions/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      if (!response.ok) {
        console.error('Failed to stop mission')
      }
    } catch (error) {
      console.error('Emergency stop failed:', error)
    }
  }
  
  return (
    <header className={cn(
      "fixed top-0 right-0 z-30 h-14",
      "glass border-b border-white/5",
      "transition-all duration-300",
      isSidebarCollapsed ? "left-[72px]" : "left-56"
    )}>
      <div className="flex h-full items-center justify-between px-6">
        {/* Left Section - Mission Selector & Connection Status */}
        <div className="flex items-center gap-4">
          <MissionSelector />
          <div className="w-px h-6 bg-zinc-700/50" />
          <ConnectionIndicator status={connectionStatus} />
        </div>
        
        {/* Right Section - Actions */}
        <div className="flex items-center gap-2">
          {/* Notifications */}
          <Button
            variant="ghost"
            size="icon"
            className="relative rounded-xl hover:bg-white/5"
            onClick={() => {}}
          >
            <Bell className="h-4 w-4 text-text-secondary-dark" />
            {pendingApprovals.length > 0 && (
              <span className="absolute -top-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-critical text-[10px] font-bold text-white">
                {pendingApprovals.length}
              </span>
            )}
          </Button>
          
          {/* AI Assistant Toggle */}
          <Button
            variant={isAIPanelOpen ? 'secondary' : 'ghost'}
            size="icon"
            onClick={toggleAIPanel}
            title="AI Assistant"
            className={cn(
              'rounded-xl',
              isAIPanelOpen ? 'bg-royal-blue/10 text-royal-blue' : 'hover:bg-white/5'
            )}
          >
            <Bot className="h-4 w-4" />
          </Button>
          
          {/* Emergency Stop Button */}
          <Button
            variant="ghost"
            className={cn(
              'ml-2 gap-2 px-3 py-1.5 rounded-xl text-xs font-medium',
              'text-critical/80 hover:text-critical hover:bg-critical/10',
              'transition-all duration-200'
            )}
            onClick={() => setIsStopModalOpen(true)}
          >
            <OctagonX className="h-3.5 w-3.5" />
            <span>STOP</span>
          </Button>
        </div>
      </div>
      
      {/* Emergency Stop Confirmation Modal - Enhanced with ABORT typing */}
      {isStopModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md rounded-2xl glass border border-white/10 p-6 shadow-2xl animate-fade-in">
            <div className="flex items-center gap-4 text-critical mb-6">
              <div className="p-3 rounded-2xl bg-critical/10">
                <AlertTriangle className="h-6 w-6" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-text-primary-dark">Emergency Stop</h2>
                <p className="text-sm text-text-muted-dark">This action requires confirmation</p>
              </div>
            </div>
            
            <p className="text-sm text-text-secondary-dark mb-4 leading-relaxed">
              This will immediately halt all running missions and active operations. 
              This may leave systems in an inconsistent state.
            </p>
            
            <div className="mb-6">
              <label className="block text-xs font-medium text-text-muted-dark mb-2">
                Type <span className="text-critical font-mono">ABORT</span> to confirm
              </label>
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value.toUpperCase())}
                placeholder="Type ABORT"
                className={cn(
                  'w-full px-4 py-2.5 rounded-xl text-sm font-mono',
                  'bg-bg-elevated-dark/50 border border-white/10',
                  'text-text-primary-dark placeholder:text-text-muted-dark',
                  'focus:outline-none focus:ring-2 focus:ring-critical/30'
                )}
                autoFocus
              />
            </div>
            
            <div className="flex justify-end gap-3">
              <Button 
                variant="ghost" 
                onClick={() => {
                  setIsStopModalOpen(false)
                  setConfirmText('')
                }}
                className="rounded-xl text-sm"
              >
                Cancel
              </Button>
              <Button 
                variant="destructive" 
                onClick={handleEmergencyStop}
                disabled={confirmText !== 'ABORT'}
                className={cn(
                  'rounded-xl text-sm font-medium',
                  confirmText !== 'ABORT' && 'opacity-50 cursor-not-allowed'
                )}
              >
                Confirm Stop
              </Button>
            </div>
          </div>
        </div>
      )}
    </header>
  )
}

// Connection Status Indicator - Minimal
interface ConnectionIndicatorProps {
  status: 'disconnected' | 'connecting' | 'connected' | 'reconnecting'
}

function ConnectionIndicator({ status }: ConnectionIndicatorProps) {
  const statusConfig = {
    connected: {
      icon: Wifi,
      color: 'text-success',
      dotColor: 'bg-success',
      label: 'Connected',
    },
    connecting: {
      icon: Wifi,
      color: 'text-warning',
      dotColor: 'bg-warning animate-pulse',
      label: 'Connecting...',
    },
    reconnecting: {
      icon: Wifi,
      color: 'text-warning',
      dotColor: 'bg-warning animate-pulse',
      label: 'Reconnecting...',
    },
    disconnected: {
      icon: WifiOff,
      color: 'text-critical',
      dotColor: 'bg-critical',
      label: 'Disconnected',
    },
  }
  
  const config = statusConfig[status]
  const Icon = config.icon
  
  return (
    <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5">
      <span className={cn('w-1.5 h-1.5 rounded-full', config.dotColor)} />
      <Icon className={cn('h-3.5 w-3.5', config.color)} />
      <span className={cn('text-xs font-medium', config.color)}>{config.label}</span>
    </div>
  )
}
