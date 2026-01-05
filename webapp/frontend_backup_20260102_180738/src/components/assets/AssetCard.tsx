// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Asset Card Component
// Professional asset visualization for Recon workspace
// Design: Palantir-inspired, data-dense, action-oriented
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Server,
  Monitor,
  Database,
  Network,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ChevronRight,
  Wifi,
  Lock,
  Unlock,
  Terminal,
  Eye,
  Crosshair,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Target, Priority, TargetStatus } from '@/types'

// ═══════════════════════════════════════════════════════════════
// OS Icon Mapping
// ═══════════════════════════════════════════════════════════════

const getOSIcon = (os?: string) => {
  if (!os) return Server
  const osLower = os.toLowerCase()
  
  if (osLower.includes('windows')) return Monitor
  if (osLower.includes('linux') || osLower.includes('ubuntu') || osLower.includes('debian')) return Terminal
  if (osLower.includes('mac') || osLower.includes('darwin')) return Monitor
  if (osLower.includes('router') || osLower.includes('cisco')) return Network
  if (osLower.includes('database') || osLower.includes('sql')) return Database
  
  return Server
}

const getOSColor = (os?: string): string => {
  if (!os) return 'text-text-muted-dark'
  const osLower = os.toLowerCase()
  
  if (osLower.includes('windows')) return 'text-blue-400'
  if (osLower.includes('linux') || osLower.includes('ubuntu')) return 'text-orange-400'
  if (osLower.includes('mac')) return 'text-zinc-300'
  
  return 'text-text-muted-dark'
}

// ═══════════════════════════════════════════════════════════════
// Status Badge Component
// ═══════════════════════════════════════════════════════════════

const statusConfig: Record<TargetStatus, { label: string; color: string; icon: React.ElementType }> = {
  discovered: { label: 'Discovered', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', icon: Eye },
  scanning: { label: 'Scanning', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30 animate-pulse', icon: Wifi },
  scanned: { label: 'Scanned', color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30', icon: ShieldCheck },
  exploiting: { label: 'Exploiting', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30 animate-pulse', icon: Crosshair },
  exploited: { label: 'Exploited', color: 'bg-red-500/20 text-red-400 border-red-500/30', icon: ShieldAlert },
  owned: { label: 'Owned', color: 'bg-green-500/20 text-green-400 border-green-500/30', icon: Unlock },
  failed: { label: 'Failed', color: 'bg-zinc-500/20 text-zinc-400 border-zinc-500/30', icon: Lock },
}

function StatusBadge({ status }: { status: TargetStatus }) {
  const config = statusConfig[status]
  const Icon = config.icon
  
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border',
      config.color
    )}>
      <Icon className="h-3 w-3" />
      {config.label}
    </span>
  )
}

// ═══════════════════════════════════════════════════════════════
// Priority Indicator
// ═══════════════════════════════════════════════════════════════

const priorityConfig: Record<Priority, { color: string; pulse: boolean }> = {
  critical: { color: 'bg-red-500', pulse: true },
  high: { color: 'bg-orange-500', pulse: false },
  medium: { color: 'bg-yellow-500', pulse: false },
  low: { color: 'bg-blue-500', pulse: false },
}

function PriorityIndicator({ priority }: { priority: Priority }) {
  const config = priorityConfig[priority]
  
  return (
    <div className="relative">
      <div className={cn(
        'w-2 h-2 rounded-full',
        config.color,
        config.pulse && 'animate-pulse'
      )} />
      {config.pulse && (
        <div className={cn(
          'absolute inset-0 w-2 h-2 rounded-full animate-ping',
          config.color,
          'opacity-75'
        )} />
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Port Badge Component
// ═══════════════════════════════════════════════════════════════

interface PortBadgeProps {
  port: string
  service: string
  isVulnerable?: boolean
}

function PortBadge({ port, service, isVulnerable }: PortBadgeProps) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono',
      isVulnerable
        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
        : 'bg-zinc-800 text-zinc-400 border border-zinc-700'
    )}>
      {isVulnerable && <AlertTriangle className="h-2.5 w-2.5" />}
      <span className="font-semibold">{port}</span>
      <span className="text-zinc-500">/</span>
      <span className="uppercase">{service}</span>
    </span>
  )
}

// ═══════════════════════════════════════════════════════════════
// Risk Score Component
// ═══════════════════════════════════════════════════════════════

function RiskScore({ score }: { score?: number }) {
  if (score === undefined) return null
  
  const normalizedScore = Math.min(100, Math.max(0, score * 100))
  const getScoreColor = () => {
    if (normalizedScore >= 80) return 'text-red-400'
    if (normalizedScore >= 60) return 'text-orange-400'
    if (normalizedScore >= 40) return 'text-yellow-400'
    return 'text-green-400'
  }
  
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1 bg-zinc-800 rounded-full overflow-hidden">
        <div
          className={cn(
            'h-full rounded-full transition-all duration-500',
            normalizedScore >= 80 ? 'bg-red-500' :
            normalizedScore >= 60 ? 'bg-orange-500' :
            normalizedScore >= 40 ? 'bg-yellow-500' : 'bg-green-500'
          )}
          style={{ width: `${normalizedScore}%` }}
        />
      </div>
      <span className={cn('text-xs font-mono font-semibold', getScoreColor())}>
        {normalizedScore.toFixed(0)}
      </span>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Asset Card Component
// ═══════════════════════════════════════════════════════════════

export interface AssetCardProps {
  target: Target
  vulnerableServices?: string[]
  sessionCount?: number
  credentialCount?: number
  onClick?: () => void
  isSelected?: boolean
  compact?: boolean
}

export function AssetCard({
  target,
  vulnerableServices = [],
  sessionCount = 0,
  credentialCount = 0,
  onClick,
  isSelected = false,
  compact = false,
}: AssetCardProps) {
  const OSIcon = getOSIcon(target.os)
  const osColor = getOSColor(target.os)
  
  const ports = Object.entries(target.ports)
  const visiblePorts = compact ? ports.slice(0, 3) : ports.slice(0, 6)
  const remainingPorts = ports.length - visiblePorts.length
  
  return (
    <div
      onClick={onClick}
      className={cn(
        'group relative overflow-hidden rounded-xl border transition-all duration-200',
        'bg-zinc-900/50 backdrop-blur-sm',
        isSelected
          ? 'border-royal-blue ring-1 ring-royal-blue/50'
          : 'border-zinc-800 hover:border-zinc-700',
        onClick && 'cursor-pointer hover:bg-zinc-900/80'
      )}
    >
      {/* Priority Indicator Strip */}
      <div className={cn(
        'absolute top-0 left-0 w-1 h-full',
        priorityConfig[target.priority].color
      )} />
      
      <div className={cn('p-4', compact ? 'p-3' : 'p-4')}>
        {/* Header Row */}
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-3 min-w-0 flex-1">
            {/* OS Icon */}
            <div className={cn(
              'flex-shrink-0 flex items-center justify-center w-10 h-10 rounded-lg',
              'bg-zinc-800/80 border border-zinc-700/50',
              target.status === 'owned' && 'bg-green-500/10 border-green-500/30'
            )}>
              <OSIcon className={cn('h-5 w-5', osColor)} />
            </div>
            
            {/* IP & Hostname */}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-mono font-semibold text-text-primary-dark truncate">
                  {target.ip}
                </h3>
                <PriorityIndicator priority={target.priority} />
              </div>
              {target.hostname && (
                <p className="text-xs text-text-muted-dark truncate">
                  {target.hostname}
                </p>
              )}
            </div>
          </div>
          
          {/* Status Badge */}
          <StatusBadge status={target.status} />
        </div>
        
        {/* OS Info */}
        {target.os && !compact && (
          <div className="mb-3 px-2 py-1.5 bg-zinc-800/50 rounded-lg">
            <span className="text-xs text-text-muted-dark">OS: </span>
            <span className="text-xs text-text-secondary-dark font-medium">{target.os}</span>
          </div>
        )}
        
        {/* Port Badges */}
        {ports.length > 0 && (
          <div className="mb-3">
            <div className="text-[10px] text-text-muted-dark uppercase tracking-wider mb-1.5">
              Open Ports ({ports.length})
            </div>
            <div className="flex flex-wrap gap-1.5">
              {visiblePorts.map(([port, service]) => (
                <PortBadge
                  key={port}
                  port={port}
                  service={service}
                  isVulnerable={vulnerableServices.includes(service)}
                />
              ))}
              {remainingPorts > 0 && (
                <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-zinc-800 text-[10px] text-zinc-500 font-mono">
                  +{remainingPorts} more
                </span>
              )}
            </div>
          </div>
        )}
        
        {/* Risk Score */}
        {target.risk_score !== undefined && !compact && (
          <div className="mb-3">
            <div className="text-[10px] text-text-muted-dark uppercase tracking-wider mb-1">
              Risk Score
            </div>
            <RiskScore score={target.risk_score} />
          </div>
        )}
        
        {/* Footer Stats */}
        <div className="flex items-center justify-between pt-3 border-t border-zinc-800">
          <div className="flex items-center gap-4 text-xs">
            {sessionCount > 0 && (
              <div className="flex items-center gap-1 text-green-400">
                <Terminal className="h-3.5 w-3.5" />
                <span className="font-medium">{sessionCount} session{sessionCount !== 1 ? 's' : ''}</span>
              </div>
            )}
            {credentialCount > 0 && (
              <div className="flex items-center gap-1 text-yellow-400">
                <Lock className="h-3.5 w-3.5" />
                <span className="font-medium">{credentialCount} cred{credentialCount !== 1 ? 's' : ''}</span>
              </div>
            )}
            {sessionCount === 0 && credentialCount === 0 && (
              <span className="text-text-muted-dark">No access yet</span>
            )}
          </div>
          
          {onClick && (
            <ChevronRight className={cn(
              'h-4 w-4 text-text-muted-dark transition-transform',
              'group-hover:text-text-secondary-dark group-hover:translate-x-0.5'
            )} />
          )}
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Asset Card Grid Component
// ═══════════════════════════════════════════════════════════════

interface AssetCardGridProps {
  targets: Target[]
  groupBy?: 'os' | 'priority' | 'status' | 'subnet' | 'none'
  vulnerabilities?: Map<string, string[]>
  sessions?: Map<string, number>
  credentials?: Map<string, number>
  onTargetClick?: (target: Target) => void
  selectedTargetId?: string | null
}

export function AssetCardGrid({
  targets,
  groupBy = 'none',
  vulnerabilities = new Map(),
  sessions = new Map(),
  credentials = new Map(),
  onTargetClick,
  selectedTargetId,
}: AssetCardGridProps) {
  // Group targets
  const groupedTargets = React.useMemo(() => {
    if (groupBy === 'none') {
      return { 'All Assets': targets }
    }
    
    return targets.reduce((acc, target) => {
      let key: string
      
      switch (groupBy) {
        case 'os':
          key = target.os || 'Unknown OS'
          break
        case 'priority':
          key = target.priority.charAt(0).toUpperCase() + target.priority.slice(1) + ' Priority'
          break
        case 'status':
          key = target.status.charAt(0).toUpperCase() + target.status.slice(1)
          break
        case 'subnet':
          key = target.subnet || target.ip.split('.').slice(0, 3).join('.') + '.0/24'
          break
        default:
          key = 'All'
      }
      
      if (!acc[key]) acc[key] = []
      acc[key].push(target)
      return acc
    }, {} as Record<string, Target[]>)
  }, [targets, groupBy])
  
  if (targets.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Server className="h-12 w-12 text-text-muted-dark mb-4" />
        <h3 className="text-lg font-medium text-text-secondary-dark mb-2">
          No Assets Discovered
        </h3>
        <p className="text-sm text-text-muted-dark max-w-md">
          Start a reconnaissance scan to discover targets on the network.
        </p>
      </div>
    )
  }
  
  return (
    <div className="space-y-6">
      {Object.entries(groupedTargets).map(([group, groupTargets]) => (
        <div key={group}>
          {groupBy !== 'none' && (
            <div className="flex items-center gap-2 mb-3">
              <h3 className="text-sm font-semibold text-text-secondary-dark">
                {group}
              </h3>
              <span className="text-xs text-text-muted-dark font-mono">
                ({groupTargets.length})
              </span>
            </div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {groupTargets.map((target) => (
              <AssetCard
                key={target.target_id}
                target={target}
                vulnerableServices={vulnerabilities.get(target.target_id)}
                sessionCount={sessions.get(target.target_id) || 0}
                credentialCount={credentials.get(target.target_id) || 0}
                onClick={() => onTargetClick?.(target)}
                isSelected={selectedTargetId === target.target_id}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
