// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - StatsGrid Component
// Floating cards with soft shadows, no borders
// Inspired by Manus.im / Modern Agentic Design
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Target,
  Bug,
  AlertTriangle,
  Activity,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'

interface StatCardProps {
  title: string
  value: number
  icon: React.ElementType
  trend?: {
    value: number
    isPositive: boolean
  }
  variant?: 'default' | 'critical' | 'warning' | 'success'
}

const variantStyles = {
  default: {
    value: 'text-royal-blue',
    icon: 'bg-blue-50 text-royal-blue',
    badge: 'bg-blue-50 text-blue-700',
  },
  critical: {
    value: 'text-critical',
    icon: 'bg-red-50 text-critical',
    badge: 'bg-red-50 text-red-700',
  },
  warning: {
    value: 'text-warning',
    icon: 'bg-amber-50 text-warning',
    badge: 'bg-amber-50 text-amber-700',
  },
  success: {
    value: 'text-success',
    icon: 'bg-emerald-50 text-success',
    badge: 'bg-emerald-50 text-emerald-700',
  },
}

function StatCard({ title, value, icon: Icon, trend, variant = 'default' }: StatCardProps) {
  const styles = variantStyles[variant]
  
  return (
    <div
      className={cn(
        'relative rounded-2xl p-5',
        'glass border border-white/5',
        'shadow-lg hover:shadow-xl',
        'transition-all duration-300 hover:-translate-y-0.5'
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-3">
          <p className="text-xs font-medium text-text-muted-dark uppercase tracking-wide">
            {title}
          </p>
          <p className={cn('text-3xl font-semibold tracking-tight text-text-primary-dark')}>
            {value.toLocaleString()}
          </p>
          {trend && (
            <p
              className={cn(
                'text-xs font-medium inline-flex items-center gap-1 px-2 py-0.5 rounded-full',
                trend.isPositive ? styles.badge : 'bg-red-50 text-red-700'
              )}
            >
              {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
            </p>
          )}
        </div>
        <div className={cn('p-2.5 rounded-xl', styles.icon)}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  )
}

export function StatsGrid() {
  const missionStats = useEventStore((state) => state.missionStats)
  const sessions = useEventStore((state) => state.sessions)
  
  // Calculate active tasks (sessions in this context) - memoize to avoid recalculation
  const activeSessions = React.useMemo(() => 
    Array.from(sessions.values()).filter((s) => s.status === 'active').length
  , [sessions])
  
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <StatCard
        title="Targets Discovered"
        value={missionStats.targets_discovered}
        icon={Target}
        variant="default"
      />
      <StatCard
        title="Vulnerabilities"
        value={missionStats.vulns_found}
        icon={Bug}
        variant="warning"
      />
      <StatCard
        title="Critical Risks"
        value={missionStats.critical_vulns ?? 0}
        icon={AlertTriangle}
        variant="critical"
      />
      <StatCard
        title="Active Sessions"
        value={activeSessions}
        icon={Activity}
        variant="success"
      />
    </div>
  )
}
