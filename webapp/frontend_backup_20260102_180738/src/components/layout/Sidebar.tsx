// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Sidebar Component
// Ultra-minimal, icon-only sidebar that expands on hover
// 4 Workspaces: Recon, Operations, Loot, Intelligence
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Target,
  Activity,
  Key,
  Brain,
  Settings,
  Shield,
  Rocket,
  Home,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'
import { useMissionStore } from '@/stores/missionStore'
import type { WorkspaceId } from '@/types'

interface NavItem {
  icon: React.ElementType
  label: string
  href: string
  workspaceId?: WorkspaceId
  badge?: number | 'live'
  badgeColor?: string
}

// Primary workspaces - the 4 main views
const workspaceItems: NavItem[] = [
  { icon: Home, label: 'Overview', href: '/' },
  { icon: Target, label: 'Scope & Recon', href: '/recon', workspaceId: 'recon' },
  { icon: Activity, label: 'Operations', href: '/operations', workspaceId: 'operations' },
  { icon: Key, label: 'Loot & Access', href: '/loot', workspaceId: 'loot' },
]

// Secondary navigation items
const secondaryItems: NavItem[] = [
  { icon: Rocket, label: 'New Mission', href: '/mission/new' },
  { icon: Settings, label: 'Settings', href: '/settings' },
]

export function Sidebar() {
  const [isHovered, setIsHovered] = React.useState(false)
  const { isSidebarCollapsed, setSidebarCollapsed, pendingApprovals } = useEventStore()
  const { systemStatus, activeSessions, credentials } = useMissionStore()
  
  // Determine if sidebar should be expanded
  const isExpanded = !isSidebarCollapsed || isHovered
  
  // Dynamic badges based on mission state
  const getBadge = (item: NavItem): { count?: number | 'live'; color?: string } => {
    switch (item.workspaceId) {
      case 'operations':
        if (systemStatus === 'active') return { count: 'live', color: 'bg-green-500' }
        if (pendingApprovals.length > 0) return { count: pendingApprovals.length, color: 'bg-amber-500' }
        return {}
      case 'loot':
        const sessionCount = activeSessions.size
        const credCount = credentials.size
        if (sessionCount > 0) return { count: sessionCount, color: 'bg-green-500' }
        if (credCount > 0) return { count: credCount, color: 'bg-yellow-500' }
        return {}
      default:
        return {}
    }
  }
  
  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-40 h-screen',
        'flex flex-col transition-all duration-300 ease-out',
        'glass border-r border-white/5',
        isExpanded ? 'w-56' : 'w-[72px]'
      )}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {/* Logo Section */}
      <div className="flex h-16 items-center px-4">
        <div className="flex items-center gap-3">
          <div className={cn(
            'flex h-10 w-10 items-center justify-center rounded-2xl shadow-lg transition-all',
            systemStatus === 'active' 
              ? 'bg-gradient-to-br from-green-500 to-green-600 shadow-green-500/20' 
              : systemStatus === 'emergency_stop'
                ? 'bg-gradient-to-br from-red-500 to-red-600 shadow-red-500/20 animate-pulse'
                : 'bg-gradient-to-br from-royal-blue to-royal-blue-dark shadow-royal-blue/20'
          )}>
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div className={cn(
            'flex flex-col transition-all duration-300 overflow-hidden',
            isExpanded ? 'opacity-100 w-auto' : 'opacity-0 w-0'
          )}>
            <span className="text-base font-semibold text-text-primary-dark tracking-tight whitespace-nowrap">RAGLOX</span>
            <span className={cn(
              'text-[10px] font-mono whitespace-nowrap',
              systemStatus === 'active' ? 'text-green-400' : 'text-text-muted-dark'
            )}>
              v3.0 {systemStatus === 'active' && '• ACTIVE'}
            </span>
          </div>
        </div>
      </div>
      
      {/* Primary Workspaces */}
      <nav className="flex-1 px-3 py-6 space-y-1">
        <div className="mb-2 px-3">
          <span className={cn(
            'text-[10px] font-semibold text-text-muted-dark uppercase tracking-wider transition-opacity',
            isExpanded ? 'opacity-100' : 'opacity-0'
          )}>
            Workspaces
          </span>
        </div>
        
        {workspaceItems.map((item) => {
          const badge = getBadge(item)
          return (
            <NavLink
              key={item.href}
              item={{ ...item, badge: badge.count, badgeColor: badge.color }}
              isExpanded={isExpanded}
            />
          )
        })}
        
        {/* Divider */}
        <div className="my-4 border-t border-zinc-800" />
        
        {/* Secondary Navigation */}
        {secondaryItems.map((item) => (
          <NavLink
            key={item.href}
            item={item}
            isExpanded={isExpanded}
          />
        ))}
      </nav>
      
      {/* AI Co-pilot Toggle */}
      <div className="px-3 pb-2">
        <NavLink
          item={{ icon: Brain, label: 'AI Co-pilot', href: '#ai' }}
          isExpanded={isExpanded}
          onClick={() => {
            // Toggle AI sidebar - this should dispatch to a global state
            const event = new CustomEvent('toggle-ai-sidebar')
            window.dispatchEvent(event)
          }}
        />
      </div>
      
      {/* Pin Toggle (only visible when hovered) */}
      {isHovered && (
        <div className="px-3 pb-4">
          <button
            onClick={() => setSidebarCollapsed(!isSidebarCollapsed)}
            className={cn(
              'w-full flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium',
              'text-text-muted-dark hover:text-text-primary-dark',
              'hover:bg-white/5 transition-all duration-200'
            )}
          >
            <div className={cn(
              'w-3 h-3 rounded-full border-2 transition-colors',
              isSidebarCollapsed 
                ? 'border-text-muted-dark' 
                : 'border-royal-blue bg-royal-blue'
            )} />
            <span className={cn(
              'transition-opacity duration-200',
              isExpanded ? 'opacity-100' : 'opacity-0'
            )}>
              {isSidebarCollapsed ? 'Pin sidebar' : 'Pinned'}
            </span>
          </button>
        </div>
      )}
    </aside>
  )
}

// Navigation Link Component
interface NavLinkProps {
  item: NavItem
  isExpanded: boolean
  onClick?: () => void
}

function NavLink({ item, isExpanded, onClick }: NavLinkProps) {
  const Icon = item.icon
  const location = useLocation()
  const isActive = location.pathname === item.href
  
  // For special actions like AI toggle
  if (onClick) {
    return (
      <button
        onClick={onClick}
        className={cn(
          'w-full relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium',
          'transition-all duration-200 group',
          'text-text-secondary-dark hover:text-text-primary-dark hover:bg-white/5'
        )}
        title={!isExpanded ? item.label : undefined}
      >
        <Icon className="h-5 w-5 flex-shrink-0 transition-transform duration-200 group-hover:scale-110" />
        <span className={cn(
          'whitespace-nowrap transition-all duration-300 overflow-hidden',
          isExpanded ? 'opacity-100 w-auto' : 'opacity-0 w-0'
        )}>
          {item.label}
        </span>
      </button>
    )
  }
  
  return (
    <Link
      to={item.href}
      className={cn(
        'relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium',
        'transition-all duration-200 group',
        isActive
          ? 'bg-royal-blue/10 text-royal-blue'
          : 'text-text-secondary-dark hover:text-text-primary-dark hover:bg-white/5'
      )}
      title={!isExpanded ? item.label : undefined}
    >
      <div className="relative">
        <Icon className={cn(
          'h-5 w-5 flex-shrink-0 transition-transform duration-200',
          !isActive && 'group-hover:scale-110'
        )} />
        
        {/* Badge indicator (compact mode) */}
        {!isExpanded && item.badge && (
          <div className={cn(
            'absolute -top-1 -right-1 flex items-center justify-center',
            'min-w-[14px] h-[14px] rounded-full text-[9px] font-bold text-white',
            item.badgeColor || 'bg-royal-blue'
          )}>
            {item.badge === 'live' ? (
              <div className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
            ) : (
              item.badge
            )}
          </div>
        )}
      </div>
      
      <span className={cn(
        'whitespace-nowrap transition-all duration-300 overflow-hidden',
        isExpanded ? 'opacity-100 w-auto' : 'opacity-0 w-0'
      )}>
        {item.label}
      </span>
      
      {/* Badge (expanded mode) */}
      {isExpanded && item.badge && (
        <div className={cn(
          'ml-auto flex items-center justify-center',
          'min-w-[20px] h-5 px-1.5 rounded-full text-[10px] font-bold text-white',
          item.badgeColor || 'bg-royal-blue'
        )}>
          {item.badge === 'live' ? (
            <div className="flex items-center gap-1">
              <div className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
              <span>LIVE</span>
            </div>
          ) : (
            item.badge
          )}
        </div>
      )}
      
      {isActive && !item.badge && (
        <div className={cn(
          'ml-auto w-1.5 h-1.5 rounded-full bg-royal-blue transition-opacity',
          isExpanded ? 'opacity-100' : 'opacity-0'
        )} />
      )}
    </Link>
  )
}
