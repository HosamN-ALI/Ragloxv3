// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Workspace A: Scope & Recon View
// Asset discovery and reconnaissance data visualization
// ═══════════════════════════════════════════════════════════════

import { useState, useMemo } from 'react'
import { useShallow } from 'zustand/shallow'
import {
  Target,
  Filter,
  Grid,
  List,
  Monitor,
  Terminal as TerminalIcon,
  Network,
  Server,
  Search,
  RefreshCw,
  Download,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'
import { AssetCardGrid } from '@/components/assets/AssetCard'
import type { Target as TargetType, Vulnerability } from '@/types'

// ═══════════════════════════════════════════════════════════════
// Filter Options
// ═══════════════════════════════════════════════════════════════

type GroupByOption = 'none' | 'os' | 'priority' | 'status' | 'subnet'
type ViewMode = 'grid' | 'list'

// ═══════════════════════════════════════════════════════════════
// Toolbar Component
// ═══════════════════════════════════════════════════════════════

interface ToolbarProps {
  searchTerm: string
  onSearchChange: (term: string) => void
  groupBy: GroupByOption
  onGroupByChange: (option: GroupByOption) => void
  viewMode: ViewMode
  onViewModeChange: (mode: ViewMode) => void
  targetCount: number
  onRefresh?: () => void
  onExport?: () => void
}

function Toolbar({
  searchTerm,
  onSearchChange,
  groupBy,
  onGroupByChange,
  viewMode,
  onViewModeChange,
  targetCount,
  onRefresh,
  onExport,
}: ToolbarProps) {
  return (
    <div className="flex items-center justify-between gap-4 mb-6">
      {/* Left: Search & Filter */}
      <div className="flex items-center gap-3 flex-1">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted-dark" />
          <input
            type="text"
            placeholder="Search by IP, hostname, or OS..."
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
            className={cn(
              'w-full pl-10 pr-4 py-2 rounded-xl text-sm',
              'bg-zinc-800 border border-zinc-700 text-text-primary-dark',
              'placeholder:text-text-muted-dark',
              'focus:outline-none focus:border-royal-blue focus:ring-1 focus:ring-royal-blue/50'
            )}
          />
        </div>
        
        {/* Group By */}
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-text-muted-dark" />
          <select
            value={groupBy}
            onChange={(e) => onGroupByChange(e.target.value as GroupByOption)}
            className={cn(
              'px-3 py-2 rounded-xl text-sm appearance-none',
              'bg-zinc-800 border border-zinc-700 text-text-secondary-dark',
              'focus:outline-none focus:border-royal-blue cursor-pointer'
            )}
          >
            <option value="none">No Grouping</option>
            <option value="os">Group by OS</option>
            <option value="priority">Group by Priority</option>
            <option value="status">Group by Status</option>
            <option value="subnet">Group by Subnet</option>
          </select>
        </div>
      </div>
      
      {/* Right: View Mode & Actions */}
      <div className="flex items-center gap-3">
        {/* Target Count */}
        <span className="text-sm text-text-muted-dark">
          <span className="font-semibold text-text-secondary-dark">{targetCount}</span> targets
        </span>
        
        {/* View Toggle */}
        <div className="flex items-center gap-1 p-1 rounded-xl bg-zinc-800 border border-zinc-700">
          <button
            onClick={() => onViewModeChange('grid')}
            className={cn(
              'p-1.5 rounded-lg transition-colors',
              viewMode === 'grid' ? 'bg-zinc-700 text-text-primary-dark' : 'text-text-muted-dark hover:text-text-secondary-dark'
            )}
          >
            <Grid className="h-4 w-4" />
          </button>
          <button
            onClick={() => onViewModeChange('list')}
            className={cn(
              'p-1.5 rounded-lg transition-colors',
              viewMode === 'list' ? 'bg-zinc-700 text-text-primary-dark' : 'text-text-muted-dark hover:text-text-secondary-dark'
            )}
          >
            <List className="h-4 w-4" />
          </button>
        </div>
        
        {/* Refresh */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="p-2 rounded-xl bg-zinc-800 border border-zinc-700 text-text-muted-dark hover:text-text-secondary-dark hover:border-zinc-600 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        )}
        
        {/* Export */}
        {onExport && (
          <button
            onClick={onExport}
            className="p-2 rounded-xl bg-zinc-800 border border-zinc-700 text-text-muted-dark hover:text-text-secondary-dark hover:border-zinc-600 transition-colors"
          >
            <Download className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Stats Bar Component
// ═══════════════════════════════════════════════════════════════

interface StatsBarProps {
  targets: TargetType[]
  vulnerabilities: Map<string, Vulnerability>
}

function StatsBar({ targets, vulnerabilities }: StatsBarProps) {
  const stats = useMemo(() => {
    const byOS: Record<string, number> = {}
    const byStatus: Record<string, number> = {}
    let totalPorts = 0
    let ownedCount = 0
    
    targets.forEach(t => {
      const os = t.os?.split(' ')[0] || 'Unknown'
      byOS[os] = (byOS[os] || 0) + 1
      byStatus[t.status] = (byStatus[t.status] || 0) + 1
      totalPorts += Object.keys(t.ports).length
      if (t.status === 'owned') ownedCount++
    })
    
    return { byOS, byStatus, totalPorts, ownedCount, vulnCount: vulnerabilities.size }
  }, [targets, vulnerabilities])
  
  return (
    <div className="grid grid-cols-5 gap-3 mb-6">
      {/* Targets */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Target className="h-4 w-4 text-blue-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Targets</span>
        </div>
        <span className="text-2xl font-bold text-text-primary-dark">{targets.length}</span>
      </div>
      
      {/* Open Ports */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Network className="h-4 w-4 text-cyan-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Open Ports</span>
        </div>
        <span className="text-2xl font-bold text-cyan-400">{stats.totalPorts}</span>
      </div>
      
      {/* Vulnerabilities */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Server className="h-4 w-4 text-orange-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Vulns</span>
        </div>
        <span className="text-2xl font-bold text-orange-400">{stats.vulnCount}</span>
      </div>
      
      {/* Owned */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Monitor className="h-4 w-4 text-green-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Owned</span>
        </div>
        <span className="text-2xl font-bold text-green-400">{stats.ownedCount}</span>
      </div>
      
      {/* OS Distribution */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <TerminalIcon className="h-4 w-4 text-purple-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">OS Types</span>
        </div>
        <div className="flex flex-wrap gap-1">
          {Object.entries(stats.byOS).slice(0, 3).map(([os, count]) => (
            <span key={os} className="text-[10px] text-text-muted-dark bg-zinc-800 px-1.5 py-0.5 rounded">
              {os}: {count}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Deep Dive Drawer Content
// ═══════════════════════════════════════════════════════════════

interface DeepDiveDrawerProps {
  target: TargetType | null
  vulnerabilities: Vulnerability[]
  onClose: () => void
}

function DeepDiveDrawer({ target, vulnerabilities, onClose }: DeepDiveDrawerProps) {
  if (!target) return null
  
  const targetVulns = vulnerabilities.filter(v => v.target_id === target.target_id)
  
  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-zinc-900 border-l border-zinc-800 shadow-2xl z-40 flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-zinc-800">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-lg font-bold text-text-primary-dark">Target Details</h2>
          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-zinc-800 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
          >
            ×
          </button>
        </div>
        <p className="text-sm font-mono text-text-secondary-dark">{target.ip}</p>
      </div>
      
      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Basic Info */}
        <section>
          <h3 className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider mb-2">
            Basic Information
          </h3>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-text-muted-dark">Hostname</span>
              <span className="text-text-secondary-dark font-mono">{target.hostname || 'N/A'}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-text-muted-dark">OS</span>
              <span className="text-text-secondary-dark">{target.os || 'Unknown'}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-text-muted-dark">Status</span>
              <span className={cn(
                'uppercase text-[10px] px-2 py-0.5 rounded-full font-semibold',
                target.status === 'owned' && 'bg-green-500/20 text-green-400',
                target.status === 'exploited' && 'bg-red-500/20 text-red-400',
                target.status === 'discovered' && 'bg-blue-500/20 text-blue-400'
              )}>
                {target.status}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-text-muted-dark">Priority</span>
              <span className={cn(
                'uppercase text-[10px] px-2 py-0.5 rounded-full font-semibold',
                target.priority === 'critical' && 'bg-red-500/20 text-red-400',
                target.priority === 'high' && 'bg-orange-500/20 text-orange-400',
                target.priority === 'medium' && 'bg-yellow-500/20 text-yellow-400',
                target.priority === 'low' && 'bg-blue-500/20 text-blue-400'
              )}>
                {target.priority}
              </span>
            </div>
          </div>
        </section>
        
        {/* Open Ports */}
        <section>
          <h3 className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider mb-2">
            Open Ports ({Object.keys(target.ports).length})
          </h3>
          <div className="space-y-1">
            {Object.entries(target.ports).map(([port, service]) => (
              <div key={port} className="flex items-center justify-between p-2 rounded-lg bg-zinc-800/50">
                <span className="text-sm font-mono text-text-primary-dark">{port}</span>
                <span className="text-xs text-text-muted-dark uppercase">{service}</span>
              </div>
            ))}
          </div>
        </section>
        
        {/* Vulnerabilities */}
        <section>
          <h3 className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider mb-2">
            Vulnerabilities ({targetVulns.length})
          </h3>
          {targetVulns.length === 0 ? (
            <p className="text-sm text-text-muted-dark italic">No vulnerabilities found</p>
          ) : (
            <div className="space-y-2">
              {targetVulns.map((vuln) => (
                <div key={vuln.vuln_id} className={cn(
                  'p-3 rounded-lg border',
                  vuln.severity === 'critical' && 'bg-red-500/10 border-red-500/30',
                  vuln.severity === 'high' && 'bg-orange-500/10 border-orange-500/30',
                  vuln.severity === 'medium' && 'bg-yellow-500/10 border-yellow-500/30',
                  vuln.severity === 'low' && 'bg-blue-500/10 border-blue-500/30'
                )}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-semibold text-text-primary-dark">{vuln.type}</span>
                    <span className={cn(
                      'text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded',
                      vuln.severity === 'critical' && 'text-red-400',
                      vuln.severity === 'high' && 'text-orange-400',
                      vuln.severity === 'medium' && 'text-yellow-400'
                    )}>
                      {vuln.severity}
                    </span>
                  </div>
                  {vuln.name && (
                    <p className="text-xs text-text-muted-dark">{vuln.name}</p>
                  )}
                  {vuln.exploit_available && (
                    <span className="inline-block mt-2 text-[10px] bg-green-500/20 text-green-400 px-1.5 py-0.5 rounded">
                      Exploit Available
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>
        
        {/* Raw Nmap Output (Simulated) */}
        <section>
          <h3 className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider mb-2">
            Raw Scan Data
          </h3>
          <pre className="p-3 rounded-lg bg-zinc-800/80 text-[10px] font-mono text-text-muted-dark overflow-x-auto">
{`# Nmap scan report for ${target.ip}
Host is up (0.00042s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE     VERSION
${Object.entries(target.ports).map(([p, s]) => `${p.padEnd(8)} open  ${s.padEnd(11)}`).join('\n')}

OS details: ${target.os || 'Unknown'}
`}
          </pre>
        </section>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Recon View Component
// ═══════════════════════════════════════════════════════════════

export interface ReconViewProps {
  onRefresh?: () => void
  onExport?: () => void
}

export function ReconView({ onRefresh, onExport }: ReconViewProps) {
  // Get store state with shallow comparison to prevent infinite loops
  const { targetsMap, vulnsMap } = useEventStore(
    useShallow((state) => ({
      targetsMap: state.targets,
      vulnsMap: state.vulnerabilities,
    }))
  )
  
  // Convert Maps to arrays in useMemo
  const targets = useMemo(() => Array.from(targetsMap.values()), [targetsMap])
  const vulnerabilities = vulnsMap
  
  const [searchTerm, setSearchTerm] = useState('')
  const [groupBy, setGroupBy] = useState<GroupByOption>('none')
  const [viewMode, setViewMode] = useState<ViewMode>('grid')
  const [selectedTarget, setSelectedTarget] = useState<TargetType | null>(null)
  
  // Filter targets
  const filteredTargets = useMemo(() => {
    if (!searchTerm) return targets
    
    const term = searchTerm.toLowerCase()
    return targets.filter(t =>
      t.ip.toLowerCase().includes(term) ||
      t.hostname?.toLowerCase().includes(term) ||
      t.os?.toLowerCase().includes(term)
    )
  }, [targets, searchTerm])
  
  // Build vulnerability map by target
  const vulnsByTarget = useMemo(() => {
    const map = new Map<string, string[]>()
    vulnerabilities.forEach((vuln) => {
      const existing = map.get(vuln.target_id) || []
      existing.push(vuln.type)
      map.set(vuln.target_id, existing)
    })
    return map
  }, [vulnerabilities])
  
  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-bold text-text-primary-dark mb-1">
          Scope & Reconnaissance
        </h1>
        <p className="text-sm text-text-muted-dark">
          Discovered assets, services, and vulnerability findings
        </p>
      </div>
      
      {/* Stats Bar */}
      <StatsBar targets={targets} vulnerabilities={vulnerabilities} />
      
      {/* Toolbar */}
      <Toolbar
        searchTerm={searchTerm}
        onSearchChange={setSearchTerm}
        groupBy={groupBy}
        onGroupByChange={setGroupBy}
        viewMode={viewMode}
        onViewModeChange={setViewMode}
        targetCount={filteredTargets.length}
        onRefresh={onRefresh}
        onExport={onExport}
      />
      
      {/* Asset Grid */}
      <div className="flex-1 overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-transparent">
        <AssetCardGrid
          targets={filteredTargets}
          groupBy={groupBy}
          vulnerabilities={vulnsByTarget}
          onTargetClick={setSelectedTarget}
          selectedTargetId={selectedTarget?.target_id || null}
        />
      </div>
      
      {/* Deep Dive Drawer */}
      {selectedTarget && (
        <>
          {/* Backdrop */}
          <div 
            className="fixed inset-0 bg-black/50 z-30"
            onClick={() => setSelectedTarget(null)}
          />
          <DeepDiveDrawer
            target={selectedTarget}
            vulnerabilities={Array.from(vulnerabilities.values())}
            onClose={() => setSelectedTarget(null)}
          />
        </>
      )}
    </div>
  )
}

export default ReconView
