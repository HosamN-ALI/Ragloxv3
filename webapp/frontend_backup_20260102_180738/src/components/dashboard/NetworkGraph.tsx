// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - NetworkGraph Component
// Glassmorphic container with minimal legend
// Inspired by Manus.im / Modern Agentic Design
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Network, Layers } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'
import type { GraphNode, GraphLink } from '@/types'

// Node colors based on status
const statusColors: Record<string, string> = {
  discovered: '#3B82F6',  // Blue
  scanning: '#F59E0B',    // Yellow
  scanned: '#10B981',     // Green
  exploiting: '#F59E0B',  // Yellow
  exploited: '#EF4444',   // Red
  owned: '#DC2626',       // Dark Red
  failed: '#6B7280',      // Gray
  cluster: '#8B5CF6',     // Purple for clusters
}

// Priority colors
const priorityColors: Record<string, string> = {
  critical: '#EF4444',
  high: '#F59E0B',
  medium: '#3B82F6',
  low: '#10B981',
}

// Status constants for filtering
const STATUS = {
  CRITICAL: 'critical',
  EXPLOITED: 'exploited',
  OWNED: 'owned',
  SCANNING: 'scanning',
  EXPLOITING: 'exploiting',
} as const

type FilterType = 'all' | 'critical' | 'exploited' | 'scanning'

export function NetworkGraph() {
  const containerRef = React.useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = React.useState({ width: 600, height: 400 })
  const [filter, setFilter] = React.useState<FilterType>('all')
  
  // Get state with stable selectors
  const graphData = useEventStore((state) => state.graphData)
  const targetCount = useEventStore((state) => state.targets.size)
  const updateGraphData = useEventStore((state) => state.updateGraphData)
  const setSelectedTarget = useEventStore((state) => state.setSelectedTarget)
  
  // Local copy of graph data with filtering
  const [localGraphData, setLocalGraphData] = React.useState<{ nodes: GraphNode[], links: GraphLink[] }>({ nodes: [], links: [] })
  
  // Update local graph data when store changes or filter changes
  React.useEffect(() => {
    let filteredNodes = [...graphData.nodes]
    
    if (filter !== 'all') {
      filteredNodes = graphData.nodes.filter(node => {
        if (filter === 'critical') return node.priority === STATUS.CRITICAL
        if (filter === 'exploited') return node.status === STATUS.EXPLOITED || node.status === STATUS.OWNED
        if (filter === 'scanning') return node.status === STATUS.SCANNING || node.status === STATUS.EXPLOITING
        return true
      })
    }
    
    setLocalGraphData({
      nodes: filteredNodes,
      links: [...graphData.links].filter(link => 
        filteredNodes.some(n => n.id === link.source) && 
        filteredNodes.some(n => n.id === link.target)
      ),
    })
  }, [graphData.nodes, graphData.links, filter])
  
  // Update graph data when targets change
  React.useEffect(() => {
    updateGraphData()
  }, [targetCount, updateGraphData])
  
  // Handle container resize
  React.useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const { width, height } = containerRef.current.getBoundingClientRect()
        setDimensions({ width, height: Math.max(height, 300) })
      }
    }
    
    updateDimensions()
    window.addEventListener('resize', updateDimensions)
    return () => window.removeEventListener('resize', updateDimensions)
  }, [])
  
  // Node click handler
  const handleNodeClick = React.useCallback(
    (node: { id?: string | number; type?: string }) => {
      if (node.type === 'target' && node.id) {
        setSelectedTarget(String(node.id))
      }
    },
    [setSelectedTarget]
  )
  
  // Custom node rendering
  const nodeCanvasObject = React.useCallback(
    (
      node: { x?: number; y?: number; name?: string; type?: string; status?: string; priority?: string; childCount?: number },
      ctx: CanvasRenderingContext2D,
      globalScale: number
    ) => {
      const label = node.name || ''
      const fontSize = 10 / globalScale
      const nodeSize = node.type === 'subnet' ? 14 : 10
      
      // Draw node circle with subtle glow
      const color = node.type === 'subnet'
        ? statusColors.cluster
        : statusColors[node.status as string] || statusColors.discovered
      
      // Glow effect
      ctx.beginPath()
      ctx.arc(node.x || 0, node.y || 0, nodeSize + 4, 0, 2 * Math.PI)
      ctx.fillStyle = `${color}20`
      ctx.fill()
      
      // Main circle
      ctx.beginPath()
      ctx.arc(node.x || 0, node.y || 0, nodeSize, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()
      
      // Border for priority
      if (node.priority) {
        ctx.strokeStyle = priorityColors[node.priority] || '#3B82F6'
        ctx.lineWidth = 2 / globalScale
        ctx.stroke()
      }
      
      // Draw child count for clusters
      if (node.type === 'subnet' && node.childCount) {
        ctx.font = `bold ${fontSize * 1.2}px Inter`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillStyle = '#FFFFFF'
        ctx.fillText(String(node.childCount), node.x || 0, node.y || 0)
      }
      
      // Draw label
      ctx.font = `${fontSize}px Inter`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'top'
      ctx.fillStyle = '#94A3B8'
      ctx.fillText(label, node.x || 0, (node.y || 0) + nodeSize + 4)
    },
    []
  )
  
  // Link rendering
  const linkColor = React.useCallback((link: { type?: string }) => {
    switch (link.type) {
      case 'attack_path':
        return 'rgba(239, 68, 68, 0.5)'
      case 'lateral':
        return 'rgba(245, 158, 11, 0.5)'
      default:
        return 'rgba(51, 65, 85, 0.3)'
    }
  }, [])
  
  const filters: { value: FilterType; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'critical', label: 'Critical' },
    { value: 'exploited', label: 'Exploited' },
    { value: 'scanning', label: 'Active' },
  ]
  
  return (
    <div className="rounded-2xl glass border border-white/5 shadow-lg overflow-hidden">
      {/* Minimal Header */}
      <div className="flex items-center justify-between px-5 py-3">
        <div className="flex items-center gap-2">
          <Network className="h-4 w-4 text-text-muted-dark" />
          <span className="text-sm font-medium text-text-primary-dark">Network Topology</span>
        </div>
        
        {/* Filter Buttons */}
        <div className="flex items-center gap-1">
          {filters.map((f) => (
            <button
              key={f.value}
              onClick={() => setFilter(f.value)}
              className={cn(
                'px-2.5 py-1 rounded-lg text-xs font-medium transition-all',
                filter === f.value
                  ? 'bg-royal-blue/10 text-royal-blue'
                  : 'text-text-muted-dark hover:text-text-primary-dark hover:bg-white/5'
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>
      
      {/* Graph Container */}
      <div className="relative h-[340px]" ref={containerRef}>
        {localGraphData.nodes.length > 0 ? (
          <ForceGraph2D
            graphData={localGraphData}
            width={dimensions.width}
            height={dimensions.height}
            backgroundColor="transparent"
            nodeCanvasObject={nodeCanvasObject}
            nodeCanvasObjectMode={() => 'replace'}
            linkColor={linkColor}
            linkWidth={1}
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={1}
            onNodeClick={handleNodeClick}
            cooldownTime={2000}
            d3AlphaDecay={0.02}
            d3VelocityDecay={0.3}
          />
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-text-muted-dark">
            <div className="p-4 rounded-2xl bg-white/5 mb-4">
              <Layers className="h-10 w-10 opacity-30" />
            </div>
            <p className="text-sm font-medium">No targets discovered</p>
            <p className="text-xs mt-1 text-text-muted-dark/70">Start a mission to visualize the network</p>
          </div>
        )}
        
        {/* Floating Stats Badge */}
        {localGraphData.nodes.length > 0 && (
          <div className="absolute bottom-3 left-3 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-black/40 backdrop-blur-sm">
            <span className="text-[10px] text-text-muted-dark">{localGraphData.nodes.length} nodes</span>
            <span className="text-[10px] text-text-muted-dark">•</span>
            <span className="text-[10px] text-text-muted-dark">{targetCount} targets</span>
          </div>
        )}
      </div>
      
      {/* Inline Legend */}
      <div className="flex items-center gap-4 px-5 py-2.5 border-t border-white/5">
        <LegendDot color={statusColors.discovered} label="Discovered" />
        <LegendDot color={statusColors.scanned} label="Scanned" />
        <LegendDot color={statusColors.exploited} label="Exploited" />
        <LegendDot color={statusColors.cluster} label="Subnet" />
      </div>
    </div>
  )
}

// Legend Dot Component - Minimal
function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <div
        className="h-2 w-2 rounded-full"
        style={{ backgroundColor: color }}
      />
      <span className="text-[10px] text-text-muted-dark">{label}</span>
    </div>
  )
}
