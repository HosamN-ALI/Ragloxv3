// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Dashboard Page
// Main dashboard view with stats, network graph, and activity feed
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { StatsGrid } from '@/components/dashboard/StatsGrid'
import { NetworkGraph } from '@/components/dashboard/NetworkGraph'
import { ActivityFeed } from '@/components/dashboard/ActivityFeed'
import { TargetDetailsDrawer } from '@/components/dashboard/TargetDetailsDrawer'
import { HITLApprovalModal } from '@/components/dashboard/HITLApprovalModal'
import { useEventStore } from '@/stores/eventStore'

export function Dashboard() {
  const { pendingApprovals } = useEventStore()
  const [selectedApproval, setSelectedApproval] = React.useState<string | null>(null)
  
  // Show approval modal when new approval comes in
  React.useEffect(() => {
    if (pendingApprovals.length > 0 && !selectedApproval) {
      // Auto-open modal for first pending approval
      // setSelectedApproval(pendingApprovals[0].action_id)
    }
  }, [pendingApprovals, selectedApproval])
  
  const currentApproval = pendingApprovals.find(
    (a) => a.action_id === selectedApproval
  )
  
  return (
    <div className="space-y-8 pb-8">
      {/* Page Header */}
      <div className="flex items-center justify-between border-b border-border-dark/30 pb-6">
        <div>
          <h1 className="text-2xl font-bold text-text-primary-dark tracking-tight">
            Dashboard
          </h1>
          <p className="text-text-secondary-dark mt-1">
            Real-time security operations overview
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-text-muted-dark font-mono">
            Last updated: {new Date().toLocaleTimeString()}
          </span>
        </div>
      </div>
      
      {/* Stats Grid */}
      <section>
        <StatsGrid />
      </section>
      
      {/* Main Content Grid */}
      <section className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Network Graph - Takes 2 columns */}
        <div className="xl:col-span-2">
          <NetworkGraph />
        </div>
        
        {/* Activity Feed - Takes 1 column */}
        <div className="xl:col-span-1">
          <ActivityFeed />
        </div>
      </section>
      
      {/* Target Details Drawer */}
      <TargetDetailsDrawer />
      
      {/* HITL Approval Modal */}
      <HITLApprovalModal
        approval={currentApproval ?? null}
        onClose={() => setSelectedApproval(null)}
      />
    </div>
  )
}
