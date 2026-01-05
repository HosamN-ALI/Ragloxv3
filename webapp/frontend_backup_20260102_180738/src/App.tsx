// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Main Application
// Enterprise-Grade SaaS Frontend with Routing
// ═══════════════════════════════════════════════════════════════

import { useEffect, useRef } from 'react'
import { Routes, Route } from 'react-router-dom'
import { Layout } from '@/components/layout/Layout'
import { AIAssistantSidebar } from '@/components/ai/AIAssistantSidebar'
import { Dashboard } from '@/pages/Dashboard'
import { useWebSocket } from '@/hooks/useWebSocket'
import { useEventStore } from '@/stores/eventStore'
import { useMissionData } from '@/hooks/useMissionData'

// Workspace Views
import { ReconView } from '@/components/workspaces/ReconView'
import { OperationsView } from '@/components/workspaces/OperationsView'
import { OperationsViewManus } from '@/components/workspaces/OperationsViewManus'
import { LootView } from '@/components/workspaces/LootView'
import { MissionSetupWizard } from '@/components/wizard/MissionSetupWizard'

function App() {
  // Initialize WebSocket connection
  const { isConnected } = useWebSocket({ autoConnect: true })
  
  // Initialize mission data loading - THIS FIXES THE DATA PIPELINE!
  const { currentMissionId } = useMissionData()
  
  // Track if welcome message was already shown
  const welcomeShownRef = useRef(false)
  
  // Access store for logging
  const { addLog, addActivity } = useEventStore()
  
  // Log when mission changes
  useEffect(() => {
    if (currentMissionId) {
      console.log('[App] Active mission:', currentMissionId)
    }
  }, [currentMissionId])
  
  useEffect(() => {
    // Only show welcome message once per session
    if (isConnected && !welcomeShownRef.current) {
      welcomeShownRef.current = true
      
      // Add a welcome log with unique ID based on timestamp
      const timestamp = new Date().toISOString()
      addLog({
        id: `welcome-log-${Date.now()}`,
        timestamp,
        level: 'info',
        message: 'Connected to RAGLOX v3.0 backend. WebSocket established.',
        specialist: 'System',
      })
      
      addActivity({
        type: 'status_change',
        title: 'System Ready',
        description: 'Connected to RAGLOX backend. Ready for operations.',
        timestamp,
      })
    }
  }, [isConnected, addLog, addActivity])
  
  return (
    <>
      <Layout>
        <Routes>
          {/* Dashboard / Overview */}
          <Route path="/" element={<Dashboard />} />
          
          {/* Workspace A - Scope & Recon */}
          <Route path="/recon" element={<ReconView />} />
          
          {/* Workspace B - Active Operations (Manus Style) */}
          <Route path="/operations" element={<OperationsViewManus />} />
          
          {/* Workspace B - Active Operations (Legacy) */}
          <Route path="/operations-legacy" element={<OperationsView />} />
          
          {/* Workspace C - Loot & Access */}
          <Route path="/loot" element={<LootView />} />
          
          {/* New Mission Wizard */}
          <Route path="/mission/new" element={<MissionSetupWizard />} />
          
          {/* Settings (placeholder) */}
          <Route path="/settings" element={
            <div className="p-6">
              <h1 className="text-2xl font-bold text-text-primary-dark mb-4">Settings</h1>
              <p className="text-text-secondary-dark">Settings page coming soon...</p>
            </div>
          } />
          
          {/* 404 Fallback */}
          <Route path="*" element={
            <div className="flex flex-col items-center justify-center h-full p-6">
              <h1 className="text-4xl font-bold text-text-primary-dark mb-2">404</h1>
              <p className="text-text-secondary-dark mb-4">Page not found</p>
              <a href="/" className="text-royal-blue hover:underline">Go back home</a>
            </div>
          } />
        </Routes>
      </Layout>
      
      {/* AI Assistant Sidebar (renders conditionally based on state) */}
      <AIAssistantSidebar />
    </>
  )
}

export default App
