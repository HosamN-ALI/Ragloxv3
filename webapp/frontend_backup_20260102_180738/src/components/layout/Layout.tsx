// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Main Layout Component
// Clean, minimal layout with floating elements
// Inspired by Manus.im / Modern Agentic Design
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { cn } from '@/lib/utils'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { GlobalConsole } from './GlobalConsole'
import { ToastContainer } from '@/components/ui/Toast'
import { useEventStore } from '@/stores/eventStore'

interface LayoutProps {
  children: React.ReactNode
}

export function Layout({ children }: LayoutProps) {
  const { isSidebarCollapsed, isConsoleExpanded } = useEventStore()
  
  return (
    <div className="min-h-screen bg-gradient-to-b from-bg-dark via-bg-dark to-[#020617]">
      {/* Sidebar */}
      <Sidebar />
      
      {/* Header */}
      <Header />
      
      {/* Main Content Area */}
      <main
        className={cn(
          'pt-16 transition-all duration-300 ease-out',
          isSidebarCollapsed ? 'ml-[72px]' : 'ml-56',
          isConsoleExpanded ? 'pb-64' : 'pb-12'
        )}
      >
        <div className="px-6 py-6">{children}</div>
      </main>
      
      {/* Global Console */}
      <GlobalConsole />
      
      {/* Toast Notifications */}
      <ToastContainer />
    </div>
  )
}
