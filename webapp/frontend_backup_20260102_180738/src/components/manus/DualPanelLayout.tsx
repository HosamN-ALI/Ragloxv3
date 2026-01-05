// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Dual Panel Layout Component
// Manus-inspired resizable dual-panel layout
// AI Chat on left, Terminal/Content on right
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { Panel, Group as PanelGroup, Separator as PanelResizeHandle } from 'react-resizable-panels'
import { 
  PanelLeft,
  PanelRight,
  Terminal as TerminalIcon,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { AIChatPanel } from './AIChatPanel'
import type { ChatMessage } from './AIChatPanel'
import { TerminalPanel } from './TerminalPanel'
import { PlanView } from './PlanView'
import type { PlanData } from './PlanView'

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

interface TerminalState {
  isOpen: boolean
  command: string
  output: string
  title: string
  isExecuting: boolean
}

interface DualPanelLayoutProps {
  // Chat props
  messages: ChatMessage[]
  onSendMessage: (content: string) => void
  isLoading?: boolean
  
  // Terminal props
  terminalState?: TerminalState
  onTerminalClose?: () => void
  
  // Plan props
  plan?: PlanData
  isPlanExpanded?: boolean
  onPlanToggle?: () => void
  
  // Content (alternative to terminal)
  rightPanelContent?: React.ReactNode
  
  // Layout config
  defaultLeftSize?: number
  minLeftSize?: number
  maxLeftSize?: number
  className?: string
}

// ═══════════════════════════════════════════════════════════════
// Resize Handle Component
// ═══════════════════════════════════════════════════════════════

function ResizeHandle({ className }: { className?: string }) {
  return (
    <PanelResizeHandle
      className={cn(
        "relative w-2 bg-transparent hover:bg-zinc-700/50 transition-colors group",
        "flex items-center justify-center",
        className
      )}
    >
      <div className="absolute inset-y-0 -left-1 -right-1 group-hover:bg-royal-blue/20 transition-colors" />
      <div className="relative z-10 h-8 w-1 rounded-full bg-zinc-700 group-hover:bg-royal-blue transition-colors" />
    </PanelResizeHandle>
  )
}

// ═══════════════════════════════════════════════════════════════
// Panel Toggle Controls
// ═══════════════════════════════════════════════════════════════

interface PanelControlsProps {
  leftPanelVisible: boolean
  rightPanelVisible: boolean
  onToggleLeft: () => void
  onToggleRight: () => void
}

function PanelControls({ 
  leftPanelVisible, 
  rightPanelVisible, 
  onToggleLeft, 
  onToggleRight 
}: PanelControlsProps) {
  return (
    <div className="absolute top-2 right-2 z-20 flex items-center gap-1">
      <button
        onClick={onToggleLeft}
        className={cn(
          "p-1.5 rounded-lg transition-colors",
          leftPanelVisible 
            ? "bg-zinc-800 text-zinc-400 hover:text-white" 
            : "bg-royal-blue/20 text-royal-blue"
        )}
        title={leftPanelVisible ? "Hide AI Panel" : "Show AI Panel"}
      >
        <PanelLeft className="h-4 w-4" />
      </button>
      <button
        onClick={onToggleRight}
        className={cn(
          "p-1.5 rounded-lg transition-colors",
          rightPanelVisible 
            ? "bg-zinc-800 text-zinc-400 hover:text-white" 
            : "bg-royal-blue/20 text-royal-blue"
        )}
        title={rightPanelVisible ? "Hide Terminal" : "Show Terminal"}
      >
        <PanelRight className="h-4 w-4" />
      </button>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Empty Terminal State
// ═══════════════════════════════════════════════════════════════

function EmptyTerminalState() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center p-8">
      <div className="p-4 rounded-2xl bg-zinc-800/50 mb-4">
        <TerminalIcon className="h-12 w-12 text-zinc-600" />
      </div>
      <h3 className="text-lg font-medium text-zinc-400 mb-2">
        Terminal Output
      </h3>
      <p className="text-sm text-zinc-600 max-w-xs">
        Click on a command in the chat to view its output here
      </p>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Dual Panel Layout Component
// ═══════════════════════════════════════════════════════════════

export function DualPanelLayout({
  messages,
  onSendMessage,
  isLoading = false,
  terminalState,
  onTerminalClose,
  plan,
  isPlanExpanded,
  onPlanToggle,
  rightPanelContent,
  defaultLeftSize = 40,
  minLeftSize = 25,
  maxLeftSize = 60,
  className
}: DualPanelLayoutProps) {
  const [leftVisible, setLeftVisible] = React.useState(true)
  const [rightVisible, setRightVisible] = React.useState(true)
  const [activeTerminal, setActiveTerminal] = React.useState<TerminalState | null>(null)
  
  // Handle terminal click from chat
  const handleTerminalClick = React.useCallback((command: string, output?: string) => {
    setActiveTerminal({
      isOpen: true,
      command,
      output: output || '',
      title: 'RAGLOX Terminal',
      isExecuting: false
    })
    setRightVisible(true)
  }, [])
  
  // Handle terminal close
  const handleTerminalClose = React.useCallback(() => {
    setActiveTerminal(null)
    onTerminalClose?.()
  }, [onTerminalClose])
  
  // Use provided terminal state or internal state
  const currentTerminal = terminalState || activeTerminal
  
  // Handle plan expand
  const handlePlanExpand = React.useCallback((expandedPlan: PlanData) => {
    // Could show plan in right panel or modal
    console.log('Plan expanded:', expandedPlan)
  }, [])
  
  return (
    <div className={cn("relative h-full bg-zinc-950", className)}>
      {/* Panel Controls */}
      <PanelControls
        leftPanelVisible={leftVisible}
        rightPanelVisible={rightVisible}
        onToggleLeft={() => setLeftVisible(!leftVisible)}
        onToggleRight={() => setRightVisible(!rightVisible)}
      />
      
      <PanelGroup orientation="horizontal" className="h-full">
        {/* Left Panel - AI Chat */}
        {leftVisible && (
          <Panel
            defaultSize={defaultLeftSize}
            minSize={minLeftSize}
            maxSize={maxLeftSize}
            className="relative"
          >
            <div className="h-full border-r border-zinc-800">
              <AIChatPanel
                messages={messages}
                onSendMessage={onSendMessage}
                onTerminalClick={handleTerminalClick}
                onPlanExpand={handlePlanExpand}
                isLoading={isLoading}
              />
            </div>
          </Panel>
        )}
        
        {/* Resize Handle */}
        {leftVisible && rightVisible && <ResizeHandle />}
        
        {/* Right Panel - Terminal/Content */}
        {rightVisible && (
          <Panel className="relative">
            <div className="h-full bg-zinc-900">
              {/* Plan View (if provided and expanded) */}
              {plan && isPlanExpanded && (
                <div className="absolute top-2 right-2 left-2 z-10">
                  <PlanView
                    plan={plan}
                    isExpanded={isPlanExpanded}
                    onToggleExpand={onPlanToggle}
                  />
                </div>
              )}
              
              {/* Custom Content */}
              {rightPanelContent ? (
                <div className="h-full">
                  {rightPanelContent}
                </div>
              ) : currentTerminal?.isOpen ? (
                /* Terminal Panel */
                <TerminalPanel
                  isOpen={true}
                  onClose={handleTerminalClose}
                  title={currentTerminal.title}
                  command={currentTerminal.command}
                  output={currentTerminal.output}
                  isExecuting={currentTerminal.isExecuting}
                  className="h-full rounded-none border-0"
                />
              ) : (
                /* Empty State */
                <EmptyTerminalState />
              )}
            </div>
          </Panel>
        )}
      </PanelGroup>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Preset Layouts
// ═══════════════════════════════════════════════════════════════

// Full Chat Layout (no terminal)
export function FullChatLayout(props: Omit<DualPanelLayoutProps, 'defaultLeftSize'>) {
  return <DualPanelLayout {...props} defaultLeftSize={100} />
}

// Full Terminal Layout (no chat)
export function FullTerminalLayout(props: Omit<DualPanelLayoutProps, 'defaultLeftSize'>) {
  return <DualPanelLayout {...props} defaultLeftSize={0} />
}

// Compact Chat Layout (30% chat, 70% terminal)
export function CompactChatLayout(props: Omit<DualPanelLayoutProps, 'defaultLeftSize'>) {
  return <DualPanelLayout {...props} defaultLeftSize={30} />
}

// Wide Chat Layout (60% chat, 40% terminal)
export function WideChatLayout(props: Omit<DualPanelLayoutProps, 'defaultLeftSize'>) {
  return <DualPanelLayout {...props} defaultLeftSize={60} />
}

export default DualPanelLayout
