// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Intelligence Sidebar (AI Co-pilot)
// Persistent AI assistant providing insights and recommendations
// Workspace D: Intelligence Panel
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { useState, useRef, useEffect } from 'react'
import {
  Brain,
  Lightbulb,
  AlertTriangle,
  TrendingUp,
  Target,
  ChevronRight,
  Send,
  Sparkles,
  Eye,
  Key,
  Network,
  X,
  Minimize2,
  Maximize2,
  MessageSquare,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useMissionStore } from '@/stores/missionStore'
import { useEventStore } from '@/stores/eventStore'
import type { AIInsight, Priority } from '@/types'

// ═══════════════════════════════════════════════════════════════
// Insight Type Configuration
// ═══════════════════════════════════════════════════════════════

interface InsightTypeConfig {
  icon: React.ElementType
  color: string
  bgColor: string
  borderColor: string
  label: string
}

const insightTypeConfig: Record<AIInsight['type'], InsightTypeConfig> = {
  finding: { icon: Eye, color: 'text-cyan-400', bgColor: 'bg-cyan-500/10', borderColor: 'border-cyan-500/30', label: 'Finding' },
  recommendation: { icon: Lightbulb, color: 'text-yellow-400', bgColor: 'bg-yellow-500/10', borderColor: 'border-yellow-500/30', label: 'Recommendation' },
  warning: { icon: AlertTriangle, color: 'text-orange-400', bgColor: 'bg-orange-500/10', borderColor: 'border-orange-500/30', label: 'Warning' },
  opportunity: { icon: TrendingUp, color: 'text-green-400', bgColor: 'bg-green-500/10', borderColor: 'border-green-500/30', label: 'Opportunity' },
}

const priorityConfig: Record<Priority, { color: string; dot: string }> = {
  critical: { color: 'text-red-400', dot: 'bg-red-500' },
  high: { color: 'text-orange-400', dot: 'bg-orange-500' },
  medium: { color: 'text-yellow-400', dot: 'bg-yellow-500' },
  low: { color: 'text-blue-400', dot: 'bg-blue-500' },
}

// ═══════════════════════════════════════════════════════════════
// Insight Card Component
// ═══════════════════════════════════════════════════════════════

interface InsightCardProps {
  insight: AIInsight
  onAction?: () => void
}

function InsightCard({ insight, onAction }: InsightCardProps) {
  const config = insightTypeConfig[insight.type]
  const priority = priorityConfig[insight.priority]
  const Icon = config.icon
  
  return (
    <div className={cn(
      'p-3 rounded-xl border transition-all hover:bg-zinc-800/50',
      config.borderColor, config.bgColor
    )}>
      <div className="flex items-start gap-3">
        <div className={cn('p-2 rounded-lg', config.bgColor)}>
          <Icon className={cn('h-4 w-4', config.color)} />
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={cn('text-[10px] font-semibold uppercase tracking-wider', config.color)}>
              {config.label}
            </span>
            <div className={cn('w-1.5 h-1.5 rounded-full', priority.dot)} />
          </div>
          
          <h4 className="text-sm font-semibold text-text-primary-dark mb-1">
            {insight.title}
          </h4>
          
          <p className="text-xs text-text-muted-dark line-clamp-2">
            {insight.description}
          </p>
          
          {insight.suggested_action && (
            <button
              onClick={onAction}
              className={cn(
                'mt-2 flex items-center gap-1 text-xs font-medium transition-colors',
                config.color, 'hover:underline'
              )}
            >
              {insight.suggested_action}
              <ChevronRight className="h-3 w-3" />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Chat Message Component
// ═══════════════════════════════════════════════════════════════

interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: string
}

function ChatMessageItem({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user'
  
  return (
    <div className={cn('flex gap-3', isUser && 'flex-row-reverse')}>
      <div className={cn(
        'flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center',
        isUser ? 'bg-royal-blue' : 'bg-zinc-700'
      )}>
        {isUser ? (
          <span className="text-xs font-bold text-white">U</span>
        ) : (
          <Brain className="h-4 w-4 text-text-secondary-dark" />
        )}
      </div>
      
      <div className={cn(
        'flex-1 p-3 rounded-xl text-sm',
        isUser ? 'bg-royal-blue/20 text-text-primary-dark' : 'bg-zinc-800/80 text-text-secondary-dark'
      )}>
        <p className="whitespace-pre-wrap">{message.content}</p>
        <span className="text-[10px] text-text-muted-dark mt-1 block">
          {new Date(message.timestamp).toLocaleTimeString()}
        </span>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Context Summary Component
// ═══════════════════════════════════════════════════════════════

function ContextSummary() {
  const { missionPhase, systemStatus, credentials } = useMissionStore()
  const missionStats = useEventStore(s => s.missionStats)
  const vulnerabilities = useEventStore(s => s.vulnerabilities)
  
  const criticalVulns = Array.from(vulnerabilities.values()).filter(v => v.severity === 'critical')
  
  return (
    <div className="p-3 rounded-xl bg-zinc-800/50 border border-zinc-700 space-y-3">
      <div className="flex items-center gap-2">
        <Sparkles className="h-4 w-4 text-purple-400" />
        <span className="text-xs font-semibold text-text-secondary-dark uppercase tracking-wider">
          Current Context
        </span>
      </div>
      
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-blue-400" />
          <span className="text-text-muted-dark">Phase:</span>
          <span className="text-text-secondary-dark font-medium capitalize">
            {missionPhase.replace('_', ' ')}
          </span>
        </div>
        
        <div className="flex items-center gap-2">
          <div className={cn(
            'w-2 h-2 rounded-full',
            systemStatus === 'active' && 'bg-green-400 animate-pulse',
            systemStatus === 'standby' && 'bg-zinc-400',
            systemStatus === 'paused' && 'bg-yellow-400'
          )} />
          <span className="text-text-muted-dark">Status:</span>
          <span className="text-text-secondary-dark font-medium capitalize">
            {systemStatus}
          </span>
        </div>
        
        <div className="flex items-center gap-2">
          <Target className="h-3 w-3 text-text-muted-dark" />
          <span className="text-text-secondary-dark">
            {missionStats.targets_discovered} targets
          </span>
        </div>
        
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-3 w-3 text-red-400" />
          <span className="text-text-secondary-dark">
            {criticalVulns.length} critical vulns
          </span>
        </div>
        
        <div className="flex items-center gap-2">
          <Key className="h-3 w-3 text-yellow-400" />
          <span className="text-text-secondary-dark">
            {credentials.size} credentials
          </span>
        </div>
        
        <div className="flex items-center gap-2">
          <Network className="h-3 w-3 text-green-400" />
          <span className="text-text-secondary-dark">
            {missionStats.sessions_established} sessions
          </span>
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Intelligence Sidebar Component
// ═══════════════════════════════════════════════════════════════

export interface IntelligenceSidebarProps {
  isOpen: boolean
  onClose: () => void
  onMinimize?: () => void
  isMinimized?: boolean
}

export function IntelligenceSidebar({
  isOpen,
  onClose,
  onMinimize,
  isMinimized = false,
}: IntelligenceSidebarProps) {
  const { aiRecommendations } = useMissionStore()
  const chatMessages = useEventStore(s => s.chatMessages)
  
  const [inputValue, setInputValue] = useState('')
  const [activeTab, setActiveTab] = useState<'insights' | 'chat'>('insights')
  const messagesEndRef = useRef<HTMLDivElement>(null)
  
  // Generate demo insights based on mission state
  const insights: AIInsight[] = React.useMemo(() => {
    const result: AIInsight[] = []
    
    // Add recommendations from store
    aiRecommendations.forEach((rec, idx) => {
      result.push({
        id: `rec-${idx}`,
        type: 'recommendation',
        title: 'AI Recommendation',
        description: rec,
        priority: 'medium',
        timestamp: new Date().toISOString(),
      })
    })
    
    // Add some contextual insights (in real app, these come from backend AI)
    result.push({
      id: 'insight-1',
      type: 'finding',
      title: 'Database Credentials Found',
      description: 'Discovered database credentials in a flat file (~/.db_creds). Consider pivoting to the database service.',
      priority: 'high',
      suggested_action: 'Pivot to Database',
      timestamp: new Date().toISOString(),
    })
    
    result.push({
      id: 'insight-2',
      type: 'opportunity',
      title: 'Weak SSH Authentication',
      description: 'Multiple targets have SSH with password authentication enabled. High success rate for credential stuffing.',
      priority: 'high',
      suggested_action: 'Launch SSH Brute Force',
      timestamp: new Date().toISOString(),
    })
    
    result.push({
      id: 'insight-3',
      type: 'warning',
      title: 'Detection Risk',
      description: 'Multiple failed login attempts detected. Consider reducing scan intensity to avoid triggering alerts.',
      priority: 'medium',
      timestamp: new Date().toISOString(),
    })
    
    return result.slice(0, 5) // Limit to 5 most recent
  }, [aiRecommendations])
  
  // Scroll to bottom on new messages
  useEffect(() => {
    if (activeTab === 'chat') {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [chatMessages, activeTab])
  
  const handleSendMessage = () => {
    if (!inputValue.trim()) return
    
    // In real app, this would send to backend AI
    console.log('Sending message:', inputValue)
    setInputValue('')
  }
  
  if (!isOpen) return null
  
  return (
    <div className={cn(
      'fixed right-0 top-0 h-full bg-zinc-900 border-l border-zinc-800 shadow-2xl z-40',
      'flex flex-col transition-all duration-300',
      isMinimized ? 'w-14' : 'w-96'
    )}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-zinc-800">
        {!isMinimized && (
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-purple-500/20">
              <Brain className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-text-primary-dark">
                AI Co-pilot
              </h2>
              <p className="text-[10px] text-text-muted-dark">
                Intelligence & Recommendations
              </p>
            </div>
          </div>
        )}
        
        {isMinimized && (
          <Brain className="h-5 w-5 text-purple-400 mx-auto" />
        )}
        
        {!isMinimized && (
          <div className="flex items-center gap-1">
            <button
              onClick={onMinimize}
              className="p-1.5 rounded hover:bg-zinc-800 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
            >
              <Minimize2 className="h-4 w-4" />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded hover:bg-zinc-800 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
      
      {isMinimized ? (
        <div className="flex-1 flex flex-col items-center py-4 gap-3">
          <button
            onClick={onMinimize}
            className="p-2 rounded-lg hover:bg-zinc-800 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
          >
            <Maximize2 className="h-5 w-5" />
          </button>
        </div>
      ) : (
        <>
          {/* Tab Navigation */}
          <div className="flex items-center gap-1 p-2 border-b border-zinc-800">
            <button
              onClick={() => setActiveTab('insights')}
              className={cn(
                'flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all',
                activeTab === 'insights'
                  ? 'bg-zinc-700 text-text-primary-dark'
                  : 'text-text-muted-dark hover:text-text-secondary-dark'
              )}
            >
              <Lightbulb className="h-3.5 w-3.5" />
              Insights
              {insights.length > 0 && (
                <span className="px-1.5 py-0.5 rounded-full bg-purple-500/20 text-purple-400 text-[10px]">
                  {insights.length}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('chat')}
              className={cn(
                'flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all',
                activeTab === 'chat'
                  ? 'bg-zinc-700 text-text-primary-dark'
                  : 'text-text-muted-dark hover:text-text-secondary-dark'
              )}
            >
              <MessageSquare className="h-3.5 w-3.5" />
              Chat
            </button>
          </div>
          
          {/* Content */}
          <div className="flex-1 overflow-hidden flex flex-col">
            {activeTab === 'insights' ? (
              <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-transparent">
                {/* Context Summary */}
                <ContextSummary />
                
                {/* Insights List */}
                <div>
                  <h3 className="text-xs font-semibold text-text-muted-dark uppercase tracking-wider mb-3">
                    Latest Insights
                  </h3>
                  
                  {insights.length === 0 ? (
                    <div className="text-center py-8">
                      <Sparkles className="h-8 w-8 text-text-muted-dark mx-auto mb-2" />
                      <p className="text-sm text-text-muted-dark">
                        No insights yet
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {insights.map(insight => (
                        <InsightCard key={insight.id} insight={insight} />
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <>
                {/* Chat Messages */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-transparent">
                  {chatMessages.length === 0 ? (
                    <div className="text-center py-8">
                      <MessageSquare className="h-8 w-8 text-text-muted-dark mx-auto mb-2" />
                      <p className="text-sm text-text-muted-dark">
                        Start a conversation with the AI
                      </p>
                      <p className="text-xs text-text-muted-dark mt-1">
                        Ask questions about the mission or request analysis
                      </p>
                    </div>
                  ) : (
                    <>
                      {chatMessages.map(msg => (
                        <ChatMessageItem key={msg.id} message={{
                          id: msg.id,
                          role: msg.role === 'assistant' ? 'assistant' : 'user',
                          content: msg.content,
                          timestamp: msg.timestamp,
                        }} />
                      ))}
                      <div ref={messagesEndRef} />
                    </>
                  )}
                </div>
                
                {/* Chat Input */}
                <div className="p-4 border-t border-zinc-800">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
                      placeholder="Ask the AI..."
                      className={cn(
                        'flex-1 px-4 py-2 rounded-xl text-sm',
                        'bg-zinc-800 border border-zinc-700 text-text-primary-dark',
                        'placeholder:text-text-muted-dark',
                        'focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500/50'
                      )}
                    />
                    <button
                      onClick={handleSendMessage}
                      disabled={!inputValue.trim()}
                      className={cn(
                        'p-2 rounded-xl transition-all',
                        inputValue.trim()
                          ? 'bg-purple-500 text-white hover:bg-purple-400'
                          : 'bg-zinc-800 text-text-muted-dark cursor-not-allowed'
                      )}
                    >
                      <Send className="h-5 w-5" />
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </>
      )}
    </div>
  )
}

export default IntelligenceSidebar
