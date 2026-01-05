// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - AI Assistant Sidebar
// Copilot-style right panel for AI reasoning and chat
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Bot,
  Send,
  X,
  Brain,
  ArrowRight,
  AlertTriangle,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatTimestamp } from '@/lib/utils'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Badge } from '@/components/ui/Badge'
import { Card } from '@/components/ui/Card'
import { useEventStore } from '@/stores/eventStore'
import type { ChatMessage, ApprovalRequest } from '@/types'

export function AIAssistantSidebar() {
  const {
    isAIPanelOpen,
    toggleAIPanel,
    chatMessages,
    pendingApprovals,
    addChatMessage,
  } = useEventStore()
  
  const [input, setInput] = React.useState('')
  const messagesEndRef = React.useRef<HTMLDivElement>(null)
  
  // Auto-scroll to bottom
  React.useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatMessages.length])
  
  // Handle send message
  const handleSend = () => {
    if (!input.trim()) return
    
    addChatMessage({
      role: 'user',
      content: input.trim(),
    })
    
    setInput('')
    
    // Simulate AI response (in production, this would call the backend)
    setTimeout(() => {
      addChatMessage({
        role: 'assistant',
        content: 'I understand your request. Let me analyze the current mission state and provide recommendations.',
      })
    }, 1000)
  }
  
  if (!isAIPanelOpen) return null
  
  return (
    <div className="fixed top-16 right-0 bottom-10 w-96 border-l border-border-dark bg-bg-card-dark z-40 flex flex-col animate-slide-in-right">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-border-dark">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-royal-blue/10">
            <Bot className="h-5 w-5 text-royal-blue" />
          </div>
          <div>
            <h3 className="font-semibold text-text-primary-dark">AI Assistant</h3>
            <p className="text-xs text-text-muted-dark">Analysis Specialist</p>
          </div>
        </div>
        <Button variant="ghost" size="icon" onClick={toggleAIPanel}>
          <X className="h-4 w-4" />
        </Button>
      </div>
      
      {/* Pending Approvals */}
      {pendingApprovals.length > 0 && (
        <div className="p-4 border-b border-border-dark bg-warning/5">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="h-4 w-4 text-warning" />
            <span className="text-sm font-medium text-warning">
              Pending Approvals ({pendingApprovals.length})
            </span>
          </div>
          <div className="space-y-2">
            {pendingApprovals.slice(0, 3).map((approval) => (
              <ApprovalCard key={approval.action_id} approval={approval} />
            ))}
          </div>
        </div>
      )}
      
      {/* AI Reasoning Section */}
      <div className="p-4 border-b border-border-dark">
        <div className="flex items-center gap-2 mb-3">
          <Brain className="h-4 w-4 text-royal-blue" />
          <span className="text-sm font-medium text-text-primary-dark">
            Current Analysis
          </span>
        </div>
        <ReasoningBlock />
      </div>
      
      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {chatMessages.map((message) => (
          <ChatMessageBubble key={message.id} message={message} />
        ))}
        <div ref={messagesEndRef} />
      </div>
      
      {/* Input */}
      <div className="p-4 border-t border-border-dark">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            handleSend()
          }}
          className="flex gap-2"
        >
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask the AI assistant..."
            className="flex-1"
          />
          <Button type="submit" size="icon" disabled={!input.trim()}>
            <Send className="h-4 w-4" />
          </Button>
        </form>
      </div>
    </div>
  )
}

// Approval Card Component
function ApprovalCard({ approval }: { approval: ApprovalRequest }) {
  const { removeApprovalRequest, addToast } = useEventStore()
  
  const handleApprove = async () => {
    try {
      const response = await fetch(`/api/missions/approve/${approval.action_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      
      if (response.ok) {
        removeApprovalRequest(approval.action_id)
        addToast({
          type: 'success',
          title: 'Action Approved',
          description: 'The operation will proceed.',
        })
      }
    } catch (error) {
      console.error('Failed to approve:', error)
    }
  }
  
  const handleReject = async () => {
    try {
      const response = await fetch(`/api/missions/reject/${approval.action_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      
      if (response.ok) {
        removeApprovalRequest(approval.action_id)
        addToast({
          type: 'info',
          title: 'Action Rejected',
          description: 'Seeking alternative approaches.',
        })
      }
    } catch (error) {
      console.error('Failed to reject:', error)
    }
  }
  
  const riskColors = {
    low: 'border-success/30 bg-success/5',
    medium: 'border-warning/30 bg-warning/5',
    high: 'border-orange-500/30 bg-orange-500/5',
    critical: 'border-critical/30 bg-critical/5',
  }
  
  return (
    <Card className={cn('p-3', riskColors[approval.risk_level])}>
      <div className="flex items-start justify-between mb-2">
        <Badge
          variant={approval.risk_level === 'critical' ? 'critical' : 'warning'}
          className="text-xs"
        >
          {approval.risk_level.toUpperCase()}
        </Badge>
        <span className="text-xs text-text-muted-dark">
          {formatTimestamp(approval.requested_at)}
        </span>
      </div>
      <p className="text-sm text-text-primary-dark mb-2">
        {approval.action_description}
      </p>
      {approval.target_ip && (
        <p className="text-xs text-text-muted-dark mb-2">
          Target: {approval.target_ip}
        </p>
      )}
      <div className="flex gap-2">
        <Button size="sm" variant="outline" className="flex-1" onClick={handleReject}>
          Reject
        </Button>
        <Button size="sm" className="flex-1" onClick={handleApprove}>
          Approve
        </Button>
      </div>
    </Card>
  )
}

// AI Reasoning Block
function ReasoningBlock() {
  // This would be populated from actual AI analysis in production
  const reasoning = {
    observation: 'Detected 3 targets with open SMB ports (445)',
    analysis: 'Checking for EternalBlue vulnerability (MS17-010)',
    decision: 'Queue vulnerability scan before exploitation',
  }
  
  return (
    <div className="space-y-3 text-sm">
      <div className="flex items-start gap-2">
        <div className="h-5 w-5 rounded-full bg-royal-blue/10 flex items-center justify-center flex-shrink-0">
          <span className="text-xs text-royal-blue">1</span>
        </div>
        <div>
          <span className="text-text-muted-dark">Observation:</span>
          <p className="text-text-primary-dark">{reasoning.observation}</p>
        </div>
      </div>
      
      <div className="flex items-center gap-2 pl-2">
        <ArrowRight className="h-3 w-3 text-text-muted-dark" />
      </div>
      
      <div className="flex items-start gap-2">
        <div className="h-5 w-5 rounded-full bg-warning/10 flex items-center justify-center flex-shrink-0">
          <span className="text-xs text-warning">2</span>
        </div>
        <div>
          <span className="text-text-muted-dark">Analysis:</span>
          <p className="text-text-primary-dark">{reasoning.analysis}</p>
        </div>
      </div>
      
      <div className="flex items-center gap-2 pl-2">
        <ArrowRight className="h-3 w-3 text-text-muted-dark" />
      </div>
      
      <div className="flex items-start gap-2">
        <div className="h-5 w-5 rounded-full bg-success/10 flex items-center justify-center flex-shrink-0">
          <span className="text-xs text-success">3</span>
        </div>
        <div>
          <span className="text-text-muted-dark">Decision:</span>
          <p className="text-text-primary-dark">{reasoning.decision}</p>
        </div>
      </div>
    </div>
  )
}

// Chat Message Bubble
function ChatMessageBubble({ message }: { message: ChatMessage }) {
  const isUser = message.role === 'user'
  const isSystem = message.role === 'system'
  
  return (
    <div
      className={cn(
        'flex',
        isUser ? 'justify-end' : 'justify-start'
      )}
    >
      <div
        className={cn(
          'max-w-[80%] rounded-lg px-3 py-2',
          isUser
            ? 'bg-royal-blue text-white'
            : isSystem
            ? 'bg-warning/10 text-text-primary-dark border border-warning/20'
            : 'bg-bg-elevated-dark text-text-primary-dark'
        )}
      >
        <p className="text-sm">{message.content}</p>
        <span className="text-xs opacity-70 mt-1 block">
          {formatTimestamp(message.timestamp)}
        </span>
      </div>
    </div>
  )
}
