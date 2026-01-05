// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - AI Chat Panel Component
// Manus-inspired AI conversation interface
// Shows AI messages, reasoning, and embedded events
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Send,
  Bot,
  User,
  Loader2,
  AlertTriangle,
  Plus,
  Mic,
  Github,
  AtSign,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { motion } from 'framer-motion'
import { EventCard } from './EventCard'
import type { EventCardData } from './EventCard'
import { PlanBadge } from './PlanView'
import type { PlanData } from './PlanView'

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

export type MessageRole = 'user' | 'assistant' | 'system'

export interface ChatMessage {
  id: string
  role: MessageRole
  content: string
  timestamp: string
  // Embedded content
  events?: EventCardData[]
  plan?: PlanData
  isStreaming?: boolean
  error?: string
}

interface AIChatPanelProps {
  messages: ChatMessage[]
  onSendMessage: (content: string) => void
  onTerminalClick?: (command: string, output?: string) => void
  onPlanExpand?: (plan: PlanData) => void
  isLoading?: boolean
  placeholder?: string
  className?: string
}

// ═══════════════════════════════════════════════════════════════
// Message Bubble Component
// ═══════════════════════════════════════════════════════════════

interface MessageBubbleProps {
  message: ChatMessage
  onTerminalClick?: (command: string, output?: string) => void
  onPlanExpand?: (plan: PlanData) => void
}

function MessageBubble({ message, onTerminalClick, onPlanExpand }: MessageBubbleProps) {
  const isUser = message.role === 'user'
  const isSystem = message.role === 'system'
  
  const formatTimestamp = (ts: string) => {
    try {
      const date = new Date(ts)
      return date.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        hour12: false 
      })
    } catch {
      return ts
    }
  }
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className={cn("flex gap-3", isUser && "flex-row-reverse")}
    >
      {/* Avatar */}
      <div className={cn(
        "flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center",
        isUser ? "bg-royal-blue" : isSystem ? "bg-amber-500/20" : "bg-zinc-800"
      )}>
        {isUser ? (
          <User className="h-4 w-4 text-white" />
        ) : isSystem ? (
          <AlertTriangle className="h-4 w-4 text-amber-400" />
        ) : (
          <Bot className="h-4 w-4 text-zinc-300" />
        )}
      </div>
      
      {/* Content */}
      <div className={cn("flex-1 max-w-[85%]", isUser && "flex flex-col items-end")}>
        {/* Role Label */}
        <div className={cn(
          "flex items-center gap-2 mb-1",
          isUser && "flex-row-reverse"
        )}>
          <span className="text-xs font-medium text-zinc-400">
            {isUser ? 'You' : isSystem ? 'System' : 'RAGLOX AI'}
          </span>
          <span className="text-xs text-zinc-600">
            {formatTimestamp(message.timestamp)}
          </span>
        </div>
        
        {/* Message Content */}
        <div className={cn(
          "rounded-2xl px-4 py-3",
          isUser 
            ? "bg-royal-blue text-white rounded-br-md" 
            : isSystem
            ? "bg-amber-500/10 border border-amber-500/20 text-zinc-200 rounded-bl-md"
            : "bg-zinc-800 text-zinc-200 rounded-bl-md"
        )}>
          {/* Text Content */}
          <p className="text-sm whitespace-pre-wrap">{message.content}</p>
          
          {/* Streaming Indicator */}
          {message.isStreaming && (
            <span className="inline-flex items-center gap-1 mt-2 text-xs text-zinc-400">
              <Loader2 className="h-3 w-3 animate-spin" />
              Thinking...
            </span>
          )}
          
          {/* Error */}
          {message.error && (
            <div className="mt-2 p-2 bg-red-500/10 border border-red-500/20 rounded-lg">
              <p className="text-xs text-red-400">{message.error}</p>
            </div>
          )}
        </div>
        
        {/* Embedded Plan */}
        {message.plan && (
          <div className="mt-3 w-full">
            <PlanBadge
              plan={message.plan}
              onClick={() => onPlanExpand?.(message.plan!)}
            />
          </div>
        )}
        
        {/* Embedded Events */}
        {message.events && message.events.length > 0 && (
          <div className="mt-3 w-full space-y-2">
            {message.events.map((event) => (
              <EventCard
                key={event.id}
                event={event}
                onTerminalClick={onTerminalClick}
              />
            ))}
          </div>
        )}
      </div>
    </motion.div>
  )
}



// ═══════════════════════════════════════════════════════════════
// Chat Input Component
// ═══════════════════════════════════════════════════════════════

interface ChatInputProps {
  onSend: (content: string) => void
  isLoading: boolean
  placeholder: string
}

function ChatInput({ onSend, isLoading, placeholder }: ChatInputProps) {
  const [input, setInput] = React.useState('')
  const textareaRef = React.useRef<HTMLTextAreaElement>(null)
  
  const handleSend = () => {
    if (!input.trim() || isLoading) return
    onSend(input.trim())
    setInput('')
    // Reset textarea height
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
    }
  }
  
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }
  
  // Auto-resize textarea
  const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value)
    const textarea = e.target
    textarea.style.height = 'auto'
    textarea.style.height = `${Math.min(textarea.scrollHeight, 200)}px`
  }
  
  return (
    <div className="border-t border-zinc-800 p-4">
      {/* Input Area */}
      <div className="flex items-end gap-2 bg-zinc-800 rounded-2xl border border-zinc-700 focus-within:border-zinc-600 transition-colors">
        {/* Attachments Button */}
        <button
          className="flex-shrink-0 p-3 text-zinc-500 hover:text-zinc-300 transition-colors"
          title="Add attachment"
        >
          <Plus className="h-5 w-5" />
        </button>
        
        {/* Text Input */}
        <textarea
          ref={textareaRef}
          value={input}
          onChange={handleInput}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          rows={1}
          className="flex-1 bg-transparent text-white placeholder-zinc-500 resize-none py-3 px-0 focus:outline-none text-sm max-h-[200px]"
          disabled={isLoading}
        />
        
        {/* Action Buttons */}
        <div className="flex items-center gap-1 p-2">
          {/* Integrations */}
          <button
            className="p-2 text-zinc-500 hover:text-zinc-300 transition-colors rounded-lg hover:bg-zinc-700"
            title="Connect tools"
          >
            <AtSign className="h-4 w-4" />
          </button>
          <button
            className="p-2 text-zinc-500 hover:text-zinc-300 transition-colors rounded-lg hover:bg-zinc-700"
            title="GitHub"
          >
            <Github className="h-4 w-4" />
          </button>
          
          {/* Voice Input */}
          <button
            className="p-2 text-zinc-500 hover:text-zinc-300 transition-colors rounded-lg hover:bg-zinc-700"
            title="Voice input"
          >
            <Mic className="h-4 w-4" />
          </button>
          
          {/* Send Button */}
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            className={cn(
              "p-2 rounded-lg transition-all",
              input.trim() && !isLoading
                ? "bg-royal-blue text-white hover:bg-royal-blue/80"
                : "bg-zinc-700 text-zinc-500 cursor-not-allowed"
            )}
          >
            {isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>
      
      {/* Tool Connections */}
      <div className="flex items-center gap-2 mt-2 px-2">
        <span className="text-xs text-zinc-600">Connect your tools to RAGLOX</span>
        <div className="flex items-center gap-1">
          <span className="text-xs text-zinc-500">@</span>
          <span className="text-xs text-zinc-500">✉</span>
          <span className="text-xs text-zinc-500">📊</span>
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Welcome Screen
// ═══════════════════════════════════════════════════════════════

interface WelcomeScreenProps {
  onQuickAction?: (action: string) => void
}

function WelcomeScreen({ onQuickAction }: WelcomeScreenProps) {
  const quickActions = [
    { icon: '🔍', label: 'Scan target', action: 'Start reconnaissance on target' },
    { icon: '🛡️', label: 'Check vulnerabilities', action: 'Scan for vulnerabilities' },
    { icon: '💻', label: 'Establish session', action: 'Establish SSH session' },
    { icon: '🔐', label: 'Harvest credentials', action: 'Search for credentials' },
  ]
  
  return (
    <div className="flex-1 flex flex-col items-center justify-center p-8">
      <div className="text-center mb-8">
        <h1 className="text-2xl font-semibold text-white mb-2">
          What can I do for you?
        </h1>
        <p className="text-sm text-zinc-500">
          RAGLOX AI is ready to assist with your security operations
        </p>
      </div>
      
      {/* Quick Actions */}
      <div className="grid grid-cols-2 gap-3 w-full max-w-md">
        {quickActions.map((action) => (
          <button
            key={action.label}
            onClick={() => onQuickAction?.(action.action)}
            className="flex items-center gap-3 p-4 bg-zinc-800/50 border border-zinc-700 rounded-xl hover:bg-zinc-800 hover:border-zinc-600 transition-all text-left"
          >
            <span className="text-2xl">{action.icon}</span>
            <span className="text-sm text-zinc-300">{action.label}</span>
          </button>
        ))}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main AI Chat Panel Component
// ═══════════════════════════════════════════════════════════════

export function AIChatPanel({
  messages,
  onSendMessage,
  onTerminalClick,
  onPlanExpand,
  isLoading = false,
  placeholder = "Send message to RAGLOX...",
  className
}: AIChatPanelProps) {
  const messagesEndRef = React.useRef<HTMLDivElement>(null)
  
  // Auto-scroll to bottom
  React.useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages.length])
  
  const handleQuickAction = (action: string) => {
    onSendMessage(action)
  }
  
  return (
    <div className={cn(
      "flex flex-col h-full bg-zinc-900",
      className
    )}>
      {/* Messages Area */}
      {messages.length === 0 ? (
        <WelcomeScreen onQuickAction={handleQuickAction} />
      ) : (
        <div className="flex-1 overflow-y-auto p-4 space-y-6 scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-transparent">
          {messages.map((message) => (
            <MessageBubble
              key={message.id}
              message={message}
              onTerminalClick={onTerminalClick}
              onPlanExpand={onPlanExpand}
            />
          ))}
          <div ref={messagesEndRef} />
        </div>
      )}
      
      {/* Input Area */}
      <ChatInput
        onSend={onSendMessage}
        isLoading={isLoading}
        placeholder={placeholder}
      />
    </div>
  )
}

export default AIChatPanel
