// RAGLOX v3.0 - AI Chat Panel Component (Manus-style exact)
// Main chat interface with inline events, knowledge badges, and command pills
// Updated for real-time WebSocket integration

import { useState, useRef, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Send,
  Plus,
  Mic,
  Smile,
  Github,
  Shield,
  Target,
  Terminal,
  ChevronDown,
  ChevronUp,
  Brain,
  Check,
  Circle,
  Loader2,
  Monitor,
  Sparkles,
  ArrowDown,
  Wifi,
  WifiOff
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { ChatMessage, EventCard as EventCardType, PlanTask, KnowledgeItem, ApprovalRequest, AIPlanData, ConnectionStatus } from "@/types";
import { ApprovalCard } from "./ApprovalCard";
import { AIPlanCard } from "./AIPlanCard";
import { CredentialCard, SessionCard, VulnerabilityCard, TargetCard } from "./ArtifactCard";

interface AIChatPanelProps {
  messages: ChatMessage[];
  events: EventCardType[];
  planTasks: PlanTask[];
  onSendMessage: (content: string) => void;
  onCommandClick?: (command: string) => void;
  onExpandTerminal?: () => void;
  onApprove?: (actionId: string, comment?: string) => void;
  onReject?: (actionId: string, reason?: string, comment?: string) => void;
  isConnected?: boolean;
  connectionStatus?: ConnectionStatus;
  terminalLastCommand?: string;
  terminalPreviewLines?: string[];
  className?: string;
  // Demo mode flag - when true, shows demo data if no real data available
  showDemoData?: boolean;
}

export function AIChatPanel({
  messages,
  events,
  planTasks,
  onSendMessage,
  onCommandClick,
  onExpandTerminal,
  onApprove,
  onReject,
  isConnected = false,
  connectionStatus = "disconnected",
  terminalLastCommand,
  terminalPreviewLines = [],
  className,
  showDemoData = false,
}: AIChatPanelProps) {
  const [inputValue, setInputValue] = useState("");
  const [isPlanExpanded, setIsPlanExpanded] = useState(false);
  const [collapsedEvents, setCollapsedEvents] = useState<Set<string>>(new Set());
  const [expandedKnowledge, setExpandedKnowledge] = useState<Set<string>>(new Set());
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, events]);

  // Auto-resize textarea
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.style.height = "auto";
      inputRef.current.style.height = `${Math.min(inputRef.current.scrollHeight, 200)}px`;
    }
  }, [inputValue]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputValue.trim()) {
      onSendMessage(inputValue.trim());
      setInputValue("");
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const toggleEvent = (eventId: string) => {
    setCollapsedEvents(prev => {
      const next = new Set(prev);
      if (next.has(eventId)) {
        next.delete(eventId);
      } else {
        next.add(eventId);
      }
      return next;
    });
  };

  const toggleKnowledge = (knowledgeId: string) => {
    setExpandedKnowledge(prev => {
      const next = new Set(prev);
      if (next.has(knowledgeId)) {
        next.delete(knowledgeId);
      } else {
        next.add(knowledgeId);
      }
      return next;
    });
  };

  // Use real events if available, otherwise use demo data only if showDemoData is true
  const displayEvents: EventCardType[] = useMemo(() => {
    if (events.length > 0) {
      return events;
    }

    // Only show demo data if explicitly requested
    if (!showDemoData) {
      return [];
    }

    // Demo events for testing UI
    return [
      {
        id: "event-1",
        title: "System Ready",
        description: "RAGLOX is connected and ready to receive commands.",
        status: "completed",
        timestamp: new Date().toISOString(),
        knowledge: [],
      },
    ];
  }, [events, showDemoData]);

  // Use real plan tasks if available
  const actualPlanTasks: PlanTask[] = useMemo(() => {
    if (planTasks.length > 0) {
      return planTasks;
    }

    // Empty array if no real data
    return [];
  }, [planTasks]);
  const completedTasks = actualPlanTasks.filter(t => t.status === "completed").length;
  const totalTasks = actualPlanTasks.length;
  const progress = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;
  const hasActivePlan = actualPlanTasks.length > 0;

  return (
    <div className={cn("flex flex-col h-full overflow-hidden", className)} style={{ backgroundColor: '#1a1a1a' }}>
      {/* Chat Header - Manus style */}
      <div className="flex items-center justify-between px-4 py-3" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="flex items-center gap-2">
          <span className="font-medium text-foreground">RAGLOX 3.0</span>
          <ChevronDown className="w-4 h-4 text-muted-foreground" />
        </div>
        <div className="flex items-center gap-2">
          {/* Connection Status Indicator */}
          <div className="flex items-center gap-1.5">
            {connectionStatus === "connected" ? (
              <>
                <div
                  className="w-2 h-2 rounded-full"
                  style={{
                    background: '#4ade80',
                    boxShadow: '0 0 6px rgba(74, 222, 128, 0.5)'
                  }}
                />
                <span className="text-xs" style={{ color: '#4ade80' }}>Live</span>
              </>
            ) : connectionStatus === "connecting" ? (
              <>
                <Loader2 className="w-3 h-3 animate-spin" style={{ color: '#f59e0b' }} />
                <span className="text-xs" style={{ color: '#f59e0b' }}>Connecting...</span>
              </>
            ) : connectionStatus === "disabled" ? (
              <>
                <WifiOff className="w-3 h-3" style={{ color: '#888888' }} />
                <span className="text-xs" style={{ color: '#888888' }}>Demo Mode</span>
              </>
            ) : (
              <>
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ background: '#ef4444' }}
                />
                <span className="text-xs" style={{ color: '#ef4444' }}>Offline</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Chat Messages Area - Content centered within available space */}
      <ScrollArea className="flex-1 min-h-0">
        <div className="flex justify-center w-full py-6 pb-40 px-6">
          <div className="w-full max-w-[800px]">
            {messages.length === 0 && displayEvents.length === 0 ? (
              <WelcomeScreen onQuickAction={onSendMessage} isConnected={isConnected} />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                {/* Agent Header */}
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-full flex items-center justify-center" style={{ background: 'rgba(74, 158, 255, 0.15)' }}>
                    <Brain className="w-4 h-4" style={{ color: '#4a9eff' }} />
                  </div>
                  <span className="font-semibold" style={{ color: '#e8e8e8', fontSize: '16px' }}>RAGLOX</span>
                  <span className="agent-badge">v3.0</span>
                </div>

                {/* Initial Message - only show if no events */}
                {displayEvents.length === 0 && messages.length > 0 && (
                  <p className="text-foreground leading-relaxed">
                    {messages[0]?.content || "Ready to assist with your security operations."}
                  </p>
                )}

                {/* Event Cards */}
                {displayEvents.map((event) => {
                  // HITL Approval Card
                  if (event.type === "approval_request" && event.approval) {
                    return (
                      <ApprovalCard
                        key={event.id}
                        approval={event.approval}
                        onApprove={(actionId, comment) => onApprove?.(actionId, comment)}
                        onReject={(actionId, reason, comment) => onReject?.(actionId, reason, comment)}
                      />
                    );
                  }

                  // AI-PLAN Card
                  if (event.type === "ai_plan" && event.aiPlan) {
                    return (
                      <AIPlanCard
                        key={event.id}
                        data={event.aiPlan}
                      />
                    );
                  }

                  // Artifact Cards
                  if (event.type === "artifact" && event.artifact) {
                    return (
                      <div key={event.id} className="space-y-2">
                        <div className="flex items-center gap-2">
                          <div className="w-5 h-5 rounded-full bg-success/20 flex items-center justify-center">
                            <Check className="w-3 h-3 text-success" />
                          </div>
                          <span className="font-medium text-foreground">{event.title}</span>
                        </div>
                        {event.description && (
                          <p className="text-muted-foreground text-sm pl-7">{event.description}</p>
                        )}
                        <div className="pl-7">
                          {event.artifact.type === "credential" && event.artifact.credential && (
                            <CredentialCard credential={event.artifact.credential} />
                          )}
                          {event.artifact.type === "session" && event.artifact.session && (
                            <SessionCard session={event.artifact.session} />
                          )}
                          {event.artifact.type === "vulnerability" && event.artifact.vulnerability && (
                            <VulnerabilityCard vulnerability={event.artifact.vulnerability} />
                          )}
                          {event.artifact.type === "target" && event.artifact.target && (
                            <TargetCard target={event.artifact.target} />
                          )}
                        </div>
                      </div>
                    );
                  }

                  // Regular Event Card
                  return (
                    <EventItem
                      key={event.id}
                      event={event}
                      isExpanded={!collapsedEvents.has(event.id)}
                      onToggle={() => toggleEvent(event.id)}
                      expandedKnowledge={expandedKnowledge}
                      onToggleKnowledge={toggleKnowledge}
                      onCommandClick={(cmd) => {
                        onCommandClick?.(cmd);
                        onExpandTerminal?.();
                      }}
                      onTerminalClick={onExpandTerminal}
                    />
                  );
                })}

                <div ref={messagesEndRef} />
              </div>
            )}
          </div>
        </div>
      </ScrollArea>

      {/* Bottom Section - Plan Bar + Input - FIXED at bottom */}
      <div
        className="flex-shrink-0"
        style={{
          position: 'sticky',
          bottom: 0,
          background: 'linear-gradient(to bottom, transparent 0%, #1a1a1a 20%, #1a1a1a 100%)',
          paddingTop: '16px',
          marginTop: 'auto'
        }}
      >
        <div className="flex justify-center w-full px-6">
          <div className="w-full max-w-[800px]">
            {/* Expanded Plan View - Floating Overlay */}
            <div className="relative">
              <AnimatePresence>
                {isPlanExpanded && hasActivePlan && (
                  <motion.div
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 10, scale: 0.95 }}
                    transition={{ duration: 0.2, ease: 'easeOut' }}
                    className="absolute bottom-full left-1/2 -translate-x-1/2 mb-3 w-[400px] max-w-[90vw]"
                    style={{
                      background: 'rgba(30, 30, 30, 0.98)',
                      backdropFilter: 'blur(12px)',
                      borderRadius: '16px',
                      boxShadow: '0 -8px 32px rgba(0,0,0,0.4)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      maxHeight: '320px',
                      overflow: 'hidden'
                    }}
                  >
                    {/* Plan Header */}
                    <div className="flex items-center justify-between p-4" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                      <div className="flex items-center gap-3">
                        <div
                          className="w-9 h-9 rounded-lg flex items-center justify-center"
                          style={{ background: 'rgba(74, 158, 255, 0.15)' }}
                        >
                          <Monitor className="w-4.5 h-4.5" style={{ color: '#4a9eff' }} />
                        </div>
                        <div>
                          <span className="font-medium text-sm" style={{ color: '#e8e8e8' }}>مظهر الخطة</span>
                          <div className="flex items-center gap-1.5 mt-0.5">
                            <Terminal className="w-3 h-3" style={{ color: '#888888' }} />
                            <span className="text-xs" style={{ color: '#888888' }}>RAGLOX is using Terminal</span>
                          </div>
                        </div>
                      </div>
                      <span className="text-sm font-medium" style={{ color: '#888888' }}>{completedTasks}/{totalTasks}</span>
                    </div>

                    {/* Progress Bar */}
                    <div className="px-4 py-2">
                      <div className="h-1 rounded-full overflow-hidden" style={{ background: '#2a2a2a' }}>
                        <motion.div
                          className="h-full rounded-full"
                          style={{ background: '#4a9eff' }}
                          initial={{ width: 0 }}
                          animate={{ width: `${progress}%` }}
                          transition={{ duration: 0.3 }}
                        />
                      </div>
                    </div>

                    {/* Tasks List - Scrollable */}
                    <div className="px-2 pb-2 max-h-[180px] overflow-y-auto">
                      {actualPlanTasks.map((task) => (
                        <div
                          key={task.id}
                          className="flex items-center gap-3 py-2 px-2 rounded-lg transition-colors"
                          style={{ cursor: 'default' }}
                          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.04)'}
                          onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                        >
                          <div
                            className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0"
                            style={{
                              background: task.status === 'completed' ? 'rgba(74, 222, 128, 0.15)' : '#2a2a2a'
                            }}
                          >
                            {task.status === 'completed' ? (
                              <Check className="w-3 h-3" style={{ color: '#4ade80' }} />
                            ) : task.status === 'running' ? (
                              <Loader2 className="w-3 h-3 animate-spin" style={{ color: '#4a9eff' }} />
                            ) : (
                              <Circle className="w-3 h-3" style={{ color: '#888888' }} />
                            )}
                          </div>
                          <span
                            className="text-sm flex-1"
                            style={{ color: task.status === 'completed' ? '#888888' : '#e8e8e8' }}
                          >
                            {task.title}
                          </span>
                          <span className="text-xs" style={{ color: '#666666' }}>#{task.order}</span>
                        </div>
                      ))}
                    </div>

                    {/* Hide Button */}
                    <button
                      className="w-full flex items-center justify-center gap-2 py-3 text-sm transition-colors"
                      style={{ borderTop: '1px solid rgba(255,255,255,0.06)', color: '#888888' }}
                      onClick={() => setIsPlanExpanded(false)}
                      onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.04)'}
                      onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                    >
                      <ChevronDown className="w-4 h-4" />
                      Hide Plan
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Collapsed Plan Bar - Attached to Input */}
            {hasActivePlan && !isPlanExpanded && (
              <div className="flex items-center justify-center mb-2">
                <button
                  onClick={() => setIsPlanExpanded(true)}
                  className="flex items-center gap-2 px-4 py-2 rounded-full transition-all"
                  style={{
                    background: 'rgba(38, 38, 38, 0.9)',
                    backdropFilter: 'blur(8px)',
                    boxShadow: '0 2px 8px rgba(0,0,0,0.15)'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(48, 48, 48, 0.95)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(38, 38, 38, 0.9)'}
                >
                  <Monitor className="w-4 h-4" style={{ color: '#A3A3A3' }} />
                  <span className="text-sm" style={{ color: '#E5E5E5' }}>مظهر الخطة</span>
                  <span className="text-sm" style={{ color: '#A3A3A3' }}>{completedTasks}/{totalTasks}</span>
                  <ChevronUp className="w-4 h-4" style={{ color: '#A3A3A3' }} />
                </button>
              </div>
            )}

            {/* Quick Actions Bar - Always Visible */}
            <QuickActionsBar onAction={onSendMessage} />

            {/* Input Area - Centered with max-width, Balanced Icons */}
            <div className="pb-4">
              <form onSubmit={handleSubmit}>
                <div
                  className="chat-input"
                  style={{ boxShadow: 'var(--shadow-card)' }}
                >
                  {/* Plus Button - Primary action */}
                  <button
                    type="button"
                    className="chat-input-btn"
                    title="Add attachment"
                  >
                    <Plus className="w-4 h-4" />
                  </button>

                  {/* Text Input */}
                  <textarea
                    ref={inputRef}
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Send message to RAGLOX"
                    className="chat-input-field min-h-[32px] max-h-[200px] py-1.5"
                    rows={1}
                  />

                  {/* Right Icons - Balanced */}
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <button
                      type="button"
                      className="chat-input-btn"
                      title="Voice input"
                    >
                      <Mic className="w-4 h-4" />
                    </button>
                    <button
                      type="submit"
                      className={cn("chat-input-send", inputValue.trim() && "active")}
                      disabled={!inputValue.trim()}
                      title="Send"
                    >
                      <ArrowDown className="w-4 h-4 rotate-180" />
                    </button>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Event Item Component - Manus style
interface EventItemProps {
  event: EventCardType;
  isExpanded: boolean;
  onToggle: () => void;
  expandedKnowledge: Set<string>;
  onToggleKnowledge: (id: string) => void;
  onCommandClick?: (command: string) => void;
  onTerminalClick?: () => void;
}

function EventItem({
  event,
  isExpanded,
  onToggle,
  expandedKnowledge,
  onToggleKnowledge,
  onCommandClick,
  onTerminalClick
}: EventItemProps) {
  const knowledge = event.knowledge || [];

  return (
    <div className="space-y-2">
      {/* Event Header */}
      <button
        onClick={onToggle}
        className="flex items-center gap-2 w-full text-left group py-2"
      >
        <div
          className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0"
          style={{
            background: event.status === "completed" ? 'rgba(74, 222, 128, 0.15)' : '#2a2a2a'
          }}
        >
          {event.status === "completed" ? (
            <Check className="w-3 h-3" style={{ color: '#4ade80' }} />
          ) : event.status === "running" ? (
            <Loader2 className="w-3 h-3 animate-spin" style={{ color: '#4a9eff' }} />
          ) : (
            <Circle className="w-3 h-3" style={{ color: '#888888' }} />
          )}
        </div>

        <span className="font-medium flex-1" style={{ color: '#e8e8e8' }}>{event.title}</span>

        <ChevronUp className={cn(
          "w-4 h-4 transition-transform duration-200",
          !isExpanded && "rotate-180"
        )} style={{ color: '#888888' }} />
      </button>

      {/* Event Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="pl-7 space-y-3 pt-1">
              {/* Description */}
              {event.description && (
                <p className="text-sm leading-relaxed" style={{ color: '#888888' }}>{event.description}</p>
              )}

              {/* Knowledge Badge - Manus style */}
              {knowledge.length > 0 && (
                <div className="space-y-2">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onToggleKnowledge(event.id);
                    }}
                    className="knowledge-badge"
                  >
                    <Brain className="icon" />
                    <span>Knowledge recalled({knowledge.length})</span>
                    <ChevronDown className={cn(
                      "chevron",
                      expandedKnowledge.has(event.id) && "expanded"
                    )} />
                  </button>

                  <AnimatePresence>
                    {expandedKnowledge.has(event.id) && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        className="overflow-hidden"
                      >
                        <div
                          className="rounded-lg p-3 space-y-1"
                          style={{ background: '#1f1f1f', boxShadow: '0 4px 24px rgba(0,0,0,0.15)' }}
                        >
                          {knowledge.map((k) => (
                            <a
                              key={k.id}
                              href="#"
                              onClick={(e) => e.preventDefault()}
                              className="block text-sm py-1 hover:underline"
                              style={{ color: '#4a9eff' }}
                            >
                              {k.title}
                            </a>
                          ))}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              )}

              {/* Command Badge - Manus style */}
              {event.command && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onCommandClick?.(event.command!);
                  }}
                  className="command-pill"
                >
                  <Terminal className="icon" />
                  <span>Executing command</span>
                  <code>{event.command}</code>
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Welcome Screen Component
interface WelcomeScreenProps {
  onQuickAction: (action: string) => void;
  isConnected?: boolean;
}

function WelcomeScreen({ onQuickAction, isConnected = false }: WelcomeScreenProps) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
      <h1 className="text-3xl font-semibold text-foreground mb-3">
        What can I do for you?
      </h1>
      <p className="text-muted-foreground mb-2">
        RAGLOX is ready to assist with your security operations
      </p>

      {/* Connection status hint */}
      <div className="flex items-center gap-2 mb-6">
        {isConnected ? (
          <>
            <div className="w-2 h-2 rounded-full bg-green-500" />
            <span className="text-xs text-green-500">Connected to backend</span>
          </>
        ) : (
          <>
            <div className="w-2 h-2 rounded-full bg-yellow-500" />
            <span className="text-xs text-yellow-500">Connecting to backend...</span>
          </>
        )}
      </div>

      {/* Instructions */}
      <p className="text-xs text-muted-foreground max-w-md">
        Use the quick actions below the input box or type your command to get started.
      </p>
    </div>
  );
}

// Quick Actions Bar Component - Always visible above input
interface QuickActionsBarProps {
  onAction: (action: string) => void;
}

function QuickActionsBar({ onAction }: QuickActionsBarProps) {
  const quickActions = [
    { 
      icon: Target, 
      label: "Recon", 
      action: "Start reconnaissance on target",
      color: "#4a9eff",
      tooltip: "Start Reconnaissance"
    },
    { 
      icon: Shield, 
      label: "Scan", 
      action: "Scan for vulnerabilities",
      color: "#f59e0b",
      tooltip: "Scan Vulnerabilities"
    },
    { 
      icon: Terminal, 
      label: "Shell", 
      action: "Attempt to get shell access",
      color: "#4ade80",
      tooltip: "Get Shell Access"
    },
    { 
      icon: Sparkles, 
      label: "Auto", 
      action: "Run in autonomous mode",
      color: "#a78bfa",
      tooltip: "Autonomous Mode"
    },
  ];

  return (
    <div className="flex justify-center mb-3">
      <div 
        className="flex items-center gap-1 px-2 py-1.5 rounded-full"
        style={{ 
          background: 'rgba(42, 42, 42, 0.7)',
          backdropFilter: 'blur(8px)',
          border: '1px solid rgba(255, 255, 255, 0.06)'
        }}
      >
        {quickActions.map((action) => (
          <button
            key={action.label}
            onClick={() => onAction(action.action)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-200"
            style={{ color: '#888888' }}
            title={action.tooltip}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
              e.currentTarget.style.color = action.color;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.color = '#888888';
            }}
          >
            <action.icon className="w-3.5 h-3.5" />
            <span>{action.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

export default AIChatPanel;
