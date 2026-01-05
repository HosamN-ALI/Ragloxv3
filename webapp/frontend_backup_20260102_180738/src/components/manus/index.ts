// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Manus-inspired Components
// Export all Manus-style UI components
// ═══════════════════════════════════════════════════════════════

// Terminal Components
export { 
  TerminalPanel, 
  SimpleTerminalOutput,
  default as Terminal 
} from './TerminalPanel'

// Event Card Components
export { 
  EventCard, 
  EventList,
  default as Event 
} from './EventCard'
export type { 
  EventCardData, 
  EventStatus, 
  EventType,
  KnowledgeItem,
  CommandExecution 
} from './EventCard'

// Plan View Components
export { 
  PlanView, 
  PlanBadge,
  default as Plan 
} from './PlanView'
export type { 
  PlanData, 
  PlanTask, 
  TaskStatus 
} from './PlanView'

// AI Chat Panel Components
export { 
  AIChatPanel,
  default as AIChat 
} from './AIChatPanel'
export type { 
  ChatMessage, 
  MessageRole 
} from './AIChatPanel'

// Dual Panel Layout Components
export { 
  DualPanelLayout,
  FullChatLayout,
  FullTerminalLayout,
  CompactChatLayout,
  WideChatLayout,
  default as Layout 
} from './DualPanelLayout'
