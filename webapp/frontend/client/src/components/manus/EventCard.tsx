// RAGLOX v3.0 - Event Card Component (Manus-style)
// Collapsible event cards that show task execution details

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  ChevronDown, 
  ChevronUp, 
  Terminal, 
  Target, 
  Shield, 
  Key, 
  Wifi,
  AlertTriangle,
  CheckCircle2,
  Circle,
  Clock,
  Sparkles
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { EventCard as EventCardType, KnowledgeItem } from "@/types";

interface EventCardProps {
  event: EventCardType;
  onToggle?: () => void;
  onCommandClick?: (command: string) => void;
}

export function EventCard({ event, onToggle, onCommandClick }: EventCardProps) {
  const [isExpanded, setIsExpanded] = useState(event.expanded || false);

  const handleToggle = () => {
    setIsExpanded(!isExpanded);
    onToggle?.();
  };

  const getEventIcon = () => {
    switch (event.type) {
      case "new_target":
      case "target_update":
        return <Target className="w-4 h-4" />;
      case "new_vuln":
      case "vuln_update":
        return <Shield className="w-4 h-4" />;
      case "new_cred":
        return <Key className="w-4 h-4" />;
      case "new_session":
        return <Wifi className="w-4 h-4" />;
      case "approval_request":
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <Circle className="w-4 h-4" />;
    }
  };

  const getStatusIndicator = () => {
    const data = event.data as Record<string, unknown>;
    const status = data?.status as string;
    
    if (status === "completed" || status === "exploited" || status === "owned") {
      return <CheckCircle2 className="w-4 h-4 text-success" />;
    }
    if (status === "running" || status === "scanning" || status === "exploiting") {
      return <Circle className="w-4 h-4 text-primary animate-pulse" />;
    }
    if (status === "failed") {
      return <AlertTriangle className="w-4 h-4 text-destructive" />;
    }
    return <Circle className="w-4 h-4 text-muted-foreground" />;
  };

  return (
    <div className={cn(
      "event-card group",
      isExpanded && "expanded"
    )}>
      {/* Header - Always visible */}
      <button
        onClick={handleToggle}
        className="w-full flex items-start gap-3 text-left"
      >
        {/* Status indicator */}
        <div className="flex-shrink-0 mt-0.5">
          {getStatusIndicator()}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          {/* Title */}
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">
              {getEventIcon()}
            </span>
            <h4 className="font-medium text-foreground truncate">
              {event.title}
            </h4>
          </div>

          {/* Description - shown when collapsed */}
          {!isExpanded && event.description && (
            <p className="text-sm text-muted-foreground mt-1 line-clamp-1">
              {event.description}
            </p>
          )}
        </div>

        {/* Expand/Collapse indicator */}
        <div className="flex-shrink-0 text-muted-foreground">
          {isExpanded ? (
            <ChevronUp className="w-4 h-4" />
          ) : (
            <ChevronDown className="w-4 h-4" />
          )}
        </div>
      </button>

      {/* Expanded Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="pt-4 space-y-3">
              {/* Description */}
              {event.description && (
                <p className="text-sm text-muted-foreground">
                  {event.description}
                </p>
              )}

              {/* Knowledge Badges */}
              {event.knowledge && event.knowledge.length > 0 && (
                <KnowledgeBadges knowledge={event.knowledge} />
              )}

              {/* Command */}
              {event.command && (
                <CommandPill 
                  command={event.command} 
                  onClick={() => onCommandClick?.(event.command!)}
                />
              )}

              {/* Output */}
              {event.output && (
                <TerminalOutput output={event.output} />
              )}

              {/* Timestamp */}
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Clock className="w-3 h-3" />
                <span>{formatTimestamp(event.timestamp)}</span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Knowledge Badges Component
interface KnowledgeBadgesProps {
  knowledge: KnowledgeItem[];
}

function KnowledgeBadges({ knowledge }: KnowledgeBadgesProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="space-y-2">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="knowledge-badge hover:bg-primary/20 transition-colors"
      >
        <Sparkles className="w-3 h-3" />
        <span>Knowledge recalled({knowledge.length})</span>
        {isExpanded ? (
          <ChevronUp className="w-3 h-3 ml-1" />
        ) : (
          <ChevronDown className="w-3 h-3 ml-1" />
        )}
      </button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="overflow-hidden"
          >
            <div className="pl-4 border-l-2 border-primary/20 space-y-2">
              {knowledge.map((item) => (
                <div key={item.id} className="text-sm">
                  <span className="text-primary font-medium">{item.title}</span>
                  {item.content && (
                    <p className="text-muted-foreground mt-0.5 text-xs">
                      {item.content}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// Command Pill Component
interface CommandPillProps {
  command: string;
  onClick?: () => void;
}

function CommandPill({ command, onClick }: CommandPillProps) {
  return (
    <button
      onClick={onClick}
      className="command-pill w-full text-left hover:border-primary/50 transition-colors group"
    >
      <Terminal className="w-3.5 h-3.5 text-muted-foreground group-hover:text-primary transition-colors" />
      <span className="flex-1 truncate">{command}</span>
    </button>
  );
}

// Terminal Output Component
interface TerminalOutputProps {
  output: string;
}

function TerminalOutput({ output }: TerminalOutputProps) {
  return (
    <div className="terminal-output max-h-48 overflow-auto">
      <pre className="whitespace-pre-wrap text-xs">{output}</pre>
    </div>
  );
}

// Helper function
function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default EventCard;
