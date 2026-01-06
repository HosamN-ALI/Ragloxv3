// RAGLOX v3.0 - Suggested Actions Component
// Shows smart follow-up suggestions based on context
// Part of the Chat UX features per development plan

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Lightbulb,
  ChevronDown,
  ChevronUp,
  Target,
  Shield,
  Terminal,
  Zap,
  Scan,
  Key,
  Network,
  Bug,
  ArrowRight,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface SuggestedAction {
  id: string;
  type: 'scan' | 'exploit' | 'credential' | 'lateral' | 'recon' | 'report' | 'custom';
  title: string;
  description?: string;
  command?: string;
  priority: 'high' | 'medium' | 'low';
  reason?: string;
}

interface SuggestedActionsProps {
  suggestions: SuggestedAction[];
  onSelect: (suggestion: SuggestedAction) => void;
  isLoading?: boolean;
  className?: string;
}

export function SuggestedActions({
  suggestions,
  onSelect,
  isLoading = false,
  className,
}: SuggestedActionsProps) {
  const [isExpanded, setIsExpanded] = useState(true);

  // Group suggestions by type
  const groupedSuggestions = useMemo(() => {
    const groups: Record<string, SuggestedAction[]> = {};
    suggestions.forEach(s => {
      if (!groups[s.type]) groups[s.type] = [];
      groups[s.type].push(s);
    });
    return groups;
  }, [suggestions]);

  if (suggestions.length === 0 && !isLoading) {
    return null;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 10 }}
      className={cn("rounded-xl overflow-hidden", className)}
      style={{
        background: 'rgba(38, 38, 38, 0.8)',
        backdropFilter: 'blur(8px)',
        border: '1px solid rgba(255,255,255,0.08)',
      }}
    >
      {/* Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-4 py-3 transition-colors"
        style={{ borderBottom: isExpanded ? '1px solid rgba(255,255,255,0.06)' : 'none' }}
        onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.04)'}
        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
      >
        <div className="flex items-center gap-2">
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center"
            style={{ background: 'rgba(251, 191, 36, 0.15)' }}
          >
            <Lightbulb className="w-4 h-4" style={{ color: '#fbbf24' }} />
          </div>
          <span className="font-medium text-sm" style={{ color: '#e8e8e8' }}>
            Suggested Actions
          </span>
          <span className="text-xs px-1.5 py-0.5 rounded" style={{ 
            background: 'rgba(251, 191, 36, 0.15)', 
            color: '#fbbf24' 
          }}>
            {suggestions.length}
          </span>
        </div>
        {isExpanded ? (
          <ChevronUp className="w-4 h-4" style={{ color: '#888888' }} />
        ) : (
          <ChevronDown className="w-4 h-4" style={{ color: '#888888' }} />
        )}
      </button>

      {/* Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0 }}
            animate={{ height: "auto" }}
            exit={{ height: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="p-3 space-y-2">
              {isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 animate-pulse" style={{ color: '#fbbf24' }} />
                    <span className="text-sm" style={{ color: '#888888' }}>
                      Generating suggestions...
                    </span>
                  </div>
                </div>
              ) : (
                suggestions.map((suggestion) => (
                  <SuggestionItem
                    key={suggestion.id}
                    suggestion={suggestion}
                    onSelect={() => onSelect(suggestion)}
                  />
                ))
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// Individual suggestion item
function SuggestionItem({
  suggestion,
  onSelect,
}: {
  suggestion: SuggestedAction;
  onSelect: () => void;
}) {
  const { icon: Icon, color, bgColor } = useMemo(() => {
    switch (suggestion.type) {
      case 'scan':
        return { icon: Scan, color: '#4a9eff', bgColor: 'rgba(74, 158, 255, 0.15)' };
      case 'exploit':
        return { icon: Bug, color: '#ef4444', bgColor: 'rgba(239, 68, 68, 0.15)' };
      case 'credential':
        return { icon: Key, color: '#f59e0b', bgColor: 'rgba(245, 158, 11, 0.15)' };
      case 'lateral':
        return { icon: Network, color: '#a78bfa', bgColor: 'rgba(167, 139, 250, 0.15)' };
      case 'recon':
        return { icon: Target, color: '#4ade80', bgColor: 'rgba(74, 222, 128, 0.15)' };
      case 'report':
        return { icon: Shield, color: '#06b6d4', bgColor: 'rgba(6, 182, 212, 0.15)' };
      default:
        return { icon: Zap, color: '#888888', bgColor: 'rgba(136, 136, 136, 0.15)' };
    }
  }, [suggestion.type]);

  const priorityColor = useMemo(() => {
    switch (suggestion.priority) {
      case 'high': return '#ef4444';
      case 'medium': return '#f59e0b';
      case 'low': return '#4ade80';
      default: return '#888888';
    }
  }, [suggestion.priority]);

  return (
    <button
      onClick={onSelect}
      className="w-full flex items-start gap-3 p-3 rounded-lg transition-all group"
      style={{ background: 'transparent' }}
      onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.04)'}
      onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
    >
      {/* Icon */}
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
        style={{ background: bgColor }}
      >
        <Icon className="w-4 h-4" style={{ color }} />
      </div>

      {/* Content */}
      <div className="flex-1 text-left min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium text-sm" style={{ color: '#e8e8e8' }}>
            {suggestion.title}
          </span>
          {/* Priority indicator */}
          <span
            className="text-[10px] px-1.5 py-0.5 rounded uppercase font-medium"
            style={{
              background: `${priorityColor}15`,
              color: priorityColor,
            }}
          >
            {suggestion.priority}
          </span>
        </div>
        {suggestion.description && (
          <p className="text-xs mt-0.5 line-clamp-2" style={{ color: '#888888' }}>
            {suggestion.description}
          </p>
        )}
        {suggestion.command && (
          <code
            className="inline-block text-xs mt-1.5 px-2 py-1 rounded"
            style={{
              background: 'rgba(0, 0, 0, 0.3)',
              color: '#4a9eff',
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {suggestion.command}
          </code>
        )}
        {suggestion.reason && (
          <p className="text-xs mt-1 italic" style={{ color: '#666666' }}>
            💡 {suggestion.reason}
          </p>
        )}
      </div>

      {/* Arrow */}
      <ArrowRight 
        className="w-4 h-4 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" 
        style={{ color: '#888888' }} 
      />
    </button>
  );
}

// Compact inline suggestion pills for chat
export function SuggestionPills({
  suggestions,
  onSelect,
  maxShow = 3,
}: {
  suggestions: SuggestedAction[];
  onSelect: (suggestion: SuggestedAction) => void;
  maxShow?: number;
}) {
  const displaySuggestions = suggestions.slice(0, maxShow);
  const hasMore = suggestions.length > maxShow;

  return (
    <div className="flex flex-wrap gap-2">
      {displaySuggestions.map((suggestion) => (
        <button
          key={suggestion.id}
          onClick={() => onSelect(suggestion)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs transition-all"
          style={{
            background: 'rgba(251, 191, 36, 0.1)',
            color: '#fbbf24',
            border: '1px solid rgba(251, 191, 36, 0.2)',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(251, 191, 36, 0.2)';
            e.currentTarget.style.borderColor = 'rgba(251, 191, 36, 0.3)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(251, 191, 36, 0.1)';
            e.currentTarget.style.borderColor = 'rgba(251, 191, 36, 0.2)';
          }}
        >
          <Lightbulb className="w-3 h-3" />
          <span>{suggestion.title}</span>
        </button>
      ))}
      {hasMore && (
        <span className="text-xs py-1.5" style={{ color: '#888888' }}>
          +{suggestions.length - maxShow} more
        </span>
      )}
    </div>
  );
}

export default SuggestedActions;
