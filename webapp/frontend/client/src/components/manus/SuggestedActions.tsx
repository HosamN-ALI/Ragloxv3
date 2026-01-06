// RAGLOX v3.0 - Suggested Actions Component
// AI-generated follow-up suggestions based on findings
// Based on Manus.im design

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Sparkles,
  Target,
  Shield,
  Terminal,
  FileText,
  AlertTriangle,
  ChevronRight,
  Zap,
  Search,
  Lock,
  Crosshair,
  Bug
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface SuggestedAction {
  id: string;
  type: "exploit" | "scan" | "recon" | "report" | "manual" | "escalate";
  title: string;
  description: string;
  command?: string;
  priority: "high" | "medium" | "low";
  reason?: string;
  targetInfo?: {
    ip?: string;
    port?: number;
    service?: string;
    vulnerability?: string;
  };
}

interface SuggestedActionsProps {
  suggestions: SuggestedAction[];
  onExecute: (action: SuggestedAction) => void;
  onDismiss?: (actionId: string) => void;
  isLoading?: boolean;
  className?: string;
}

export function SuggestedActions({
  suggestions,
  onExecute,
  onDismiss,
  isLoading = false,
  className,
}: SuggestedActionsProps) {
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set());

  // Filter out dismissed suggestions
  const visibleSuggestions = suggestions.filter(
    (s) => !dismissedIds.has(s.id)
  );

  const handleDismiss = (actionId: string) => {
    setDismissedIds((prev) => {
      const newSet = new Set(prev);
      newSet.add(actionId);
      return newSet;
    });
    onDismiss?.(actionId);
  };

  if (visibleSuggestions.length === 0 && !isLoading) {
    return null;
  }

  return (
    <div
      className={cn("rounded-xl overflow-hidden", className)}
      style={{
        background: "rgba(30, 30, 30, 0.95)",
        border: "1px solid rgba(255, 255, 255, 0.06)",
      }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-3 px-4 py-3"
        style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.06)" }}
      >
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center"
          style={{ background: "rgba(167, 139, 250, 0.15)" }}
        >
          <Sparkles className="w-4 h-4" style={{ color: "#a78bfa" }} />
        </div>
        <div>
          <span className="text-sm font-medium" style={{ color: "#e8e8e8" }}>
            Suggested Next Steps
          </span>
          <p className="text-xs" style={{ color: "#666666" }}>
            AI-generated recommendations based on findings
          </p>
        </div>
      </div>

      {/* Suggestions List */}
      <div className="p-2">
        {isLoading ? (
          <LoadingSkeleton />
        ) : (
          <AnimatePresence>
            {visibleSuggestions.map((suggestion, index) => (
              <motion.div
                key={suggestion.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ delay: index * 0.05 }}
              >
                <SuggestionCard
                  suggestion={suggestion}
                  onExecute={() => onExecute(suggestion)}
                  onDismiss={() => handleDismiss(suggestion.id)}
                />
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}

// Suggestion Card Component
interface SuggestionCardProps {
  suggestion: SuggestedAction;
  onExecute: () => void;
  onDismiss: () => void;
}

function SuggestionCard({ suggestion, onExecute, onDismiss }: SuggestionCardProps) {
  const [isHovered, setIsHovered] = useState(false);

  // Get icon and color based on type
  const getTypeInfo = () => {
    switch (suggestion.type) {
      case "exploit":
        return { icon: Zap, color: "#ef4444", bgColor: "rgba(239, 68, 68, 0.15)" };
      case "scan":
        return { icon: Search, color: "#f59e0b", bgColor: "rgba(245, 158, 11, 0.15)" };
      case "recon":
        return { icon: Target, color: "#4a9eff", bgColor: "rgba(74, 158, 255, 0.15)" };
      case "report":
        return { icon: FileText, color: "#4ade80", bgColor: "rgba(74, 222, 128, 0.15)" };
      case "escalate":
        return { icon: Lock, color: "#a78bfa", bgColor: "rgba(167, 139, 250, 0.15)" };
      case "manual":
      default:
        return { icon: Terminal, color: "#888888", bgColor: "rgba(136, 136, 136, 0.15)" };
    }
  };

  // Get priority badge color
  const getPriorityColor = () => {
    switch (suggestion.priority) {
      case "high":
        return { bg: "rgba(239, 68, 68, 0.15)", text: "#ef4444" };
      case "medium":
        return { bg: "rgba(245, 158, 11, 0.15)", text: "#f59e0b" };
      case "low":
        return { bg: "rgba(136, 136, 136, 0.15)", text: "#888888" };
    }
  };

  const typeInfo = getTypeInfo();
  const priorityColor = getPriorityColor();
  const TypeIcon = typeInfo.icon;

  return (
    <div
      className="p-3 rounded-lg mb-2 transition-all duration-200 cursor-pointer"
      style={{
        background: isHovered ? "rgba(255, 255, 255, 0.04)" : "transparent",
      }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onClick={onExecute}
    >
      <div className="flex items-start gap-3">
        {/* Icon */}
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: typeInfo.bgColor }}
        >
          <TypeIcon className="w-4.5 h-4.5" style={{ color: typeInfo.color }} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-medium" style={{ color: "#e8e8e8" }}>
              {suggestion.title}
            </span>
            <span
              className="px-1.5 py-0.5 rounded text-xs"
              style={{ background: priorityColor.bg, color: priorityColor.text }}
            >
              {suggestion.priority}
            </span>
          </div>

          <p className="text-xs mb-2" style={{ color: "#888888" }}>
            {suggestion.description}
          </p>

          {/* Target Info */}
          {suggestion.targetInfo && (
            <div className="flex items-center gap-2 mb-2">
              {suggestion.targetInfo.ip && (
                <span
                  className="text-xs px-2 py-0.5 rounded"
                  style={{ background: "#2a2a2a", color: "#4a9eff" }}
                >
                  {suggestion.targetInfo.ip}
                  {suggestion.targetInfo.port && `:${suggestion.targetInfo.port}`}
                </span>
              )}
              {suggestion.targetInfo.service && (
                <span
                  className="text-xs px-2 py-0.5 rounded"
                  style={{ background: "#2a2a2a", color: "#888888" }}
                >
                  {suggestion.targetInfo.service}
                </span>
              )}
            </div>
          )}

          {/* Command Preview */}
          {suggestion.command && (
            <code
              className="block text-xs p-2 rounded"
              style={{
                background: "#141414",
                color: "#4ade80",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              $ {suggestion.command}
            </code>
          )}

          {/* Reason */}
          {suggestion.reason && (
            <p className="text-xs mt-2" style={{ color: "#666666" }}>
              <span style={{ color: "#a78bfa" }}>Why:</span> {suggestion.reason}
            </p>
          )}
        </div>

        {/* Action Arrow */}
        <motion.div
          animate={{ x: isHovered ? 4 : 0, opacity: isHovered ? 1 : 0.5 }}
          className="flex-shrink-0"
        >
          <ChevronRight className="w-5 h-5" style={{ color: "#888888" }} />
        </motion.div>
      </div>
    </div>
  );
}

// Loading Skeleton
function LoadingSkeleton() {
  return (
    <div className="space-y-2 p-2">
      {[1, 2, 3].map((i) => (
        <div
          key={i}
          className="p-3 rounded-lg animate-pulse"
          style={{ background: "rgba(255, 255, 255, 0.02)" }}
        >
          <div className="flex items-start gap-3">
            <div
              className="w-9 h-9 rounded-lg"
              style={{ background: "#2a2a2a" }}
            />
            <div className="flex-1">
              <div
                className="h-4 rounded mb-2"
                style={{ background: "#2a2a2a", width: "60%" }}
              />
              <div
                className="h-3 rounded"
                style={{ background: "#2a2a2a", width: "80%" }}
              />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// Compact Suggestions (Inline Display)
interface CompactSuggestionsProps {
  suggestions: SuggestedAction[];
  onExecute: (action: SuggestedAction) => void;
  maxVisible?: number;
  className?: string;
}

export function CompactSuggestions({
  suggestions,
  onExecute,
  maxVisible = 3,
  className,
}: CompactSuggestionsProps) {
  const visibleSuggestions = suggestions.slice(0, maxVisible);

  if (visibleSuggestions.length === 0) {
    return null;
  }

  return (
    <div className={cn("flex flex-wrap gap-2", className)}>
      {visibleSuggestions.map((suggestion) => (
        <button
          key={suggestion.id}
          onClick={() => onExecute(suggestion)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs transition-all duration-200"
          style={{
            background: "rgba(42, 42, 42, 0.8)",
            border: "1px solid rgba(255, 255, 255, 0.06)",
            color: "#888888",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = "rgba(52, 52, 52, 0.9)";
            e.currentTarget.style.color = "#e8e8e8";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "rgba(42, 42, 42, 0.8)";
            e.currentTarget.style.color = "#888888";
          }}
        >
          <Sparkles className="w-3 h-3" style={{ color: "#a78bfa" }} />
          <span>{suggestion.title}</span>
        </button>
      ))}
    </div>
  );
}

export default SuggestedActions;
