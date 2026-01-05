// RAGLOX v3.0 - HITL Approval Card Component (Manus-style)
// Compact design - consistent with other event cards

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  AlertTriangle, 
  Terminal, 
  Clock, 
  Play, 
  X,
  ChevronDown
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import type { ApprovalRequest } from "@/types";

interface ApprovalCardProps {
  approval: ApprovalRequest;
  onApprove: (actionId: string, comment?: string) => void;
  onReject: (actionId: string, reason?: string, comment?: string) => void;
  className?: string;
}

export function ApprovalCard({ 
  approval, 
  onApprove, 
  onReject,
  className 
}: ApprovalCardProps) {
  const [isExpanded, setIsExpanded] = useState(true); // Expanded by default for approvals
  const [timeRemaining, setTimeRemaining] = useState<string>("");
  const [isExpired, setIsExpired] = useState(false);
  const [comment, setComment] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);

  // Calculate time remaining
  useEffect(() => {
    const updateTimer = () => {
      const now = new Date();
      const expires = new Date(approval.expires_at);
      const diff = expires.getTime() - now.getTime();

      if (diff <= 0) {
        setIsExpired(true);
        setTimeRemaining("Expired");
        return;
      }

      const minutes = Math.floor(diff / 60000);
      const seconds = Math.floor((diff % 60000) / 1000);
      setTimeRemaining(`${minutes}:${seconds.toString().padStart(2, '0')}`);
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [approval.expires_at]);

  const handleApprove = async () => {
    setIsProcessing(true);
    try {
      await onApprove(approval.action_id, comment || undefined);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleReject = async () => {
    setIsProcessing(true);
    try {
      await onReject(approval.action_id, "User rejected", comment || undefined);
    } finally {
      setIsProcessing(false);
    }
  };

  // Risk level colors - Manus warm palette
  const riskColors = {
    critical: "border-l-[3px] border-l-[#ef4444]",
    high: "border-l-[3px] border-l-[#f59e0b]",
    medium: "border-l-[3px] border-l-[#eab308]",
    low: "border-l-[3px] border-l-[#4ade80]",
  };

  const riskBadgeColors = {
    critical: "bg-[#ef4444] text-white",
    high: "bg-[#f59e0b] text-black",
    medium: "bg-[#eab308] text-black",
    low: "bg-[#4ade80] text-black",
  };

  const riskLevel = approval.risk_level.toLowerCase() as keyof typeof riskColors;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        "rounded-xl overflow-hidden",
        riskColors[riskLevel] || riskColors.medium,
        isExpired && "opacity-50",
        className
      )}
      style={{ background: '#1f1f1f', boxShadow: '0 4px 24px rgba(0,0,0,0.15)' }}
    >
      {/* Compact Header - Always Visible */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-[#2a2a2a]/50 transition-all duration-200"
      >
        <div className="w-6 h-6 rounded-md flex items-center justify-center flex-shrink-0" style={{ background: 'rgba(239, 68, 68, 0.15)' }}>
          <AlertTriangle className="w-3.5 h-3.5" style={{ color: '#ef4444' }} />
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-sm" style={{ color: '#e8e8e8' }}>Approval Required</span>
            <span className={cn(
              "text-[10px] px-1.5 py-0.5 rounded font-medium uppercase",
              riskBadgeColors[riskLevel] || riskBadgeColors.medium
            )}>
              {approval.risk_level}
            </span>
            <span className={cn(
              "text-xs flex items-center gap-1 ml-auto",
              isExpired ? "text-red-400" : "text-muted-foreground"
            )}>
              <Clock className="w-3 h-3" />
              {timeRemaining}
            </span>
          </div>
        </div>

        <ChevronDown className={cn(
          "w-4 h-4 text-muted-foreground transition-transform flex-shrink-0",
          isExpanded && "rotate-180"
        )} />
      </button>

      {/* Expandable Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-3">
              {/* Action Description */}
              <p className="text-sm" style={{ color: '#e8e8e8' }}>{approval.action_description}</p>

              {/* Command Preview - Compact */}
              {approval.command_preview && (
                <div className="rounded-lg overflow-hidden" style={{ background: '#141414' }}>
                  <div className="flex items-center gap-1.5 px-3 py-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                    <Terminal className="w-3 h-3" style={{ color: '#4a9eff' }} />
                    <span className="text-[10px]" style={{ color: '#888888' }}>Execute</span>
                    <code className="text-[11px] font-mono truncate" style={{ color: '#e8e8e8' }}>
                      {approval.command_preview.split('\n')[0].substring(0, 50)}...
                    </code>
                  </div>
                </div>
              )}

              {/* Action Buttons - Inline */}
              <div className="flex items-center gap-2 pt-1">
                <input
                  type="text"
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  placeholder="Add a comment..."
                  className="flex-1 px-3 py-2 rounded-lg text-xs focus:outline-none focus:ring-1"
                  style={{ background: '#2a2a2a', border: '1px solid transparent', color: '#e8e8e8' }}
                  disabled={isExpired || isProcessing}
                />
                <Button
                  onClick={handleApprove}
                  disabled={isExpired || isProcessing}
                  size="sm"
                  className="gap-1.5 h-7 px-3 text-xs bg-primary hover:bg-primary/90"
                >
                  <Play className="w-3 h-3" />
                  Run Command
                </Button>
                <Button
                  onClick={handleReject}
                  disabled={isExpired || isProcessing}
                  variant="secondary"
                  size="sm"
                  className="gap-1.5 h-7 px-3 text-xs"
                >
                  <X className="w-3 h-3" />
                  Reject
                </Button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Collapsed Preview */}
      {!isExpanded && (
        <div className="px-3 pb-2.5">
          <p className="text-xs text-muted-foreground truncate">
            {approval.action_description}
          </p>
        </div>
      )}
    </motion.div>
  );
}

export default ApprovalCard;
