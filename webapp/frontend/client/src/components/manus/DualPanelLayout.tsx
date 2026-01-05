// RAGLOX v3.0 - Three-Column Layout Component (Manus-style)
// Layout: Sidebar | Chat Panel | Terminal Panel (when open)
// Updated for real-time WebSocket integration

import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Sidebar, SidebarUtility } from "./Sidebar";
import { AIChatPanel } from "./AIChatPanel";
import { TerminalPanel } from "./TerminalPanel";
import { UtilityPanel } from "./UtilityPanel";
import type { ChatMessage, EventCard, PlanTask, ConnectionStatus } from "@/types";

type PreferencesState = {
  liveTelemetry: boolean;
  showTooltips: boolean;
  compactPlan: boolean;
};

interface DualPanelLayoutProps {
  // Chat data
  messages: ChatMessage[];
  events: EventCard[];
  planTasks: PlanTask[];
  onSendMessage: (content: string) => void;
  isConnected?: boolean;
  connectionStatus?: ConnectionStatus;

  // Terminal data
  terminalOutput: string[];
  terminalTitle?: string;
  terminalSubtitle?: string;
  executingCommand?: string;
  isTerminalLive?: boolean;
  terminalProgress?: number;
  terminalTotalSteps?: number;
  terminalCurrentStep?: number;
  terminalCurrentTask?: string;
  terminalTaskCompleted?: boolean;

  // Callbacks
  onCommandClick?: (command: string) => void;
  onApprove?: (actionId: string, comment?: string) => void;
  onReject?: (actionId: string, reason?: string, comment?: string) => void;
  onClearTerminal?: () => void;

  // Sidebar
  showSidebar?: boolean;

  // Demo mode
  showDemoData?: boolean;

  className?: string;
}

export function DualPanelLayout({
  messages,
  events,
  planTasks,
  onSendMessage,
  isConnected,
  connectionStatus = "disconnected",
  terminalOutput,
  terminalTitle = "Target Terminal",
  terminalSubtitle,
  executingCommand,
  isTerminalLive,
  terminalProgress = 0,
  terminalTotalSteps = 0,
  terminalCurrentStep = 0,
  terminalCurrentTask,
  terminalTaskCompleted = false,
  onCommandClick,
  onApprove,
  onReject,
  onClearTerminal,
  showSidebar = true,
  showDemoData = false,
  className,
}: DualPanelLayoutProps) {
  const [terminalExpanded, setTerminalExpanded] = useState(false);
  const [activeUtilityPanel, setActiveUtilityPanel] = useState<SidebarUtility | null>(null);
  const [preferences, setPreferences] = useState<PreferencesState>({
    liveTelemetry: true,
    showTooltips: true,
    compactPlan: false,
  });

  // Get last command from terminal output
  const getLastCommand = () => {
    const commands = terminalOutput.filter(line => line.includes("$ ") && !line.startsWith("ubuntu@"));
    if (commands.length > 0) {
      const lastLine = commands[commands.length - 1];
      const match = lastLine.match(/\$\s+(.+)/);
      return match ? match[1] : undefined;
    }
    const nmapLine = terminalOutput.find(line => line.includes("nmap"));
    if (nmapLine) {
      const match = nmapLine.match(/\$\s+(.+)/);
      return match ? match[1] : "nmap -sV 172.28.0.100";
    }
    return executingCommand || "df -h";
  };

  const handleSidebarItemClick = useCallback((itemId: string) => {
    if (itemId === "close") {
      setActiveUtilityPanel(null);
      return;
    }
    if (["files", "settings", "help", "notifications"].includes(itemId)) {
      setActiveUtilityPanel((prev) => (prev === itemId ? null : (itemId as SidebarUtility)));
    } else {
      setActiveUtilityPanel(null);
    }
  }, []);

  const togglePreference = useCallback((key: keyof PreferencesState) => {
    setPreferences((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  }, []);

  // Handle command click - expand terminal
  const handleCommandClick = useCallback((command: string) => {
    setTerminalExpanded(true);
    onCommandClick?.(command);
  }, [onCommandClick]);

  // Handle expand terminal from badge
  const handleExpandTerminal = useCallback(() => {
    setTerminalExpanded(true);
  }, []);

  // Handle close terminal
  const handleCloseTerminal = useCallback(() => {
    setTerminalExpanded(false);
  }, []);

  return (
    <div className={cn("relative flex h-full", className)}>
      {/* Sidebar */}
      {showSidebar && (
        <div className="h-full flex-shrink-0 w-[108px]">
          <Sidebar
            className="h-full"
            activeUtility={activeUtilityPanel}
            onItemClick={handleSidebarItemClick}
          />
        </div>
      )}

      {/* Chat Panel - Flexible width */}
      <motion.div
        className="h-full overflow-hidden flex-1 min-w-0"
        initial={false}
        animate={{
          // Chat panel takes remaining space
        }}
        transition={{ type: "spring", damping: 25, stiffness: 300 }}
      >
        <AIChatPanel
          messages={messages}
          events={events}
          planTasks={planTasks}
          onSendMessage={onSendMessage}
          onCommandClick={handleCommandClick}
          onExpandTerminal={handleExpandTerminal}
          onApprove={onApprove}
          onReject={onReject}
          isConnected={isConnected}
          connectionStatus={connectionStatus}
          terminalLastCommand={getLastCommand()}
          showDemoData={showDemoData}
          className="h-full"
        />
      </motion.div>

      {/* Terminal Panel - Slides in from right */}
      <AnimatePresence>
        {terminalExpanded && (
          <motion.div
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 500, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ type: "spring", damping: 25, stiffness: 300 }}
            className="h-full overflow-hidden flex-shrink-0"
          >
            <TerminalPanel
              title={terminalTitle || "Terminal"}
              executingCommand={executingCommand || getLastCommand()}
              output={terminalOutput}
              isLive={isTerminalLive}
              connectionStatus={connectionStatus}
              onClose={handleCloseTerminal}
              onClear={onClearTerminal}
              className="h-full"
            />
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {activeUtilityPanel && (
          <UtilityPanel
            key={activeUtilityPanel}
            type={activeUtilityPanel}
            events={events}
            preferences={preferences}
            onTogglePreference={togglePreference}
            onClose={() => setActiveUtilityPanel(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

export default DualPanelLayout;
