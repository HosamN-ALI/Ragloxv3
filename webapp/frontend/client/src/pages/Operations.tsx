// RAGLOX v3.0 - Operations Page (Manus-style)
// Full-screen operations interface with Sidebar, Chat, and Terminal
// Updated for real-time WebSocket integration with polling fallback
// Enhanced with mission controls (start/stop/pause/resume)

import { useEffect, useState, useCallback, useRef } from "react";
import { useParams, useLocation } from "wouter";
import { DualPanelLayout } from "@/components/manus";
import { useMissionStore } from "@/stores/missionStore";
import { useWebSocket } from "@/hooks/useWebSocket";
import { hitlApi, chatApi, missionApi, ApiError } from "@/lib/api";
import type { ChatMessage, EventCard, PlanTask, MissionStatus } from "@/types";
import { toast } from "sonner";
import {
  Play,
  Pause,
  Square,
  RotateCcw,
  ArrowLeft,
  Loader2,
  Wifi,
  WifiOff,
  RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { POLLING_INTERVAL } from "@/lib/config";

export default function Operations() {
  const params = useParams<{ missionId?: string }>();
  const [, setLocation] = useLocation();
  
  // If no mission ID provided, redirect to missions list
  if (!params.missionId) {
    setLocation("/missions");
    return null;
  }
  
  const missionId = params.missionId;

  // Zustand store for mission data
  const {
    mission,
    targets,
    vulnerabilities,
    credentials,
    sessions,
    chatMessages: storeChatMessages,
    isLoading,
    isControlLoading,
    error: storeError,
    loadAllData,
    loadStatistics,
    addEvent,
    startMission,
    pauseMission,
    resumeMission,
    stopMission,
    clearError,
  } = useMissionStore();

  // WebSocket hook for real-time updates
  const {
    status: wsStatus,
    isConnected,
    isPolling,
    events: wsEvents,
    planTasks: wsPlanTasks,
    terminalOutput: wsTerminalOutput,
    newApprovals,
    newChatMessages,
    clearEvents,
    clearTerminal,
    startPolling,
    stopPolling,
  } = useWebSocket(missionId, {
    onConnect: () => {
      toast.success("Connected to mission (real-time)");
    },
    onDisconnect: () => {
      // Don't show toast on every disconnect - only on final failure
    },
    onError: () => {
      // Error handled in onclose
    },
  });

  // Track if we've shown the fallback notification
  const shownFallbackNotification = useRef(false);

  // Polling interval ref
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Local state for terminal output (combining initial + WebSocket)
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [events, setEvents] = useState<EventCard[]>([]);
  const [planTasks, setPlanTasks] = useState<PlanTask[]>([]);

  // Load mission data on mount
  useEffect(() => {
    if (missionId) {
      loadAllData(missionId).catch((error) => {
        console.error("[Operations] Failed to load mission data:", error);
        // Don't show error toast if mission doesn't exist - it's expected for test mission
        if (!String(error).includes("404")) {
          toast.error("Failed to load mission data");
        }
      });

      // Also load statistics
      loadStatistics(missionId);
    }
  }, [missionId, loadAllData, loadStatistics]);

  // Fallback polling when WebSocket is disabled
  useEffect(() => {
    // If WebSocket is disabled, start polling
    if (wsStatus === "disabled") {
      if (!shownFallbackNotification.current) {
        shownFallbackNotification.current = true;
        toast.info("Using polling mode (WebSocket unavailable)", {
          duration: 3000,
        });
      }

      // Start polling
      const poll = async () => {
        try {
          // Fetch latest data
          const [stats, approvals, chat] = await Promise.allSettled([
            missionApi.stats(missionId).catch(() => null),
            hitlApi.list(missionId).catch(() => []),
            chatApi.list(missionId, 10).catch(() => []),
          ]);

          // Update approvals if we got new ones
          if (approvals.status === "fulfilled" && Array.isArray(approvals.value)) {
            // Could update local state here
          }

          // Update chat messages
          if (chat.status === "fulfilled" && Array.isArray(chat.value)) {
            setChatMessages((prev) => {
              const existingIds = new Set(prev.map((m) => m.id));
              const newMsgs = chat.value.filter((m: ChatMessage) => !existingIds.has(m.id));
              if (newMsgs.length > 0) {
                return [...prev, ...newMsgs];
              }
              return prev;
            });
          }
        } catch (error) {
          console.error("[Polling] Error:", error);
        }
      };

      // Initial poll
      poll();

      // Set up interval
      pollingIntervalRef.current = setInterval(poll, POLLING_INTERVAL);

      return () => {
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
        }
      };
    }

    // Clear polling if WebSocket becomes available
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
    };
  }, [wsStatus, missionId]);

  // Update local state from WebSocket
  useEffect(() => {
    if (wsEvents.length > 0) {
      setEvents((prev) => {
        // Merge new events, avoiding duplicates
        const existingIds = new Set(prev.map((e) => e.id));
        const newEvents = wsEvents.filter((e) => !existingIds.has(e.id));
        return [...newEvents, ...prev].slice(0, 100);
      });
    }
  }, [wsEvents]);

  useEffect(() => {
    if (wsPlanTasks.length > 0) {
      setPlanTasks(wsPlanTasks);
    }
  }, [wsPlanTasks]);

  useEffect(() => {
    if (wsTerminalOutput.length > 0) {
      setTerminalOutput((prev) => [...prev, ...wsTerminalOutput]);
    }
  }, [wsTerminalOutput]);

  useEffect(() => {
    if (newChatMessages.length > 0) {
      setChatMessages((prev) => {
        const existingIds = new Set(prev.map((m) => m.id));
        const newMsgs = newChatMessages.filter((m) => !existingIds.has(m.id));
        return [...prev, ...newMsgs];
      });
    }
  }, [newChatMessages]);

  // Sync store chat messages
  useEffect(() => {
    if (storeChatMessages.length > 0) {
      setChatMessages(storeChatMessages);
    }
  }, [storeChatMessages]);

  // Show store errors
  useEffect(() => {
    if (storeError) {
      toast.error("Error", { description: storeError });
      clearError();
    }
  }, [storeError, clearError]);

  // ============================================
  // Mission Control Handlers
  // ============================================

  const handleStartMission = useCallback(async () => {
    const success = await startMission(missionId);
    if (success) {
      toast.success("Mission started", {
        description: "The mission is now running.",
      });
    }
  }, [missionId, startMission]);

  const handlePauseMission = useCallback(async () => {
    const success = await pauseMission(missionId);
    if (success) {
      toast.info("Mission paused", {
        description: "The mission has been paused. Resume when ready.",
      });
    }
  }, [missionId, pauseMission]);

  const handleResumeMission = useCallback(async () => {
    const success = await resumeMission(missionId);
    if (success) {
      toast.success("Mission resumed", {
        description: "The mission is now running again.",
      });
    }
  }, [missionId, resumeMission]);

  const handleStopMission = useCallback(async () => {
    const success = await stopMission(missionId);
    if (success) {
      toast.info("Mission stopped", {
        description: "The mission has been stopped.",
      });
    }
  }, [missionId, stopMission]);

  const handleRefreshData = useCallback(async () => {
    await loadAllData(missionId);
    await loadStatistics(missionId);
    toast.success("Data refreshed");
  }, [missionId, loadAllData, loadStatistics]);

  // Handle sending messages with enhanced error handling
  const handleSendMessage = useCallback(async (content: string) => {
    // Add user message to local state immediately (optimistic update)
    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: "user",
      content,
      timestamp: new Date().toISOString(),
    };
    setChatMessages((prev) => [...prev, userMessage]);

    // Try to send via API
    try {
      const response = await chatApi.send(missionId, content);

      // Add AI response to chat
      setChatMessages((prev) => [...prev, response]);

      // Add to events for activity feed
      addEvent({
        id: `event-${Date.now()}`,
        type: "chat_message",
        title: "Message from assistant",
        description: response.content,
        timestamp: response.timestamp,
        status: "completed",
        data: response,
        expanded: false,
      });
    } catch (error) {
      console.error("[Operations] Failed to send message:", error);

      // Create helpful error message based on error type
      let errorMessage = "Failed to send message";
      let errorDescription = "Unknown error occurred";

      if (error instanceof ApiError) {
        if (error.status === 404) {
          errorMessage = "Mission not found";
          errorDescription = "The mission may have been deleted or doesn't exist.";
        } else if (error.status === 0) {
          errorMessage = "Connection failed";
          errorDescription = "Unable to connect to backend server. Check if the server is running.";
        } else if (error.status === 503) {
          errorMessage = "Service unavailable";
          errorDescription = "The backend service is temporarily unavailable.";
        } else {
          errorDescription = error.message;
        }
      } else if (error instanceof Error) {
        errorDescription = error.message;
      }

      // Add system response indicating error
      const errorResponse: ChatMessage = {
        id: `msg-error-${Date.now()}`,
        role: "system",
        content: `⚠️ ${errorMessage}: ${errorDescription}`,
        timestamp: new Date().toISOString(),
      };
      setChatMessages((prev) => [...prev, errorResponse]);

      // Show toast notification
      toast.error(errorMessage, {
        description: errorDescription,
      });
    }
  }, [missionId, addEvent]);

  // Handle command click (show in terminal)
  const handleCommandClick = useCallback((command: string) => {
    setTerminalOutput((prev) => [
      ...prev,
      "",
      `ubuntu@raglox:~ $ ${command}`,
      "Executing command...",
    ]);
  }, []);

  // Handle approval with enhanced feedback
  const handleApprove = useCallback(async (actionId: string, comment?: string) => {
    try {
      const response = await hitlApi.approve(missionId, actionId, comment);

      // Show success message
      toast.success("Action approved", {
        description: "The command is now executing.",
      });

      // Remove from events
      setEvents((prev) => prev.filter(
        (e) => e.type !== "approval_request" || e.approval?.action_id !== actionId
      ));

      // Add approval confirmation event
      addEvent({
        id: `event-approved-${Date.now()}`,
        type: "approval_resolved",
        title: "Action Approved",
        description: `Action ${actionId} approved${comment ? `: ${comment}` : ""}`,
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });
    } catch (error) {
      console.error("[Operations] Failed to approve action:", error);

      let errorMessage = "Failed to approve action";
      if (error instanceof ApiError) {
        errorMessage = error.message;
      }

      toast.error("Approval failed", {
        description: errorMessage,
      });
    }
  }, [missionId, addEvent]);

  // Handle rejection with enhanced feedback
  const handleReject = useCallback(async (actionId: string, reason?: string, comment?: string) => {
    try {
      await hitlApi.reject(missionId, actionId, reason || "User rejected", comment);

      // Show success message
      toast.info("Action rejected", {
        description: "The system will seek alternative approaches.",
      });

      // Remove from events
      setEvents((prev) => prev.filter(
        (e) => e.type !== "approval_request" || e.approval?.action_id !== actionId
      ));

      // Add rejection confirmation event
      addEvent({
        id: `event-rejected-${Date.now()}`,
        type: "approval_resolved",
        title: "Action Rejected",
        description: `Action ${actionId} rejected: ${reason || "User decision"}`,
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });
    } catch (error) {
      console.error("[Operations] Failed to reject action:", error);

      let errorMessage = "Failed to reject action";
      if (error instanceof ApiError) {
        errorMessage = error.message;
      }

      toast.error("Rejection failed", {
        description: errorMessage,
      });
    }
  }, [missionId, addEvent]);

  // Handle terminal clear
  const handleClearTerminal = useCallback(() => {
    setTerminalOutput([]);
    clearTerminal();
  }, [clearTerminal]);

  // ============================================
  // Helper Functions
  // ============================================

  const getStatusColor = (status?: MissionStatus | string) => {
    switch (status) {
      case "running":
        return "bg-green-500/10 text-green-500 border-green-500/20";
      case "paused":
        return "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";
      case "completed":
        return "bg-blue-500/10 text-blue-500 border-blue-500/20";
      case "failed":
        return "bg-red-500/10 text-red-500 border-red-500/20";
      case "waiting_for_approval":
        return "bg-orange-500/10 text-orange-500 border-orange-500/20";
      case "created":
        return "bg-gray-500/10 text-gray-500 border-gray-500/20";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const canStart = mission?.status === "created" || mission?.status === "failed";
  const canPause = mission?.status === "running";
  const canResume = mission?.status === "paused";
  const canStop = mission?.status === "running" || mission?.status === "paused" || mission?.status === "waiting_for_approval";

  return (
    <div className="h-screen w-screen overflow-hidden bg-background flex flex-col">
      {/* Mission Control Header */}
      <header className="h-14 border-b border-border bg-card flex items-center justify-between px-4 shrink-0">
        <div className="flex items-center gap-4">
          {/* Back Button */}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setLocation("/")}
            className="gap-2"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </Button>

          {/* Mission Info */}
          <div className="flex items-center gap-3">
            <div>
              <h1 className="text-sm font-semibold">
                {mission?.name || `Mission ${missionId.slice(0, 8)}...`}
              </h1>
              <p className="text-xs text-muted-foreground">
                {targets.length} targets • {vulnerabilities.length} vulns • {credentials.length} creds
              </p>
            </div>
            <Badge variant="outline" className={getStatusColor(mission?.status)}>
              {mission?.status || "Unknown"}
            </Badge>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Connection Status */}
          <Tooltip>
            <TooltipTrigger asChild>
              <div className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs ${isConnected
                  ? "bg-green-500/10 text-green-500"
                  : isPolling
                    ? "bg-yellow-500/10 text-yellow-500"
                    : "bg-red-500/10 text-red-500"
                }`}>
                {isConnected ? (
                  <Wifi className="w-3 h-3" />
                ) : (
                  <WifiOff className="w-3 h-3" />
                )}
                <span>{isConnected ? "Live" : isPolling ? "Polling" : "Offline"}</span>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              {isConnected
                ? "Connected via WebSocket (real-time)"
                : isPolling
                  ? `Polling every ${POLLING_INTERVAL / 1000}s`
                  : "Disconnected from server"}
            </TooltipContent>
          </Tooltip>

          {/* Refresh Button */}
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                onClick={handleRefreshData}
                disabled={isLoading}
              >
                <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin" : ""}`} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Refresh data</TooltipContent>
          </Tooltip>

          {/* Mission Controls */}
          <div className="flex items-center gap-1 ml-2 pl-2 border-l border-border">
            {/* Start Button */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handleStartMission}
                  disabled={!canStart || isControlLoading}
                  className="text-green-500 hover:text-green-600 hover:bg-green-500/10"
                >
                  {isControlLoading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>Start Mission</TooltipContent>
            </Tooltip>

            {/* Pause Button */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handlePauseMission}
                  disabled={!canPause || isControlLoading}
                  className="text-yellow-500 hover:text-yellow-600 hover:bg-yellow-500/10"
                >
                  <Pause className="w-4 h-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Pause Mission</TooltipContent>
            </Tooltip>

            {/* Resume Button */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handleResumeMission}
                  disabled={!canResume || isControlLoading}
                  className="text-blue-500 hover:text-blue-600 hover:bg-blue-500/10"
                >
                  <RotateCcw className="w-4 h-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Resume Mission</TooltipContent>
            </Tooltip>

            {/* Stop Button */}
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handleStopMission}
                  disabled={!canStop || isControlLoading}
                  className="text-red-500 hover:text-red-600 hover:bg-red-500/10"
                >
                  <Square className="w-4 h-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Stop Mission</TooltipContent>
            </Tooltip>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 overflow-hidden">
        <DualPanelLayout
          messages={chatMessages}
          events={events}
          planTasks={planTasks}
          onSendMessage={handleSendMessage}
          isConnected={isConnected}
          connectionStatus={wsStatus}
          terminalOutput={terminalOutput}
          terminalTitle="Target Terminal"
          terminalSubtitle="RAGLOX is using Terminal"
          executingCommand={terminalOutput.length > 0 ? terminalOutput[terminalOutput.length - 1]?.replace(/^.*\$ /, '') : undefined}
          isTerminalLive={isConnected}
          terminalProgress={planTasks.length > 0 ? (planTasks.filter(t => t.status === "completed").length / planTasks.length) * 100 : 0}
          terminalTotalSteps={planTasks.length}
          terminalCurrentStep={planTasks.filter(t => t.status === "completed").length}
          terminalCurrentTask={planTasks.find(t => t.status === "running")?.title || planTasks.find(t => t.status === "pending")?.title}
          terminalTaskCompleted={planTasks.length > 0 && planTasks.every(t => t.status === "completed")}
          onCommandClick={handleCommandClick}
          onApprove={handleApprove}
          onReject={handleReject}
          onClearTerminal={handleClearTerminal}
          showSidebar={true}
          showDemoData={false}
        />
      </div>
    </div>
  );
}
