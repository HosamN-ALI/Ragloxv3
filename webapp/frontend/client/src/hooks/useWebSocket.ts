// RAGLOX v3.0 - WebSocket Hook
// React hook for real-time WebSocket connections with the backend
// Uses the WebSocketClient class for connection management

import { useState, useEffect, useCallback, useRef } from "react";
import type {
  WebSocketMessage,
  WebSocketEventType,
  EventCard,
  PlanTask,
  Target,
  Vulnerability,
  Credential,
  Session,
  ApprovalRequest,
  ChatMessage,
  ConnectionStatus,
} from "@/types";
import { WebSocketClient } from "@/lib/websocket";
import {
  API_BASE_URL,
  POLLING_INTERVAL,
  shouldEnableWebSocket,
  MAX_EVENTS_DISPLAY,
} from "@/lib/config";

// ============================================
// Hook Options Interface
// ============================================

interface UseWebSocketOptions {
  autoConnect?: boolean;
  autoReconnect?: boolean;
  maxReconnectAttempts?: number;
  reconnectDelay?: number;
  onMessage?: (message: WebSocketMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
}

// ============================================
// Hook Result Interface
// ============================================

interface UseWebSocketResult {
  // Connection state
  status: ConnectionStatus;
  isConnected: boolean;
  isPolling: boolean;
  lastMessage: WebSocketMessage | null;

  // Parsed data
  events: EventCard[];
  planTasks: PlanTask[];
  terminalOutput: string[];

  // New data from WebSocket
  newTargets: Target[];
  newVulnerabilities: Vulnerability[];
  newCredentials: Credential[];
  newSessions: Session[];
  newApprovals: ApprovalRequest[];
  newChatMessages: ChatMessage[];

  // Actions
  connect: () => void;
  disconnect: () => void;
  send: (data: unknown) => void;
  clearEvents: () => void;
  clearTerminal: () => void;
  startPolling: () => void;
  stopPolling: () => void;
}

// ============================================
// useWebSocket Hook
// ============================================

export function useWebSocket(
  missionId: string,
  options: UseWebSocketOptions = {}
): UseWebSocketResult {
  const {
    autoConnect = true,
    autoReconnect = true,
    maxReconnectAttempts = 5,
    reconnectDelay = 2000,
    onMessage,
    onConnect,
    onDisconnect,
    onError,
  } = options;

  // Connection state
  const [status, setStatus] = useState<ConnectionStatus>(
    shouldEnableWebSocket() ? "disconnected" : "disabled"
  );
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [isPolling, setIsPolling] = useState(false);

  // Parsed data
  const [events, setEvents] = useState<EventCard[]>([]);
  const [planTasks, setPlanTasks] = useState<PlanTask[]>([]);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);

  // New data arrays
  const [newTargets, setNewTargets] = useState<Target[]>([]);
  const [newVulnerabilities, setNewVulnerabilities] = useState<Vulnerability[]>([]);
  const [newCredentials, setNewCredentials] = useState<Credential[]>([]);
  const [newSessions, setNewSessions] = useState<Session[]>([]);
  const [newApprovals, setNewApprovals] = useState<ApprovalRequest[]>([]);
  const [newChatMessages, setNewChatMessages] = useState<ChatMessage[]>([]);

  // Refs
  const wsClientRef = useRef<WebSocketClient | null>(null);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const processedMessageIds = useRef<Set<string>>(new Set());

  // ============================================
  // Message Handler
  // ============================================

  const handleMessage = useCallback((message: WebSocketMessage) => {
    // Generate a unique ID for deduplication
    const messageId = `${message.type}-${message.timestamp}-${JSON.stringify(message.data).slice(0, 50)}`;
    if (processedMessageIds.current.has(messageId)) {
      return; // Skip duplicate messages
    }
    processedMessageIds.current.add(messageId);

    // Keep the set from growing too large
    if (processedMessageIds.current.size > 1000) {
      const entries = Array.from(processedMessageIds.current);
      processedMessageIds.current = new Set(entries.slice(-500));
    }

    setLastMessage(message);
    onMessage?.(message);

    const { type, data, timestamp } = message;

    // Create event card
    const eventCard: EventCard = {
      id: `event-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: type as EventCard["type"],
      title: getEventTitle(type, data),
      description: getEventDescription(type, data),
      timestamp,
      data,
      expanded: false,
    };

    // Handle specific event types
    switch (type) {
      case "connected":
        console.log("[WebSocket] Connected to mission:", missionId);
        break;

      case "new_target":
        setNewTargets((prev) => [...prev, data as Target]);
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "target_update":
        setNewTargets((prev) => {
          const target = data as Target;
          const index = prev.findIndex((t) => t.target_id === target.target_id);
          if (index >= 0) {
            const updated = [...prev];
            updated[index] = target;
            return updated;
          }
          return prev;
        });
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "new_vuln":
        setNewVulnerabilities((prev) => [...prev, data as Vulnerability]);
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "new_cred":
        setNewCredentials((prev) => [...prev, data as Credential]);
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "new_session":
        setNewSessions((prev) => [...prev, data as Session]);
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "approval_request":
        setNewApprovals((prev) => [...prev, data as ApprovalRequest]);
        // Create approval-specific event card
        const approvalCard: EventCard = {
          ...eventCard,
          type: "approval_request",
          approval: data as ApprovalRequest,
        };
        setEvents((prev) => [approvalCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "approval_resolved":
        setNewApprovals((prev) =>
          prev.filter((a) => a.action_id !== (data as { action_id: string }).action_id)
        );
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "chat_message":
        setNewChatMessages((prev) => [...prev, data as ChatMessage]);
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "ai_plan":
        // Handle AI plan data
        const aiPlanCard: EventCard = {
          ...eventCard,
          type: "ai_plan",
          aiPlan: data as EventCard["aiPlan"],
        };
        setEvents((prev) => [aiPlanCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));

        // Update plan tasks if included
        if ((data as { tasks?: PlanTask[] }).tasks) {
          setPlanTasks((data as { tasks: PlanTask[] }).tasks);
        }
        break;

      case "mission_status":
      case "status_change":
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "goal_achieved":
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "statistics":
        // Statistics updates don't need to create events
        break;

      case "error":
        console.error("[WebSocket] Server error:", data);
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));
        break;

      case "terminal_output":
        // Handle dedicated terminal output events
        {
          const termData = data as { command?: string; output?: string; status?: string };
          if (termData.output) {
            const lines = termData.output.split('\n').filter(line => line.length > 0);
            setTerminalOutput((prev) => [...prev, ...lines]);
          }
          // Don't add terminal_output to events (too noisy)
        }
        break;

      default:
        // Generic event handling
        setEvents((prev) => [eventCard, ...prev].slice(0, MAX_EVENTS_DISPLAY));

        // Check for terminal output in generic events
        if ((data as { output?: string }).output) {
          const output = (data as { output: string }).output;
          setTerminalOutput((prev) => [...prev, ...output.split('\n')]);
        }
        if ((data as { command?: string }).command) {
          const command = (data as { command: string }).command;
          setTerminalOutput((prev) => [...prev, `$ ${command}`]);
        }
    }
  }, [missionId, onMessage]);

  // ============================================
  // Connection Management
  // ============================================

  const connect = useCallback(() => {
    if (!shouldEnableWebSocket()) {
      console.log("[WebSocket] WebSocket disabled - using polling mode");
      setStatus("disabled");
      return;
    }

    // Create new WebSocket client if needed
    if (!wsClientRef.current) {
      wsClientRef.current = new WebSocketClient(missionId, {
        autoReconnect,
        maxReconnectAttempts,
        reconnectDelay,
        onConnect: () => {
          setStatus("connected");
          onConnect?.();
        },
        onDisconnect: () => {
          setStatus("disconnected");
          onDisconnect?.();
        },
        onError: (error) => {
          setStatus("error");
          onError?.(error);
        },
        onMessage: handleMessage,
      });
    }

    setStatus("connecting");
    wsClientRef.current.connect();
  }, [missionId, autoReconnect, maxReconnectAttempts, reconnectDelay, handleMessage, onConnect, onDisconnect, onError]);

  const disconnect = useCallback(() => {
    if (wsClientRef.current) {
      wsClientRef.current.disconnect();
      wsClientRef.current = null;
    }
    setStatus("disconnected");
  }, []);

  const send = useCallback((data: unknown) => {
    if (wsClientRef.current?.isConnected) {
      wsClientRef.current.send(data);
    } else {
      console.warn("[WebSocket] Cannot send - not connected");
    }
  }, []);

  // ============================================
  // Polling Functions (Fallback)
  // ============================================

  const fetchData = useCallback(async () => {
    try {
      // Fetch stats
      const statsResponse = await fetch(`${API_BASE_URL}/api/v1/missions/${missionId}/stats`);
      if (statsResponse.ok) {
        const stats = await statsResponse.json();
        handleMessage({
          type: "statistics",
          data: stats,
          timestamp: new Date().toISOString(),
        });
      }

      // Fetch approvals
      const approvalsResponse = await fetch(`${API_BASE_URL}/api/v1/missions/${missionId}/approvals`);
      if (approvalsResponse.ok) {
        const approvals = await approvalsResponse.json();
        if (Array.isArray(approvals) && approvals.length > 0) {
          approvals.forEach((approval: ApprovalRequest) => {
            handleMessage({
              type: "approval_request",
              data: approval,
              timestamp: new Date().toISOString(),
            });
          });
        }
      }

      // Fetch chat messages (latest 10)
      const chatResponse = await fetch(`${API_BASE_URL}/api/v1/missions/${missionId}/chat?limit=10`);
      if (chatResponse.ok) {
        const messages = await chatResponse.json();
        if (Array.isArray(messages) && messages.length > 0) {
          messages.forEach((msg: ChatMessage) => {
            handleMessage({
              type: "chat_message",
              data: msg,
              timestamp: msg.timestamp || new Date().toISOString(),
            });
          });
        }
      }
    } catch (error) {
      console.log("[Polling] Fetch error (mission may not exist):", error);
    }
  }, [missionId, handleMessage]);

  const startPolling = useCallback(() => {
    if (pollingIntervalRef.current) return; // Already polling

    console.log("[Polling] Starting polling mode");
    setStatus("polling");
    setIsPolling(true);

    // Initial fetch
    fetchData();

    // Start interval
    pollingIntervalRef.current = setInterval(fetchData, POLLING_INTERVAL);
  }, [fetchData]);

  const stopPolling = useCallback(() => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
    setIsPolling(false);
  }, []);

  // ============================================
  // Utility Functions
  // ============================================

  const clearEvents = useCallback(() => {
    setEvents([]);
    processedMessageIds.current.clear();
  }, []);

  const clearTerminal = useCallback(() => {
    setTerminalOutput([]);
  }, []);

  // ============================================
  // Effects
  // ============================================

  // Auto-connect on mount
  useEffect(() => {
    if (!missionId) return;

    if (autoConnect && shouldEnableWebSocket()) {
      connect();
    } else if (!shouldEnableWebSocket()) {
      // WebSocket not available, start polling
      startPolling();
    }

    return () => {
      disconnect();
      stopPolling();
    };
  }, [missionId]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-start polling when WebSocket is disabled
  useEffect(() => {
    if (status === "disabled" && missionId && !isPolling) {
      console.log("[WebSocket] Switching to polling mode");
      startPolling();
    }
  }, [status, missionId, isPolling, startPolling]);

  // Update status from WebSocket client
  useEffect(() => {
    if (wsClientRef.current) {
      const interval = setInterval(() => {
        const clientStatus = wsClientRef.current?.status;
        if (clientStatus && clientStatus !== status) {
          setStatus(clientStatus);
        }
      }, 500);
      return () => clearInterval(interval);
    }
  }, [status]);

  return {
    status,
    isConnected: status === "connected",
    isPolling,
    lastMessage,
    events,
    planTasks,
    terminalOutput,
    newTargets,
    newVulnerabilities,
    newCredentials,
    newSessions,
    newApprovals,
    newChatMessages,
    connect,
    disconnect,
    send,
    clearEvents,
    clearTerminal,
    startPolling,
    stopPolling,
  };
}

// ============================================
// Helper Functions
// ============================================

function getEventTitle(type: WebSocketEventType | string, data: unknown): string {
  const d = data as Record<string, unknown>;
  switch (type) {
    case "connected":
      return "Connected to Mission";
    case "new_target":
      return `Target Discovered: ${d.ip || d.hostname || "Unknown"}`;
    case "target_update":
      return `Target Updated: ${d.ip || d.hostname || "Unknown"}`;
    case "new_vuln":
      return `Vulnerability Found: ${d.name || d.type || "Unknown"}`;
    case "new_cred":
      return `Credential Harvested: ${d.username || "Unknown"}`;
    case "new_session":
      return `Session Established: ${d.type || "Unknown"}`;
    case "approval_request":
      return `Approval Required: ${d.action_type || "Action"}`;
    case "approval_resolved":
      return `Approval Resolved`;
    case "mission_status":
    case "status_change":
      return `Mission Status: ${d.status || "Updated"}`;
    case "statistics":
      return "Statistics Updated";
    case "goal_achieved":
      return `Goal Achieved: ${d.goal || d.description || "Goal"}`;
    case "chat_message":
      return `Message from ${d.role || "System"}`;
    case "ai_plan":
      return `AI Planning: ${d.message || "Task"}`;
    case "error":
      return `Error: ${d.message || "Unknown error"}`;
    default:
      return `Event: ${type}`;
  }
}

function getEventDescription(type: WebSocketEventType | string, data: unknown): string {
  const d = data as Record<string, unknown>;
  switch (type) {
    case "new_target":
      return `Discovered ${d.os || "Unknown OS"} at ${d.ip || d.hostname || "Unknown"}`;
    case "new_vuln":
      return `${d.severity || "Unknown"} severity${d.cvss ? ` - CVSS: ${d.cvss}` : ""}`;
    case "new_cred":
      return `${d.type || "Unknown"} credential for ${d.username || "Unknown"}`;
    case "new_session":
      return `${d.type || "Unknown"} session as ${d.user || d.username || "Unknown"}`;
    case "approval_request":
      return (d.action_description as string) || "Action requires approval";
    case "chat_message":
      return (d.content as string) || "";
    case "ai_plan":
      return (d.reasoning as string) || (d.message as string) || "";
    default:
      return "";
  }
}

export default useWebSocket;
