// RAGLOX v3.0 - Mission Data Hooks
// React hooks for loading and managing mission data

import { useState, useEffect, useCallback } from "react";
import {
  missionApi,
  targetApi,
  vulnApi,
  credApi,
  sessionApi,
  chatApi,
  hitlApi,
  MissionWebSocket,
} from "@/lib/api";
import type {
  Mission,
  Target,
  Vulnerability,
  Credential,
  Session,
  ChatMessage,
  ApprovalRequest,
  WebSocketMessage,
  EventCard,
  PlanTask,
} from "@/types";

// Default Mission ID for testing - can be configured via environment variable
export const DEFAULT_MISSION_ID = import.meta.env.VITE_DEFAULT_MISSION_ID || "5bae06db-0f6c-478d-81a3-b54e2f3eb9d5";

// ============================================
// useMission Hook
// ============================================

interface UseMissionResult {
  mission: Mission | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useMission(missionId: string = DEFAULT_MISSION_ID): UseMissionResult {
  const [mission, setMission] = useState<Mission | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMission = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await missionApi.get(missionId);
      setMission(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load mission");
      console.error("[useMission] Error:", err);
    } finally {
      setLoading(false);
    }
  }, [missionId]);

  useEffect(() => {
    fetchMission();
  }, [fetchMission]);

  return { mission, loading, error, refetch: fetchMission };
}

// ============================================
// useTargets Hook
// ============================================

interface UseTargetsResult {
  targets: Target[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useTargets(missionId: string = DEFAULT_MISSION_ID): UseTargetsResult {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTargets = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await targetApi.list(missionId);
      setTargets(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load targets");
      console.error("[useTargets] Error:", err);
    } finally {
      setLoading(false);
    }
  }, [missionId]);

  useEffect(() => {
    fetchTargets();
  }, [fetchTargets]);

  return { targets, loading, error, refetch: fetchTargets };
}

// ============================================
// useVulnerabilities Hook
// ============================================

interface UseVulnerabilitiesResult {
  vulnerabilities: Vulnerability[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useVulnerabilities(missionId: string = DEFAULT_MISSION_ID): UseVulnerabilitiesResult {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchVulnerabilities = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await vulnApi.list(missionId);
      setVulnerabilities(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load vulnerabilities");
      console.error("[useVulnerabilities] Error:", err);
    } finally {
      setLoading(false);
    }
  }, [missionId]);

  useEffect(() => {
    fetchVulnerabilities();
  }, [fetchVulnerabilities]);

  return { vulnerabilities, loading, error, refetch: fetchVulnerabilities };
}

// ============================================
// useCredentials Hook
// ============================================

interface UseCredentialsResult {
  credentials: Credential[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useCredentials(missionId: string = DEFAULT_MISSION_ID): UseCredentialsResult {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchCredentials = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await credApi.list(missionId);
      setCredentials(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load credentials");
      console.error("[useCredentials] Error:", err);
    } finally {
      setLoading(false);
    }
  }, [missionId]);

  useEffect(() => {
    fetchCredentials();
  }, [fetchCredentials]);

  return { credentials, loading, error, refetch: fetchCredentials };
}

// ============================================
// useSessions Hook
// ============================================

interface UseSessionsResult {
  sessions: Session[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

export function useSessions(missionId: string = DEFAULT_MISSION_ID): UseSessionsResult {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSessions = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await sessionApi.list(missionId);
      setSessions(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load sessions");
      console.error("[useSessions] Error:", err);
    } finally {
      setLoading(false);
    }
  }, [missionId]);

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  return { sessions, loading, error, refetch: fetchSessions };
}

// ============================================
// useChatHistory Hook
// ============================================

interface UseChatHistoryResult {
  messages: ChatMessage[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  sendMessage: (content: string) => Promise<ChatMessage | null>;
}

export function useChatHistory(missionId: string = DEFAULT_MISSION_ID): UseChatHistoryResult {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMessages = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await chatApi.list(missionId);
      setMessages(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load chat history");
      console.error("[useChatHistory] Error:", err);
    } finally {
      setLoading(false);
    }
  }, [missionId]);

  const sendMessage = useCallback(async (content: string): Promise<ChatMessage | null> => {
    try {
      const response = await chatApi.send(missionId, content);
      setMessages((prev) => [...prev, response]);
      return response;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to send message");
      console.error("[useChatHistory] Send error:", err);
      return null;
    }
  }, [missionId]);

  useEffect(() => {
    fetchMessages();
  }, [fetchMessages]);

  return { messages, loading, error, refetch: fetchMessages, sendMessage };
}

// ============================================
// useApprovals Hook
// ============================================

interface UseApprovalsResult {
  approvals: ApprovalRequest[];
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  approve: (actionId: string) => Promise<boolean>;
  reject: (actionId: string, reason: string) => Promise<boolean>;
}

export function useApprovals(missionId: string = DEFAULT_MISSION_ID): UseApprovalsResult {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchApprovals = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await hitlApi.list(missionId);
      setApprovals(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load approvals");
      console.error("[useApprovals] Error:", err);
    } finally {
      setLoading(false);
    }
  }, [missionId]);

  const approve = useCallback(async (actionId: string): Promise<boolean> => {
    try {
      await hitlApi.approve(missionId, actionId);
      await fetchApprovals();
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to approve action");
      return false;
    }
  }, [missionId, fetchApprovals]);

  const reject = useCallback(async (actionId: string, reason: string): Promise<boolean> => {
    try {
      await hitlApi.reject(missionId, actionId, reason);
      await fetchApprovals();
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reject action");
      return false;
    }
  }, [missionId, fetchApprovals]);

  useEffect(() => {
    fetchApprovals();
  }, [fetchApprovals]);

  return { approvals, loading, error, refetch: fetchApprovals, approve, reject };
}

// ============================================
// useWebSocket Hook
// ============================================

interface UseWebSocketResult {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  events: EventCard[];
  planTasks: PlanTask[];
  terminalOutput: string[];
}

export function useWebSocket(missionId: string = DEFAULT_MISSION_ID): UseWebSocketResult {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const [events, setEvents] = useState<EventCard[]>([]);
  const [planTasks, setPlanTasks] = useState<PlanTask[]>([]);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([]);

  useEffect(() => {
    const ws = new MissionWebSocket(
      missionId,
      (message) => {
        const wsMessage = message as WebSocketMessage;
        setLastMessage(wsMessage);
        
        // Handle different event types
        switch (wsMessage.type) {
          case "chat_message":
            // Add to events
            const chatEvent: EventCard = {
              id: `event-${Date.now()}`,
              type: "chat_message",
              title: "Message from assistant",
              description: (wsMessage.data as { content?: string })?.content || "",
              timestamp: wsMessage.timestamp,
              data: wsMessage.data,
            };
            setEvents((prev) => [...prev, chatEvent]);
            break;
            
          case "new_target":
          case "target_update":
            const targetEvent: EventCard = {
              id: `event-${Date.now()}`,
              type: wsMessage.type,
              title: wsMessage.type === "new_target" ? "New Target Discovered" : "Target Updated",
              description: JSON.stringify(wsMessage.data),
              timestamp: wsMessage.timestamp,
              data: wsMessage.data,
            };
            setEvents((prev) => [...prev, targetEvent]);
            break;
            
          case "new_vuln":
            const vulnEvent: EventCard = {
              id: `event-${Date.now()}`,
              type: "new_vuln",
              title: "Vulnerability Found",
              description: JSON.stringify(wsMessage.data),
              timestamp: wsMessage.timestamp,
              data: wsMessage.data,
            };
            setEvents((prev) => [...prev, vulnEvent]);
            break;
            
          case "new_cred":
            const credEvent: EventCard = {
              id: `event-${Date.now()}`,
              type: "new_cred",
              title: "Credential Harvested",
              description: JSON.stringify(wsMessage.data),
              timestamp: wsMessage.timestamp,
              data: wsMessage.data,
            };
            setEvents((prev) => [...prev, credEvent]);
            break;
            
          case "new_session":
            const sessionEvent: EventCard = {
              id: `event-${Date.now()}`,
              type: "new_session",
              title: "Session Established",
              description: JSON.stringify(wsMessage.data),
              timestamp: wsMessage.timestamp,
              data: wsMessage.data,
            };
            setEvents((prev) => [...prev, sessionEvent]);
            break;
            
          case "approval_request":
            const approvalEvent: EventCard = {
              id: `event-${Date.now()}`,
              type: "approval_request",
              title: "Approval Required",
              description: (wsMessage.data as { action_description?: string })?.action_description || "",
              timestamp: wsMessage.timestamp,
              data: wsMessage.data,
            };
            setEvents((prev) => [...prev, approvalEvent]);
            break;
            
          default:
            console.log("[WebSocket] Unhandled event type:", wsMessage.type);
        }
      },
      () => setIsConnected(false),
      () => setIsConnected(false)
    );

    ws.connect();
    setIsConnected(true);

    return () => {
      ws.disconnect();
    };
  }, [missionId]);

  return { isConnected, lastMessage, events, planTasks, terminalOutput };
}

// ============================================
// useMissionData - Combined Hook
// ============================================

interface UseMissionDataResult {
  mission: Mission | null;
  targets: Target[];
  vulnerabilities: Vulnerability[];
  credentials: Credential[];
  sessions: Session[];
  chatMessages: ChatMessage[];
  approvals: ApprovalRequest[];
  isConnected: boolean;
  events: EventCard[];
  planTasks: PlanTask[];
  terminalOutput: string[];
  loading: boolean;
  error: string | null;
  sendMessage: (content: string) => Promise<ChatMessage | null>;
  approveAction: (actionId: string) => Promise<boolean>;
  rejectAction: (actionId: string, reason: string) => Promise<boolean>;
  refetchAll: () => Promise<void>;
}

export function useMissionData(missionId: string = DEFAULT_MISSION_ID): UseMissionDataResult {
  const { mission, loading: missionLoading, error: missionError, refetch: refetchMission } = useMission(missionId);
  const { targets, loading: targetsLoading, refetch: refetchTargets } = useTargets(missionId);
  const { vulnerabilities, loading: vulnsLoading, refetch: refetchVulns } = useVulnerabilities(missionId);
  const { credentials, loading: credsLoading, refetch: refetchCreds } = useCredentials(missionId);
  const { sessions, loading: sessionsLoading, refetch: refetchSessions } = useSessions(missionId);
  const { messages: chatMessages, sendMessage, refetch: refetchChat } = useChatHistory(missionId);
  const { approvals, approve: approveAction, reject: rejectAction, refetch: refetchApprovals } = useApprovals(missionId);
  const { isConnected, events, planTasks, terminalOutput } = useWebSocket(missionId);

  const loading = missionLoading || targetsLoading || vulnsLoading || credsLoading || sessionsLoading;
  const error = missionError;

  const refetchAll = useCallback(async () => {
    await Promise.all([
      refetchMission(),
      refetchTargets(),
      refetchVulns(),
      refetchCreds(),
      refetchSessions(),
      refetchChat(),
      refetchApprovals(),
    ]);
  }, [refetchMission, refetchTargets, refetchVulns, refetchCreds, refetchSessions, refetchChat, refetchApprovals]);

  return {
    mission,
    targets,
    vulnerabilities,
    credentials,
    sessions,
    chatMessages,
    approvals,
    isConnected,
    events,
    planTasks,
    terminalOutput,
    loading,
    error,
    sendMessage,
    approveAction,
    rejectAction,
    refetchAll,
  };
}
