// RAGLOX v3.0 - Mission Store (Zustand)
// Centralized state management for mission data
// Updated with mission control actions (start/stop/pause/resume)

import { create } from "zustand";
import type {
  Mission,
  Target,
  Vulnerability,
  Credential,
  Session,
  ApprovalRequest,
  ChatMessage,
  EventCard,
  PlanTask,
  WebSocketMessage,
  TaskStatus,
  MissionStatistics,
  MissionStatus,
} from "@/types";
import {
  missionApi,
  targetApi,
  vulnApi,
  credApi,
  sessionApi,
  hitlApi,
  chatApi,
  MissionWebSocket,
  ApiError,
} from "@/lib/api";
import { MAX_EVENTS_DISPLAY, MAX_CHAT_MESSAGES } from "@/lib/config";

// ============================================
// State Interface
// ============================================

interface MissionState {
  // Current mission
  currentMissionId: string | null;
  mission: Mission | null;
  statistics: MissionStatistics | null;

  // Data
  targets: Target[];
  vulnerabilities: Vulnerability[];
  credentials: Credential[];
  sessions: Session[];
  approvals: ApprovalRequest[];
  chatMessages: ChatMessage[];

  // UI State
  events: EventCard[];
  planTasks: PlanTask[];
  isLoading: boolean;
  isControlLoading: boolean; // For mission control actions
  error: string | null;

  // WebSocket
  wsConnection: MissionWebSocket | null;
  isConnected: boolean;

  // Actions - Mission Management
  setMissionId: (id: string | null) => void;
  loadMission: (id: string) => Promise<void>;
  loadAllData: (id: string) => Promise<void>;
  loadStatistics: (id: string) => Promise<void>;

  // Actions - Mission Control
  createMission: (data: {
    name: string;
    description?: string;
    scope: string[];
    goals: string[];
    constraints?: Record<string, unknown>;
  }) => Promise<string | null>;
  startMission: (id?: string) => Promise<boolean>;
  pauseMission: (id?: string) => Promise<boolean>;
  resumeMission: (id?: string) => Promise<boolean>;
  stopMission: (id?: string) => Promise<boolean>;

  // WebSocket Actions
  connectWebSocket: (missionId: string) => void;
  disconnectWebSocket: () => void;
  handleWebSocketMessage: (message: WebSocketMessage) => void;

  // Chat Actions
  sendMessage: (content: string) => Promise<void>;

  // HITL Actions
  approveAction: (actionId: string, comment?: string) => Promise<boolean>;
  rejectAction: (actionId: string, reason: string, comment?: string) => Promise<boolean>;

  // Event Actions
  addEvent: (event: EventCard) => void;
  toggleEventExpanded: (eventId: string) => void;
  clearEvents: () => void;

  // Plan Actions
  updateTaskStatus: (taskId: string, status: TaskStatus) => void;
  setPlanTasks: (tasks: PlanTask[]) => void;

  // Data Update Actions (from WebSocket)
  addTarget: (target: Target) => void;
  updateTarget: (target: Target) => void;
  addVulnerability: (vuln: Vulnerability) => void;
  addCredential: (cred: Credential) => void;
  addSession: (session: Session) => void;
  addApproval: (approval: ApprovalRequest) => void;
  removeApproval: (actionId: string) => void;
  addChatMessage: (message: ChatMessage) => void;
  updateMissionStatus: (status: MissionStatus) => void;

  // Utility
  clearError: () => void;
  reset: () => void;
}

// ============================================
// Initial State
// ============================================

const initialState = {
  currentMissionId: null,
  mission: null,
  statistics: null,
  targets: [],
  vulnerabilities: [],
  credentials: [],
  sessions: [],
  approvals: [],
  chatMessages: [],
  events: [],
  planTasks: [],
  isLoading: false,
  isControlLoading: false,
  error: null,
  wsConnection: null,
  isConnected: false,
};

// ============================================
// Mission Store
// ============================================

export const useMissionStore = create<MissionState>((set, get) => ({
  ...initialState,

  // ============================================
  // Mission Management Actions
  // ============================================

  setMissionId: (id) => set({ currentMissionId: id }),

  loadMission: async (id) => {
    set({ isLoading: true, error: null });
    try {
      const mission = await missionApi.get(id);
      set({ mission, currentMissionId: id });
    } catch (error) {
      const message = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: message });
    } finally {
      set({ isLoading: false });
    }
  },

  loadAllData: async (id) => {
    set({ isLoading: true, error: null });
    try {
      const [mission, targets, vulnerabilities, credentials, sessions, approvals, chatMessages] =
        await Promise.all([
          missionApi.get(id),
          targetApi.list(id).catch(() => []),
          vulnApi.list(id).catch(() => []),
          credApi.list(id).catch(() => []),
          sessionApi.list(id).catch(() => []),
          hitlApi.list(id).catch(() => []),
          chatApi.list(id).catch(() => []),
        ]);

      set({
        mission,
        currentMissionId: id,
        targets,
        vulnerabilities,
        credentials,
        sessions,
        approvals,
        chatMessages,
      });
    } catch (error) {
      const message = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: message });
    } finally {
      set({ isLoading: false });
    }
  },

  loadStatistics: async (id) => {
    try {
      const statistics = await missionApi.stats(id);
      set({ statistics });
    } catch (error) {
      console.error("[MissionStore] Failed to load statistics:", error);
    }
  },

  // ============================================
  // Mission Control Actions
  // ============================================

  createMission: async (data) => {
    set({ isControlLoading: true, error: null });
    try {
      const response = await missionApi.create(data);

      // Add event for mission creation
      get().addEvent({
        id: `event-create-${Date.now()}`,
        type: "mission_status",
        title: "Mission Created",
        description: `Mission "${data.name}" created successfully`,
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });

      return response.mission_id;
    } catch (error) {
      const message = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: message });
      return null;
    } finally {
      set({ isControlLoading: false });
    }
  },

  startMission: async (id) => {
    const missionId = id || get().currentMissionId;
    if (!missionId) {
      set({ error: "No mission selected" });
      return false;
    }

    set({ isControlLoading: true, error: null });
    try {
      const response = await missionApi.start(missionId);

      // Update mission status
      set((state) => ({
        mission: state.mission ? { ...state.mission, status: response.status } : null,
      }));

      // Add event
      get().addEvent({
        id: `event-start-${Date.now()}`,
        type: "mission_status",
        title: "Mission Started",
        description: response.message || "Mission execution started",
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });

      return true;
    } catch (error) {
      const message = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: message });
      return false;
    } finally {
      set({ isControlLoading: false });
    }
  },

  pauseMission: async (id) => {
    const missionId = id || get().currentMissionId;
    if (!missionId) {
      set({ error: "No mission selected" });
      return false;
    }

    set({ isControlLoading: true, error: null });
    try {
      const response = await missionApi.pause(missionId);

      // Update mission status
      set((state) => ({
        mission: state.mission ? { ...state.mission, status: response.status } : null,
      }));

      // Add event
      get().addEvent({
        id: `event-pause-${Date.now()}`,
        type: "mission_status",
        title: "Mission Paused",
        description: response.message || "Mission execution paused",
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });

      return true;
    } catch (error) {
      const message = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: message });
      return false;
    } finally {
      set({ isControlLoading: false });
    }
  },

  resumeMission: async (id) => {
    const missionId = id || get().currentMissionId;
    if (!missionId) {
      set({ error: "No mission selected" });
      return false;
    }

    set({ isControlLoading: true, error: null });
    try {
      const response = await missionApi.resume(missionId);

      // Update mission status
      set((state) => ({
        mission: state.mission ? { ...state.mission, status: response.status } : null,
      }));

      // Add event
      get().addEvent({
        id: `event-resume-${Date.now()}`,
        type: "mission_status",
        title: "Mission Resumed",
        description: response.message || "Mission execution resumed",
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });

      return true;
    } catch (error) {
      const message = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: message });
      return false;
    } finally {
      set({ isControlLoading: false });
    }
  },

  stopMission: async (id) => {
    const missionId = id || get().currentMissionId;
    if (!missionId) {
      set({ error: "No mission selected" });
      return false;
    }

    set({ isControlLoading: true, error: null });
    try {
      const response = await missionApi.stop(missionId);

      // Update mission status
      set((state) => ({
        mission: state.mission ? { ...state.mission, status: response.status } : null,
      }));

      // Add event
      get().addEvent({
        id: `event-stop-${Date.now()}`,
        type: "mission_status",
        title: "Mission Stopped",
        description: response.message || "Mission execution stopped",
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });

      return true;
    } catch (error) {
      const message = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: message });
      return false;
    } finally {
      set({ isControlLoading: false });
    }
  },

  // ============================================
  // WebSocket Actions
  // ============================================

  connectWebSocket: (missionId) => {
    const { wsConnection } = get();

    // Disconnect existing connection
    if (wsConnection) {
      wsConnection.disconnect();
    }

    const ws = new MissionWebSocket(
      missionId,
      (message) => get().handleWebSocketMessage(message as WebSocketMessage),
      () => set({ isConnected: false }),
      () => set({ isConnected: false }),
      () => set({ isConnected: true })
    );

    ws.connect();
    set({ wsConnection: ws });
  },

  disconnectWebSocket: () => {
    const { wsConnection } = get();
    if (wsConnection) {
      wsConnection.disconnect();
    }
    set({ wsConnection: null, isConnected: false });
  },

  handleWebSocketMessage: (message) => {
    const { type, data, timestamp } = message;

    // Create event card for the message
    const eventCard: EventCard = {
      id: `event-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: type as EventCard["type"],
      title: getEventTitle(type, data),
      description: getEventDescription(type, data),
      timestamp,
      data,
      expanded: false,
    };

    // Add to events (except for some internal types)
    if (!["pong", "statistics"].includes(type)) {
      set((state) => ({
        events: [eventCard, ...state.events].slice(0, MAX_EVENTS_DISPLAY),
      }));
    }

    // Handle specific event types
    switch (type) {
      case "new_target":
        get().addTarget(data as Target);
        break;

      case "target_update":
        get().updateTarget(data as Target);
        break;

      case "new_vuln":
        get().addVulnerability(data as Vulnerability);
        break;

      case "new_cred":
        get().addCredential(data as Credential);
        break;

      case "new_session":
        get().addSession(data as Session);
        break;

      case "approval_request":
        get().addApproval(data as ApprovalRequest);
        break;

      case "approval_resolved":
        get().removeApproval((data as { action_id: string }).action_id);
        break;

      case "chat_message":
        get().addChatMessage(data as ChatMessage);
        break;

      case "mission_status":
      case "status_change":
        get().updateMissionStatus((data as { status: MissionStatus }).status);
        break;

      case "statistics":
        set({ statistics: data as MissionStatistics });
        break;

      case "ai_plan":
        // Handle AI plan tasks
        if ((data as { tasks?: PlanTask[] }).tasks) {
          get().setPlanTasks((data as { tasks: PlanTask[] }).tasks);
        }
        break;
    }
  },

  // ============================================
  // Chat Actions
  // ============================================

  sendMessage: async (content) => {
    const { currentMissionId } = get();
    if (!currentMissionId) return;

    try {
      const message = await chatApi.send(currentMissionId, content);
      get().addChatMessage(message);
    } catch (error) {
      const errorMessage = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: errorMessage });
    }
  },

  // ============================================
  // HITL Actions
  // ============================================

  approveAction: async (actionId, comment) => {
    const { currentMissionId } = get();
    if (!currentMissionId) return false;

    try {
      await hitlApi.approve(currentMissionId, actionId, comment);
      get().removeApproval(actionId);

      // Add event
      get().addEvent({
        id: `event-approve-${Date.now()}`,
        type: "approval_resolved",
        title: "Action Approved",
        description: `Action ${actionId} approved${comment ? `: ${comment}` : ""}`,
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });

      return true;
    } catch (error) {
      const errorMessage = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: errorMessage });
      return false;
    }
  },

  rejectAction: async (actionId, reason, comment) => {
    const { currentMissionId } = get();
    if (!currentMissionId) return false;

    try {
      await hitlApi.reject(currentMissionId, actionId, reason, comment);
      get().removeApproval(actionId);

      // Add event
      get().addEvent({
        id: `event-reject-${Date.now()}`,
        type: "approval_resolved",
        title: "Action Rejected",
        description: `Action ${actionId} rejected: ${reason}`,
        timestamp: new Date().toISOString(),
        status: "completed",
        expanded: false,
      });

      return true;
    } catch (error) {
      const errorMessage = error instanceof ApiError ? error.message : (error as Error).message;
      set({ error: errorMessage });
      return false;
    }
  },

  // ============================================
  // Event Actions
  // ============================================

  addEvent: (event) => {
    set((state) => ({
      events: [event, ...state.events].slice(0, MAX_EVENTS_DISPLAY),
    }));
  },

  toggleEventExpanded: (eventId) => {
    set((state) => ({
      events: state.events.map((e) =>
        e.id === eventId ? { ...e, expanded: !e.expanded } : e
      ),
    }));
  },

  clearEvents: () => set({ events: [] }),

  // ============================================
  // Plan Actions
  // ============================================

  updateTaskStatus: (taskId, status) => {
    set((state) => ({
      planTasks: state.planTasks.map((t) =>
        t.id === taskId ? { ...t, status } : t
      ),
    }));
  },

  setPlanTasks: (tasks) => set({ planTasks: tasks }),

  // ============================================
  // Data Update Actions
  // ============================================

  addTarget: (target) => {
    set((state) => ({
      targets: [...state.targets, target],
    }));
  },

  updateTarget: (target) => {
    set((state) => ({
      targets: state.targets.map((t) =>
        t.target_id === target.target_id ? target : t
      ),
    }));
  },

  addVulnerability: (vuln) => {
    set((state) => ({
      vulnerabilities: [...state.vulnerabilities, vuln],
    }));
  },

  addCredential: (cred) => {
    set((state) => ({
      credentials: [...state.credentials, cred],
    }));
  },

  addSession: (session) => {
    set((state) => ({
      sessions: [...state.sessions, session],
    }));
  },

  addApproval: (approval) => {
    set((state) => ({
      approvals: [...state.approvals, approval],
    }));
  },

  removeApproval: (actionId) => {
    set((state) => ({
      approvals: state.approvals.filter((a) => a.action_id !== actionId),
    }));
  },

  addChatMessage: (message) => {
    set((state) => ({
      chatMessages: [...state.chatMessages, message].slice(-MAX_CHAT_MESSAGES),
    }));
  },

  updateMissionStatus: (status) => {
    set((state) => ({
      mission: state.mission ? { ...state.mission, status } : null,
    }));
  },

  // ============================================
  // Utility Actions
  // ============================================

  clearError: () => set({ error: null }),

  reset: () => {
    const { wsConnection } = get();
    if (wsConnection) {
      wsConnection.disconnect();
    }
    set(initialState);
  },
}));

// ============================================
// Helper Functions
// ============================================

function getEventTitle(type: string, data: unknown): string {
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
      return "Approval Resolved";
    case "mission_status":
    case "status_change":
      return `Mission Status: ${d.status || "Updated"}`;
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

function getEventDescription(type: string, data: unknown): string {
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

// ============================================
// Selectors
// ============================================

export const selectMission = (state: MissionState) => state.mission;
export const selectTargets = (state: MissionState) => state.targets;
export const selectVulnerabilities = (state: MissionState) => state.vulnerabilities;
export const selectCredentials = (state: MissionState) => state.credentials;
export const selectSessions = (state: MissionState) => state.sessions;
export const selectApprovals = (state: MissionState) => state.approvals;
export const selectEvents = (state: MissionState) => state.events;
export const selectIsConnected = (state: MissionState) => state.isConnected;
export const selectIsLoading = (state: MissionState) => state.isLoading;
export const selectError = (state: MissionState) => state.error;

// ============================================
// Install Zustand Devtools
// ============================================

if (import.meta.env.DEV) {
  // @ts-expect-error - devtools extension
  window.__ZUSTAND_DEVTOOLS__ = useMissionStore;
}

export default useMissionStore;
