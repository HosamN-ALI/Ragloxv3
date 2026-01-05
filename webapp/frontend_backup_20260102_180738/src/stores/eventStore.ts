// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Event Store (Zustand)
// Core state management with WebSocket integration
// ═══════════════════════════════════════════════════════════════

import { create } from 'zustand'
import { devtools, subscribeWithSelector } from 'zustand/middleware'
import type {
  Target,
  Vulnerability,
  Session,
  MissionStats,
  TaskExecutionLog,
  ActivityItem,
  ApprovalRequest,
  ChatMessage,
  Toast,
  WebSocketMessage,
  GraphData,
  GraphNode,
  GraphLink,
} from '@/types'
import { generateId } from '@/lib/utils'

// ═══════════════════════════════════════════════════════════════
// WebSocket Connection State
// ═══════════════════════════════════════════════════════════════

type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'reconnecting'

interface WebSocketState {
  status: ConnectionStatus
  lastConnectedAt: string | null
  reconnectAttempts: number
  error: string | null
}

// ═══════════════════════════════════════════════════════════════
// Event Store State
// ═══════════════════════════════════════════════════════════════

interface EventStoreState {
  // Connection
  wsState: WebSocketState
  
  // Mission data
  currentMissionId: string | null
  missionStats: MissionStats
  
  // Entities
  targets: Map<string, Target>
  vulnerabilities: Map<string, Vulnerability>
  sessions: Map<string, Session>
  
  // Logs & Activity
  logs: TaskExecutionLog[]
  activities: ActivityItem[]
  
  // HITL
  pendingApprovals: ApprovalRequest[]
  chatMessages: ChatMessage[]
  
  // UI State
  toasts: Toast[]
  selectedTargetId: string | null
  isConsoleExpanded: boolean
  isSidebarCollapsed: boolean
  isAIPanelOpen: boolean
  
  // Graph data
  graphData: GraphData
}

// ═══════════════════════════════════════════════════════════════
// Event Store Actions
// ═══════════════════════════════════════════════════════════════

interface EventStoreActions {
  // WebSocket
  setConnectionStatus: (status: ConnectionStatus, error?: string) => void
  incrementReconnectAttempts: () => void
  resetReconnectAttempts: () => void
  
  // Mission
  setCurrentMission: (missionId: string | null) => void
  updateMissionStats: (stats: Partial<MissionStats>) => void
  
  // Targets
  addTarget: (target: Target) => void
  updateTarget: (targetId: string, updates: Partial<Target>) => void
  removeTarget: (targetId: string) => void
  
  // Vulnerabilities
  addVulnerability: (vuln: Vulnerability) => void
  updateVulnerability: (vulnId: string, updates: Partial<Vulnerability>) => void
  
  // Sessions
  addSession: (session: Session) => void
  updateSession: (sessionId: string, updates: Partial<Session>) => void
  
  // Logs
  addLog: (log: TaskExecutionLog) => void
  clearLogs: () => void
  
  // Activities
  addActivity: (activity: Omit<ActivityItem, 'id'>) => void
  clearActivities: () => void
  
  // HITL
  addApprovalRequest: (request: ApprovalRequest) => void
  removeApprovalRequest: (actionId: string) => void
  addChatMessage: (message: Omit<ChatMessage, 'id' | 'timestamp'>) => void
  
  // Toasts
  addToast: (toast: Omit<Toast, 'id'>) => void
  removeToast: (id: string) => void
  
  // UI
  setSelectedTarget: (targetId: string | null) => void
  toggleConsole: () => void
  toggleSidebar: () => void
  setSidebarCollapsed: (collapsed: boolean) => void
  toggleAIPanel: () => void
  
  // Graph
  updateGraphData: () => void
  
  // Process WebSocket messages
  processWebSocketMessage: (message: WebSocketMessage) => void
  
  // Reset
  reset: () => void
}

// ═══════════════════════════════════════════════════════════════
// Initial State
// ═══════════════════════════════════════════════════════════════

const initialMissionStats: MissionStats = {
  targets_discovered: 0,
  vulns_found: 0,
  creds_harvested: 0,
  sessions_established: 0,
  goals_achieved: 0,
  goals_total: 0,
  completion_percentage: 0,
  critical_vulns: 0,
  high_vulns: 0,
  active_sessions: 0,
}

const initialState: EventStoreState = {
  wsState: {
    status: 'disconnected',
    lastConnectedAt: null,
    reconnectAttempts: 0,
    error: null,
  },
  currentMissionId: null,
  missionStats: initialMissionStats,
  targets: new Map(),
  vulnerabilities: new Map(),
  sessions: new Map(),
  logs: [],
  activities: [],
  pendingApprovals: [],
  chatMessages: [],
  toasts: [],
  selectedTargetId: null,
  isConsoleExpanded: false,
  isSidebarCollapsed: false,
  isAIPanelOpen: false,
  graphData: { nodes: [], links: [] },
}

// ═══════════════════════════════════════════════════════════════
// Store Creation
// ═══════════════════════════════════════════════════════════════

export const useEventStore = create<EventStoreState & EventStoreActions>()(
  devtools(
    subscribeWithSelector((set, get) => ({
      ...initialState,
      
      // ═══════════════════════════════════════════════════════════
      // WebSocket Actions
      // ═══════════════════════════════════════════════════════════
      
      setConnectionStatus: (status, error) =>
        set((state) => ({
          wsState: {
            ...state.wsState,
            status,
            error: error ?? null,
            lastConnectedAt: status === 'connected' ? new Date().toISOString() : state.wsState.lastConnectedAt,
          },
        })),
      
      incrementReconnectAttempts: () =>
        set((state) => ({
          wsState: {
            ...state.wsState,
            reconnectAttempts: state.wsState.reconnectAttempts + 1,
          },
        })),
      
      resetReconnectAttempts: () =>
        set((state) => ({
          wsState: {
            ...state.wsState,
            reconnectAttempts: 0,
          },
        })),
      
      // ═══════════════════════════════════════════════════════════
      // Mission Actions
      // ═══════════════════════════════════════════════════════════
      
      setCurrentMission: (missionId) => set({ currentMissionId: missionId }),
      
      updateMissionStats: (stats) =>
        set((state) => ({
          missionStats: { ...state.missionStats, ...stats },
        })),
      
      // ═══════════════════════════════════════════════════════════
      // Target Actions
      // ═══════════════════════════════════════════════════════════
      
      addTarget: (target) =>
        set((state) => {
          const newTargets = new Map(state.targets)
          newTargets.set(target.target_id, target)
          return { targets: newTargets }
        }),
      
      updateTarget: (targetId, updates) =>
        set((state) => {
          const newTargets = new Map(state.targets)
          const existing = newTargets.get(targetId)
          if (existing) {
            newTargets.set(targetId, { ...existing, ...updates })
          }
          return { targets: newTargets }
        }),
      
      removeTarget: (targetId) =>
        set((state) => {
          const newTargets = new Map(state.targets)
          newTargets.delete(targetId)
          return { targets: newTargets }
        }),
      
      // ═══════════════════════════════════════════════════════════
      // Vulnerability Actions
      // ═══════════════════════════════════════════════════════════
      
      addVulnerability: (vuln) =>
        set((state) => {
          const newVulns = new Map(state.vulnerabilities)
          newVulns.set(vuln.vuln_id, vuln)
          return { vulnerabilities: newVulns }
        }),
      
      updateVulnerability: (vulnId, updates) =>
        set((state) => {
          const newVulns = new Map(state.vulnerabilities)
          const existing = newVulns.get(vulnId)
          if (existing) {
            newVulns.set(vulnId, { ...existing, ...updates })
          }
          return { vulnerabilities: newVulns }
        }),
      
      // ═══════════════════════════════════════════════════════════
      // Session Actions
      // ═══════════════════════════════════════════════════════════
      
      addSession: (session) =>
        set((state) => {
          const newSessions = new Map(state.sessions)
          newSessions.set(session.session_id, session)
          return { sessions: newSessions }
        }),
      
      updateSession: (sessionId, updates) =>
        set((state) => {
          const newSessions = new Map(state.sessions)
          const existing = newSessions.get(sessionId)
          if (existing) {
            newSessions.set(sessionId, { ...existing, ...updates })
          }
          return { sessions: newSessions }
        }),
      
      // ═══════════════════════════════════════════════════════════
      // Log Actions
      // ═══════════════════════════════════════════════════════════
      
      addLog: (log) =>
        set((state) => ({
          logs: [...state.logs.slice(-499), log], // Keep last 500 logs
        })),
      
      clearLogs: () => set({ logs: [] }),
      
      // ═══════════════════════════════════════════════════════════
      // Activity Actions
      // ═══════════════════════════════════════════════════════════
      
      addActivity: (activity) =>
        set((state) => ({
          activities: [
            { ...activity, id: generateId() },
            ...state.activities.slice(0, 99), // Keep last 100 activities
          ],
        })),
      
      clearActivities: () => set({ activities: [] }),
      
      // ═══════════════════════════════════════════════════════════
      // HITL Actions
      // ═══════════════════════════════════════════════════════════
      
      addApprovalRequest: (request) =>
        set((state) => ({
          pendingApprovals: [...state.pendingApprovals, request],
        })),
      
      removeApprovalRequest: (actionId) =>
        set((state) => ({
          pendingApprovals: state.pendingApprovals.filter((r) => r.action_id !== actionId),
        })),
      
      addChatMessage: (message) =>
        set((state) => ({
          chatMessages: [
            ...state.chatMessages,
            {
              ...message,
              id: generateId(),
              timestamp: new Date().toISOString(),
            },
          ],
        })),
      
      // ═══════════════════════════════════════════════════════════
      // Toast Actions
      // ═══════════════════════════════════════════════════════════
      
      addToast: (toast) => {
        const id = generateId()
        set((state) => ({
          toasts: [...state.toasts, { ...toast, id }],
        }))
        // Auto-remove after duration
        const duration = toast.duration ?? 5000
        if (duration > 0) {
          setTimeout(() => {
            get().removeToast(id)
          }, duration)
        }
      },
      
      removeToast: (id) =>
        set((state) => ({
          toasts: state.toasts.filter((t) => t.id !== id),
        })),
      
      // ═══════════════════════════════════════════════════════════
      // UI Actions
      // ═══════════════════════════════════════════════════════════
      
      setSelectedTarget: (targetId) => set({ selectedTargetId: targetId }),
      
      toggleConsole: () =>
        set((state) => ({ isConsoleExpanded: !state.isConsoleExpanded })),
      
      toggleSidebar: () =>
        set((state) => ({ isSidebarCollapsed: !state.isSidebarCollapsed })),
      
      setSidebarCollapsed: (collapsed: boolean) =>
        set({ isSidebarCollapsed: collapsed }),
      
      toggleAIPanel: () =>
        set((state) => ({ isAIPanelOpen: !state.isAIPanelOpen })),
      
      // ═══════════════════════════════════════════════════════════
      // Graph Actions
      // ═══════════════════════════════════════════════════════════
      
      updateGraphData: () => {
        const state = get()
        const targets = Array.from(state.targets.values())
        const CLUSTER_THRESHOLD = 20
        
        // If targets exceed threshold, group by subnet
        if (targets.length > CLUSTER_THRESHOLD) {
          const subnetMap = new Map<string, Target[]>()
          
          targets.forEach((target) => {
            // Extract subnet from IP (first 3 octets)
            const subnet = target.ip.split('.').slice(0, 3).join('.') + '.0/24'
            if (!subnetMap.has(subnet)) {
              subnetMap.set(subnet, [])
            }
            subnetMap.get(subnet)!.push(target)
          })
          
          const nodes: GraphNode[] = []
          const links: GraphLink[] = []
          
          // Create subnet nodes
          subnetMap.forEach((subnetTargets, subnet) => {
            nodes.push({
              id: subnet,
              name: subnet,
              type: 'subnet',
              status: 'cluster',
              childCount: subnetTargets.length,
              children: subnetTargets.map((t) => t.target_id),
            })
          })
          
          // Create links between subnets if there are attack paths
          // (This is simplified - in production you'd check actual attack paths)
          const subnets = Array.from(subnetMap.keys())
          for (let i = 0; i < subnets.length - 1; i++) {
            if (i + 1 < subnets.length) {
              links.push({
                source: subnets[i],
                target: subnets[i + 1],
                type: 'discovery',
              })
            }
          }
          
          set({ graphData: { nodes, links } })
        } else {
          // Show individual targets
          const nodes: GraphNode[] = targets.map((target) => ({
            id: target.target_id,
            name: target.hostname || target.ip,
            type: 'target',
            ip: target.ip,
            os: target.os,
            status: target.status,
            priority: target.priority,
          }))
          
          const links: GraphLink[] = []
          // Create discovery links (chain of discovery for demo)
          for (let i = 1; i < nodes.length; i++) {
            links.push({
              source: nodes[0].id,
              target: nodes[i].id,
              type: 'discovery',
            })
          }
          
          set({ graphData: { nodes, links } })
        }
      },
      
      // ═══════════════════════════════════════════════════════════
      // WebSocket Message Processing
      // ═══════════════════════════════════════════════════════════
      
      processWebSocketMessage: (message) => {
        const { type, data, timestamp } = message
        const actions = get()
        
        switch (type) {
          case 'connected':
            actions.setConnectionStatus('connected')
            actions.resetReconnectAttempts()
            actions.addActivity({
              type: 'status_change',
              title: 'Connected to RAGLOX',
              description: message.message,
              timestamp,
            })
            break
          
          case 'new_target':
            if (data) {
              const targetData = data as { target_id: string; ip: string; hostname?: string }
              const target: Target = {
                target_id: targetData.target_id,
                ip: targetData.ip,
                hostname: targetData.hostname,
                status: 'discovered',
                priority: 'medium',
                ports: {},
              }
              actions.addTarget(target)
              actions.updateMissionStats({
                targets_discovered: get().missionStats.targets_discovered + 1,
              })
              actions.addActivity({
                type: 'target_discovered',
                title: 'New Target Discovered',
                description: `${targetData.ip}${targetData.hostname ? ` (${targetData.hostname})` : ''}`,
                timestamp,
              })
              actions.updateGraphData()
            }
            break
          
          case 'new_vuln':
            if (data) {
              const vulnData = data as {
                vuln_id: string
                target_id: string
                severity: string
                type: string
              }
              const vuln: Vulnerability = {
                vuln_id: vulnData.vuln_id,
                target_id: vulnData.target_id,
                type: vulnData.type,
                severity: vulnData.severity as Vulnerability['severity'],
                status: 'discovered',
                exploit_available: false,
              }
              actions.addVulnerability(vuln)
              
              const currentStats = get().missionStats
              const newStats: Partial<MissionStats> = {
                vulns_found: currentStats.vulns_found + 1,
              }
              if (vulnData.severity === 'critical') {
                newStats.critical_vulns = (currentStats.critical_vulns ?? 0) + 1
              } else if (vulnData.severity === 'high') {
                newStats.high_vulns = (currentStats.high_vulns ?? 0) + 1
              }
              actions.updateMissionStats(newStats)
              
              actions.addActivity({
                type: 'vuln_found',
                title: 'Vulnerability Found',
                description: vulnData.type,
                timestamp,
                severity: vulnData.severity as Vulnerability['severity'],
              })
            }
            break
          
          case 'new_session':
            if (data) {
              const sessionData = data as {
                session_id: string
                target_id: string
                type: string
                privilege: string
              }
              const session: Session = {
                session_id: sessionData.session_id,
                target_id: sessionData.target_id,
                type: sessionData.type as Session['type'],
                privilege: sessionData.privilege,
                status: 'active',
                established_at: timestamp,
                last_activity: timestamp,
              }
              actions.addSession(session)
              actions.updateMissionStats({
                sessions_established: get().missionStats.sessions_established + 1,
                active_sessions: (get().missionStats.active_sessions ?? 0) + 1,
              })
              actions.addActivity({
                type: 'session_established',
                title: 'Session Established',
                description: `${sessionData.type} - ${sessionData.privilege}`,
                timestamp,
              })
            }
            break
          
          case 'goal_achieved':
            if (data) {
              const goalData = data as { goal: string }
              actions.updateMissionStats({
                goals_achieved: get().missionStats.goals_achieved + 1,
              })
              actions.addActivity({
                type: 'goal_achieved',
                title: 'Goal Achieved!',
                description: goalData.goal,
                timestamp,
              })
              actions.addToast({
                type: 'success',
                title: 'Goal Achieved',
                description: goalData.goal,
                duration: 10000,
              })
            }
            break
          
          case 'status_change':
            if (data) {
              const statusData = data as { old_status: string; new_status: string }
              actions.addActivity({
                type: 'status_change',
                title: 'Mission Status Changed',
                description: `${statusData.old_status} → ${statusData.new_status}`,
                timestamp,
              })
            }
            break
          
          case 'statistics':
            if (data) {
              actions.updateMissionStats(data as Partial<MissionStats>)
            }
            break
          
          case 'approval_request':
            if (data) {
              const approvalData = data as unknown as ApprovalRequest
              actions.addApprovalRequest({
                ...approvalData,
                requested_at: timestamp,
              })
              actions.addActivity({
                type: 'approval_required',
                title: 'Approval Required',
                description: approvalData.action_description,
                timestamp,
                severity: approvalData.risk_level as 'critical' | 'high' | 'medium' | 'low',
              })
              actions.addToast({
                type: 'warning',
                title: 'Approval Required',
                description: approvalData.action_description,
                duration: 0, // Don't auto-dismiss
                action: {
                  label: 'Review',
                  onClick: () => actions.toggleAIPanel(),
                },
              })
            }
            break
          
          case 'approval_response':
            if (data) {
              const responseData = data as { action_id: string; approved: boolean }
              actions.removeApprovalRequest(responseData.action_id)
            }
            break
          
          case 'chat_message':
            if (data) {
              const chatData = data as {
                message_id: string
                role: string
                content: string
                related_task_id?: string
                related_action_id?: string
              }
              actions.addChatMessage({
                role: chatData.role as ChatMessage['role'],
                content: chatData.content,
                related_task_id: chatData.related_task_id,
                related_action_id: chatData.related_action_id,
              })
            }
            break
          
          case 'task_execution_log':
            if (data) {
              const logData = data as unknown as TaskExecutionLog
              actions.addLog({
                ...logData,
                id: logData.id || generateId(),
                timestamp: timestamp,
              })
            }
            break
          
          case 'error':
            actions.addToast({
              type: 'error',
              title: 'Error',
              description: message.message || 'An error occurred',
            })
            break
          
          case 'pong':
            // Heartbeat response - no action needed
            break
          
          default:
            console.log('Unknown WebSocket event:', type, data)
        }
      },
      
      // ═══════════════════════════════════════════════════════════
      // Reset
      // ═══════════════════════════════════════════════════════════
      
      reset: () => set(initialState),
    })),
    { name: 'RAGLOX-EventStore' }
  )
)

// ═══════════════════════════════════════════════════════════════
// Selectors
// ═══════════════════════════════════════════════════════════════

export const selectIsConnected = (state: EventStoreState) =>
  state.wsState.status === 'connected'

export const selectConnectionStatus = (state: EventStoreState) =>
  state.wsState.status

export const selectTargets = (state: EventStoreState) =>
  Array.from(state.targets.values())

export const selectVulnerabilities = (state: EventStoreState) =>
  Array.from(state.vulnerabilities.values())

export const selectSessions = (state: EventStoreState) =>
  Array.from(state.sessions.values())

export const selectRecentLogs = (state: EventStoreState) =>
  state.logs.slice(-10)

export const selectLastLog = (state: EventStoreState) =>
  state.logs[state.logs.length - 1] || null

export const selectCriticalVulns = (state: EventStoreState) =>
  Array.from(state.vulnerabilities.values()).filter((v) => v.severity === 'critical')

export const selectSelectedTarget = (state: EventStoreState) =>
  state.selectedTargetId ? state.targets.get(state.selectedTargetId) : null
