// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Mission Lifecycle Store
// Professional Command Center State Management
// ═══════════════════════════════════════════════════════════════

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'
import type {
  Session,
  ApprovalRequest,
  Credential,
} from '@/types'

// ═══════════════════════════════════════════════════════════════
// Mission Phase Enum - Red Team Lifecycle
// ═══════════════════════════════════════════════════════════════

export type MissionPhase =
  | 'setup'           // No mission - show wizard
  | 'reconnaissance'  // Discovering assets
  | 'enumeration'     // Scanning ports/services
  | 'exploitation'    // Active attacks
  | 'post_exploitation' // Credential harvest, pivoting
  | 'completed'       // Mission done
  | 'aborted'         // Emergency stopped

export type SystemStatus =
  | 'standby'         // System armed, no active mission
  | 'active'          // Active operation in progress
  | 'awaiting_approval' // HITL decision required
  | 'paused'          // Mission paused
  | 'emergency_stop'  // Kill switch activated

// ═══════════════════════════════════════════════════════════════
// Timeline Event Types - Structured Mission Progress
// ═══════════════════════════════════════════════════════════════

export type TimelineEventType =
  | 'phase_start'
  | 'phase_complete'
  | 'target_discovered'
  | 'port_discovered'
  | 'vuln_found'
  | 'exploit_attempt'
  | 'exploit_success'
  | 'exploit_failed'
  | 'session_established'
  | 'credential_harvested'
  | 'file_extracted'
  | 'lateral_movement'
  | 'approval_required'
  | 'approval_granted'
  | 'approval_denied'
  | 'goal_achieved'
  | 'error'

export interface TimelineEvent {
  id: string
  timestamp: string
  type: TimelineEventType
  phase: MissionPhase
  title: string
  description: string
  metadata?: {
    target_id?: string
    target_ip?: string
    vuln_id?: string
    session_id?: string
    cred_id?: string
    action_id?: string
    risk_level?: string
    severity?: string
    file_path?: string
    source?: string
  }
  status: 'completed' | 'in_progress' | 'pending' | 'failed' | 'awaiting'
}

// ═══════════════════════════════════════════════════════════════
// Artifact Types - Stolen Files & Data
// ═══════════════════════════════════════════════════════════════

export interface Artifact {
  id: string
  target_id: string
  file_path: string
  file_name: string
  file_type: 'credentials' | 'config' | 'database' | 'key' | 'document' | 'binary' | 'other'
  content_preview?: string
  size_bytes: number
  extracted_at: string
  source_session_id?: string
}

// ═══════════════════════════════════════════════════════════════
// Enhanced Credential with Validation
// ═══════════════════════════════════════════════════════════════

export interface EnhancedCredential extends Credential {
  password?: string
  password_hash?: string
  validation_status: 'verified' | 'unverified' | 'invalid' | 'testing'
  last_tested?: string
  source_file?: string
  impact_assessment?: string
}

// ═══════════════════════════════════════════════════════════════
// Attack Path Visualization
// ═══════════════════════════════════════════════════════════════

export interface AttackPathNode {
  id: string
  target_id: string
  type: 'entry' | 'pivot' | 'objective'
  technique: string
  status: 'planned' | 'in_progress' | 'completed' | 'failed'
}

export interface AttackPath {
  id: string
  name: string
  nodes: AttackPathNode[]
  edges: Array<{ from: string; to: string; type: string }>
}

// ═══════════════════════════════════════════════════════════════
// Mission Store State
// ═══════════════════════════════════════════════════════════════

interface MissionStoreState {
  // Core Mission State
  missionId: string | null
  missionName: string
  missionPhase: MissionPhase
  systemStatus: SystemStatus
  
  // Mission Configuration
  scope: string[]
  goals: string[]
  intensity: 'stealth' | 'balanced' | 'aggressive'
  
  // Timeline (Structured Log)
  timeline: TimelineEvent[]
  currentPhaseStartTime: string | null
  
  // Loot & Access
  credentials: Map<string, EnhancedCredential>
  artifacts: Map<string, Artifact>
  activeSessions: Map<string, Session>
  
  // Attack Intelligence
  attackPaths: AttackPath[]
  aiRecommendations: string[]
  
  // HITL State
  currentApproval: ApprovalRequest | null
  approvalHistory: Array<ApprovalRequest & { decision: 'approved' | 'rejected'; decided_at: string }>
  
  // Emergency Control
  emergencyStopActive: boolean
  emergencyStopReason: string | null
  
  // Stats derived from data
  phaseProgress: Record<MissionPhase, number>
}

// ═══════════════════════════════════════════════════════════════
// Mission Store Actions
// ═══════════════════════════════════════════════════════════════

interface MissionStoreActions {
  // Mission Lifecycle
  initMission: (config: { name: string; scope: string[]; goals: string[]; intensity: 'stealth' | 'balanced' | 'aggressive' }) => void
  startMission: (missionId: string) => void
  advancePhase: (newPhase: MissionPhase) => void
  pauseMission: () => void
  resumeMission: () => void
  completeMission: () => void
  abortMission: (reason: string) => void
  
  // Timeline Management
  addTimelineEvent: (event: Omit<TimelineEvent, 'id' | 'timestamp' | 'phase'>) => void
  updateTimelineEvent: (eventId: string, updates: Partial<TimelineEvent>) => void
  
  // Credential Management
  addCredential: (cred: EnhancedCredential) => void
  updateCredentialStatus: (credId: string, status: EnhancedCredential['validation_status']) => void
  
  // Artifact Management
  addArtifact: (artifact: Artifact) => void
  
  // Session Management
  addActiveSession: (session: Session) => void
  removeActiveSession: (sessionId: string) => void
  
  // HITL
  setCurrentApproval: (approval: ApprovalRequest | null) => void
  recordApprovalDecision: (actionId: string, decision: 'approved' | 'rejected') => void
  
  // Emergency Control
  activateEmergencyStop: (reason: string) => void
  resetEmergencyStop: () => void
  
  // AI Intelligence
  addAIRecommendation: (recommendation: string) => void
  clearAIRecommendations: () => void
  
  // Reset
  resetMission: () => void
}

// ═══════════════════════════════════════════════════════════════
// Initial State
// ═══════════════════════════════════════════════════════════════

const initialState: MissionStoreState = {
  missionId: null,
  missionName: '',
  missionPhase: 'setup',
  systemStatus: 'standby',
  
  scope: [],
  goals: [],
  intensity: 'balanced',
  
  timeline: [],
  currentPhaseStartTime: null,
  
  credentials: new Map(),
  artifacts: new Map(),
  activeSessions: new Map(),
  
  attackPaths: [],
  aiRecommendations: [],
  
  currentApproval: null,
  approvalHistory: [],
  
  emergencyStopActive: false,
  emergencyStopReason: null,
  
  phaseProgress: {
    setup: 0,
    reconnaissance: 0,
    enumeration: 0,
    exploitation: 0,
    post_exploitation: 0,
    completed: 0,
    aborted: 0,
  },
}

// ═══════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════

const generateId = () => `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

// ═══════════════════════════════════════════════════════════════
// Store Creation
// ═══════════════════════════════════════════════════════════════

export const useMissionStore = create<MissionStoreState & MissionStoreActions>()(
  devtools(
    (set) => ({
      ...initialState,
      
      // ═══════════════════════════════════════════════════════════
      // Mission Lifecycle Actions
      // ═══════════════════════════════════════════════════════════
      
      initMission: (config) =>
        set({
          missionName: config.name,
          scope: config.scope,
          goals: config.goals,
          intensity: config.intensity,
          missionPhase: 'setup',
          systemStatus: 'standby',
          timeline: [{
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'phase_start',
            phase: 'setup',
            title: 'Mission Initialized',
            description: `Mission "${config.name}" configured with ${config.scope.length} target(s)`,
            status: 'completed',
          }],
        }),
      
      startMission: (missionId) =>
        set((state) => ({
          missionId,
          missionPhase: 'reconnaissance',
          systemStatus: 'active',
          currentPhaseStartTime: new Date().toISOString(),
          timeline: [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'phase_start',
            phase: 'reconnaissance',
            title: 'Reconnaissance Started',
            description: 'Initiating network discovery and asset enumeration',
            status: 'in_progress',
          }],
        })),
      
      advancePhase: (newPhase) =>
        set((state) => {
          const now = new Date().toISOString()
          const updatedTimeline = [...state.timeline]
          
          // Mark current phase as complete
          const lastPhaseEvent = [...updatedTimeline].reverse().find(
            (e: TimelineEvent) => e.type === 'phase_start' && e.status === 'in_progress'
          )
          if (lastPhaseEvent) {
            const idx = updatedTimeline.indexOf(lastPhaseEvent)
            updatedTimeline[idx] = { ...lastPhaseEvent, status: 'completed' }
          }
          
          // Add new phase start
          updatedTimeline.push({
            id: generateId(),
            timestamp: now,
            type: 'phase_start',
            phase: newPhase,
            title: `${newPhase.charAt(0).toUpperCase() + newPhase.slice(1).replace('_', ' ')} Phase`,
            description: `Transitioning to ${newPhase} operations`,
            status: 'in_progress',
          })
          
          return {
            missionPhase: newPhase,
            currentPhaseStartTime: now,
            timeline: updatedTimeline,
            systemStatus: newPhase === 'completed' ? 'standby' : 'active',
          }
        }),
      
      pauseMission: () =>
        set((state) => ({
          systemStatus: 'paused',
          timeline: [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'phase_start',
            phase: state.missionPhase,
            title: 'Mission Paused',
            description: 'Operation temporarily suspended by operator',
            status: 'pending',
          }],
        })),
      
      resumeMission: () =>
        set((state) => ({
          systemStatus: 'active',
          timeline: [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'phase_start',
            phase: state.missionPhase,
            title: 'Mission Resumed',
            description: 'Operation continuing from paused state',
            status: 'in_progress',
          }],
        })),
      
      completeMission: () =>
        set((state) => ({
          missionPhase: 'completed',
          systemStatus: 'standby',
          timeline: [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'phase_complete',
            phase: 'completed',
            title: 'Mission Completed',
            description: 'All objectives achieved. Operation concluded successfully.',
            status: 'completed',
          }],
        })),
      
      abortMission: (reason) =>
        set((state) => ({
          missionPhase: 'aborted',
          systemStatus: 'emergency_stop',
          emergencyStopActive: true,
          emergencyStopReason: reason,
          timeline: [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'error',
            phase: 'aborted',
            title: 'Mission Aborted',
            description: reason,
            status: 'failed',
          }],
        })),
      
      // ═══════════════════════════════════════════════════════════
      // Timeline Management
      // ═══════════════════════════════════════════════════════════
      
      addTimelineEvent: (event) =>
        set((state) => ({
          timeline: [...state.timeline, {
            ...event,
            id: generateId(),
            timestamp: new Date().toISOString(),
            phase: state.missionPhase,
          }],
        })),
      
      updateTimelineEvent: (eventId, updates) =>
        set((state) => ({
          timeline: state.timeline.map((e) =>
            e.id === eventId ? { ...e, ...updates } : e
          ),
        })),
      
      // ═══════════════════════════════════════════════════════════
      // Credential Management
      // ═══════════════════════════════════════════════════════════
      
      addCredential: (cred) =>
        set((state) => {
          const newCreds = new Map(state.credentials)
          newCreds.set(cred.cred_id, cred)
          
          // Add timeline event
          const newTimeline = [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'credential_harvested' as TimelineEventType,
            phase: state.missionPhase,
            title: 'Credential Harvested',
            description: `${cred.type}: ${cred.username || 'unknown'}@${cred.domain || 'local'}`,
            metadata: {
              cred_id: cred.cred_id,
              source: cred.source,
            },
            status: 'completed' as const,
          }]
          
          return {
            credentials: newCreds,
            timeline: newTimeline,
          }
        }),
      
      updateCredentialStatus: (credId, status) =>
        set((state) => {
          const newCreds = new Map(state.credentials)
          const cred = newCreds.get(credId)
          if (cred) {
            newCreds.set(credId, {
              ...cred,
              validation_status: status,
              last_tested: new Date().toISOString(),
            })
          }
          return { credentials: newCreds }
        }),
      
      // ═══════════════════════════════════════════════════════════
      // Artifact Management
      // ═══════════════════════════════════════════════════════════
      
      addArtifact: (artifact) =>
        set((state) => {
          const newArtifacts = new Map(state.artifacts)
          newArtifacts.set(artifact.id, artifact)
          
          const newTimeline = [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'file_extracted' as TimelineEventType,
            phase: state.missionPhase,
            title: 'File Extracted',
            description: `${artifact.file_name} (${artifact.file_type})`,
            metadata: {
              file_path: artifact.file_path,
              target_id: artifact.target_id,
            },
            status: 'completed' as const,
          }]
          
          return {
            artifacts: newArtifacts,
            timeline: newTimeline,
          }
        }),
      
      // ═══════════════════════════════════════════════════════════
      // Session Management
      // ═══════════════════════════════════════════════════════════
      
      addActiveSession: (session) =>
        set((state) => {
          const newSessions = new Map(state.activeSessions)
          newSessions.set(session.session_id, session)
          
          const newTimeline = [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'session_established' as TimelineEventType,
            phase: state.missionPhase,
            title: 'Session Established',
            description: `${session.type.toUpperCase()} shell as ${session.user || 'unknown'} (${session.privilege})`,
            metadata: {
              session_id: session.session_id,
              target_id: session.target_id,
            },
            status: 'completed' as const,
          }]
          
          return {
            activeSessions: newSessions,
            timeline: newTimeline,
          }
        }),
      
      removeActiveSession: (sessionId) =>
        set((state) => {
          const newSessions = new Map(state.activeSessions)
          newSessions.delete(sessionId)
          return { activeSessions: newSessions }
        }),
      
      // ═══════════════════════════════════════════════════════════
      // HITL Actions
      // ═══════════════════════════════════════════════════════════
      
      setCurrentApproval: (approval) =>
        set((state) => ({
          currentApproval: approval,
          systemStatus: approval ? 'awaiting_approval' : state.systemStatus === 'awaiting_approval' ? 'active' : state.systemStatus,
          timeline: approval ? [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'approval_required' as TimelineEventType,
            phase: state.missionPhase,
            title: 'Approval Required',
            description: approval.action_description,
            metadata: {
              action_id: approval.action_id,
              risk_level: approval.risk_level,
              target_ip: approval.target_ip,
            },
            status: 'awaiting' as const,
          }] : state.timeline,
        })),
      
      recordApprovalDecision: (actionId, decision) =>
        set((state) => {
          const approval = state.currentApproval
          if (!approval || approval.action_id !== actionId) return state
          
          const updatedTimeline = [...state.timeline]
          const approvalEvent = [...updatedTimeline].reverse().find(
            (e: TimelineEvent) => e.type === 'approval_required' && e.metadata?.action_id === actionId
          )
          if (approvalEvent) {
            const idx = updatedTimeline.indexOf(approvalEvent)
            updatedTimeline[idx] = { ...approvalEvent, status: 'completed' }
          }
          
          updatedTimeline.push({
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: decision === 'approved' ? 'approval_granted' : 'approval_denied',
            phase: state.missionPhase,
            title: decision === 'approved' ? 'Action Approved' : 'Action Denied',
            description: approval.action_description,
            metadata: { action_id: actionId },
            status: 'completed',
          })
          
          return {
            currentApproval: null,
            systemStatus: 'active',
            approvalHistory: [...state.approvalHistory, {
              ...approval,
              decision,
              decided_at: new Date().toISOString(),
            }],
            timeline: updatedTimeline,
          }
        }),
      
      // ═══════════════════════════════════════════════════════════
      // Emergency Control
      // ═══════════════════════════════════════════════════════════
      
      activateEmergencyStop: (reason) =>
        set((state) => ({
          emergencyStopActive: true,
          emergencyStopReason: reason,
          systemStatus: 'emergency_stop',
          timeline: [...state.timeline, {
            id: generateId(),
            timestamp: new Date().toISOString(),
            type: 'error',
            phase: state.missionPhase,
            title: 'EMERGENCY STOP ACTIVATED',
            description: reason,
            status: 'failed',
          }],
        })),
      
      resetEmergencyStop: () =>
        set({
          emergencyStopActive: false,
          emergencyStopReason: null,
          systemStatus: 'standby',
        }),
      
      // ═══════════════════════════════════════════════════════════
      // AI Intelligence
      // ═══════════════════════════════════════════════════════════
      
      addAIRecommendation: (recommendation) =>
        set((state) => ({
          aiRecommendations: [...state.aiRecommendations, recommendation],
        })),
      
      clearAIRecommendations: () => set({ aiRecommendations: [] }),
      
      // ═══════════════════════════════════════════════════════════
      // Reset
      // ═══════════════════════════════════════════════════════════
      
      resetMission: () => set({
        ...initialState,
        credentials: new Map(),
        artifacts: new Map(),
        activeSessions: new Map(),
      }),
    }),
    { name: 'RAGLOX-MissionStore' }
  )
)

// ═══════════════════════════════════════════════════════════════
// Selectors
// ═══════════════════════════════════════════════════════════════

export const selectCredentials = (state: MissionStoreState) =>
  Array.from(state.credentials.values())

export const selectVerifiedCredentials = (state: MissionStoreState) =>
  Array.from(state.credentials.values()).filter(c => c.validation_status === 'verified')

export const selectArtifacts = (state: MissionStoreState) =>
  Array.from(state.artifacts.values())

export const selectActiveSessions = (state: MissionStoreState) =>
  Array.from(state.activeSessions.values())

export const selectRecentTimeline = (state: MissionStoreState) =>
  state.timeline.slice(-20)

export const selectPhaseEvents = (phase: MissionPhase) => (state: MissionStoreState) =>
  state.timeline.filter(e => e.phase === phase)

export const selectIsOperational = (state: MissionStoreState) =>
  state.systemStatus === 'active' || state.systemStatus === 'awaiting_approval'

export const selectNeedsApproval = (state: MissionStoreState) =>
  state.currentApproval !== null
