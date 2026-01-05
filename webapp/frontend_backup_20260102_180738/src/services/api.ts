// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - API Service
// Centralized API calls for mission data
// ═══════════════════════════════════════════════════════════════

const API_BASE = '/api/v1'

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

export interface MissionResponse {
  mission_id: string
  name: string
  status: string
  scope: string[]
  goals: Record<string, string>
  statistics: {
    targets_discovered: number
    vulns_found: number
    creds_harvested: number
    sessions_established: number
    goals_achieved: number
  }
  target_count: number
  vuln_count: number
  created_at: string
  started_at: string | null
  completed_at: string | null
}

export interface TargetResponse {
  target_id: string
  ip: string
  hostname?: string
  os?: string
  status: string
  priority: string
  risk_score?: number
  ports: Record<string, string>
}

export interface VulnerabilityResponse {
  vuln_id: string
  target_id: string
  type: string
  name?: string
  severity: string
  cvss?: number
  status: string
  exploit_available: boolean
}

export interface CredentialResponse {
  cred_id: string
  target_id: string
  type: string
  username: string
  domain?: string
  privilege_level: string
  source?: string
  verified: boolean
  created_at?: string
}

export interface SessionResponse {
  session_id: string
  target_id: string
  type: string
  user: string
  privilege: string
  status: string
  established_at?: string
  last_activity?: string
}

// ═══════════════════════════════════════════════════════════════
// API Functions
// ═══════════════════════════════════════════════════════════════

export async function fetchMissions(): Promise<string[]> {
  const response = await fetch(`${API_BASE}/missions`)
  if (!response.ok) throw new Error('Failed to fetch missions')
  return response.json()
}

export async function fetchMission(missionId: string): Promise<MissionResponse> {
  const response = await fetch(`${API_BASE}/missions/${missionId}`)
  if (!response.ok) throw new Error(`Failed to fetch mission ${missionId}`)
  return response.json()
}

export async function fetchTargets(missionId: string): Promise<TargetResponse[]> {
  const response = await fetch(`${API_BASE}/missions/${missionId}/targets`)
  if (!response.ok) throw new Error('Failed to fetch targets')
  return response.json()
}

export async function fetchVulnerabilities(missionId: string): Promise<VulnerabilityResponse[]> {
  const response = await fetch(`${API_BASE}/missions/${missionId}/vulnerabilities`)
  if (!response.ok) throw new Error('Failed to fetch vulnerabilities')
  return response.json()
}

export async function fetchCredentials(missionId: string): Promise<CredentialResponse[]> {
  const response = await fetch(`${API_BASE}/missions/${missionId}/credentials`)
  if (!response.ok) throw new Error('Failed to fetch credentials')
  return response.json()
}

export async function fetchSessions(missionId: string): Promise<SessionResponse[]> {
  const response = await fetch(`${API_BASE}/missions/${missionId}/sessions`)
  if (!response.ok) throw new Error('Failed to fetch sessions')
  return response.json()
}

export async function fetchMissionStats(missionId: string): Promise<Record<string, any>> {
  const response = await fetch(`${API_BASE}/missions/${missionId}/stats`)
  if (!response.ok) throw new Error('Failed to fetch mission stats')
  return response.json()
}

// ═══════════════════════════════════════════════════════════════
// Mission Actions
// ═══════════════════════════════════════════════════════════════

export async function createMission(data: {
  name: string
  scope: string[]
  goals: string[]
  description?: string
}): Promise<{ mission_id: string }> {
  const response = await fetch(`${API_BASE}/missions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!response.ok) throw new Error('Failed to create mission')
  return response.json()
}

export async function startMission(missionId: string): Promise<void> {
  const response = await fetch(`${API_BASE}/missions/${missionId}/start`, {
    method: 'POST',
  })
  if (!response.ok) throw new Error('Failed to start mission')
}

export async function stopMission(missionId: string): Promise<void> {
  const response = await fetch(`${API_BASE}/missions/${missionId}/stop`, {
    method: 'POST',
  })
  if (!response.ok) throw new Error('Failed to stop mission')
}

export async function pauseMission(missionId: string): Promise<void> {
  const response = await fetch(`${API_BASE}/missions/${missionId}/pause`, {
    method: 'POST',
  })
  if (!response.ok) throw new Error('Failed to pause mission')
}

// ═══════════════════════════════════════════════════════════════
// Health Check
// ═══════════════════════════════════════════════════════════════

export async function fetchHealth(): Promise<{
  status: string
  components: {
    api: string
    blackboard: string
    knowledge: string
  }
}> {
  const response = await fetch('/health')
  if (!response.ok) throw new Error('Failed to fetch health')
  return response.json()
}
