// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Mission Data Hook
// Manages mission context and automatic data loading
// ═══════════════════════════════════════════════════════════════

import { useEffect, useCallback, useRef } from 'react'
import { useEventStore } from '@/stores/eventStore'
import { useMissionStore } from '@/stores/missionStore'
import {
  fetchMissions,
  fetchMission,
  fetchTargets,
  fetchVulnerabilities,
  fetchCredentials,
  fetchSessions,
} from '@/services/api'
import type { Target, Vulnerability, Session } from '@/types'

const MISSION_ID_KEY = 'raglox_current_mission_id'
const POLL_INTERVAL = 30000 // 30 seconds (reduced frequency)

// Global state for initialization (survives HMR and StrictMode remounts)
const globalState = {
  initialized: false,
  initializing: false,
}

export function useMissionData() {
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const isLoadingRef = useRef(false)
  const mountedRef = useRef(true)
  
  // Event store actions
  const {
    currentMissionId,
    setCurrentMission,
    addTarget,
    addVulnerability,
    addSession,
    updateMissionStats,
    addLog,
  } = useEventStore()
  
  // Mission store actions
  const {
    addCredential,
  } = useMissionStore()

  // ═══════════════════════════════════════════════════════════════
  // Load Mission Data from API
  // ═══════════════════════════════════════════════════════════════

  const loadMissionData = useCallback(async (missionId: string) => {
    if (isLoadingRef.current) return
    isLoadingRef.current = true
    
    try {
      console.log('[MissionData] Loading data for mission:', missionId)
      
      // Fetch all data in parallel
      const [mission, targets, vulns, creds, sessions] = await Promise.all([
        fetchMission(missionId),
        fetchTargets(missionId),
        fetchVulnerabilities(missionId),
        fetchCredentials(missionId),
        fetchSessions(missionId),
      ])
      
      console.log('[MissionData] Loaded:', {
        mission: mission.name,
        targets: targets.length,
        vulns: vulns.length,
        creds: creds.length,
        sessions: sessions.length,
      })
      
      // Update mission stats
      updateMissionStats({
        targets_discovered: mission.statistics.targets_discovered,
        vulns_found: mission.statistics.vulns_found,
        creds_harvested: mission.statistics.creds_harvested,
        sessions_established: mission.statistics.sessions_established,
        goals_achieved: mission.statistics.goals_achieved,
      })
      
      // Add targets to store
      targets.forEach((target) => {
        const t: Target = {
          target_id: target.target_id,
          ip: target.ip,
          hostname: target.hostname,
          os: target.os,
          status: target.status as any,
          priority: target.priority as any,
          risk_score: target.risk_score,
          ports: target.ports,
        }
        addTarget(t)
      })
      
      // Add vulnerabilities to store
      vulns.forEach((vuln) => {
        const v: Vulnerability = {
          vuln_id: vuln.vuln_id,
          target_id: vuln.target_id,
          type: vuln.type,
          name: vuln.name || vuln.type,
          severity: vuln.severity as any,
          cvss: vuln.cvss,
          status: vuln.status as any,
          exploit_available: vuln.exploit_available,
        }
        addVulnerability(v)
      })
      
      // Add credentials to mission store
      creds.forEach((cred) => {
        addCredential({
          cred_id: cred.cred_id,
          target_id: cred.target_id,
          type: cred.type,
          username: cred.username,
          password_hash: '••••••••', // Masked
          domain: cred.domain || undefined,
          source: cred.source || 'unknown',
          privilege_level: cred.privilege_level,
          verified: cred.verified,
          validation_status: cred.verified ? 'verified' : 'unverified',
        })
      })
      
      // Add sessions to event store
      sessions.forEach((session) => {
        const s: Session = {
          session_id: session.session_id,
          target_id: session.target_id,
          type: session.type as any,
          user: session.user,
          privilege: session.privilege,
          status: session.status as any,
          established_at: session.established_at || new Date().toISOString(),
          last_activity: session.last_activity || new Date().toISOString(),
        }
        addSession(s)
      })
      
      // Log successful load
      addLog({
        id: `load-${Date.now()}`,
        timestamp: new Date().toISOString(),
        level: 'info',
        message: `Loaded mission data: ${targets.length} targets, ${vulns.length} vulns, ${creds.length} creds, ${sessions.length} sessions`,
        specialist: 'System',
      })
      
    } catch (error) {
      console.error('[MissionData] Failed to load:', error)
      addLog({
        id: `error-${Date.now()}`,
        timestamp: new Date().toISOString(),
        level: 'error',
        message: `Failed to load mission data: ${error}`,
        specialist: 'System',
      })
    } finally {
      isLoadingRef.current = false
    }
  }, [addTarget, addVulnerability, addSession, addCredential, updateMissionStats, addLog])

  // ═══════════════════════════════════════════════════════════════
  // Select Mission
  // ═══════════════════════════════════════════════════════════════

  const selectMission = useCallback(async (missionId: string) => {
    console.log('[MissionData] Selecting mission:', missionId)
    
    // Save to localStorage
    localStorage.setItem(MISSION_ID_KEY, missionId)
    
    // Update store
    setCurrentMission(missionId)
    
    // Load data
    await loadMissionData(missionId)
  }, [setCurrentMission, loadMissionData])

  // ═══════════════════════════════════════════════════════════════
  // Auto-load on mount
  // ═══════════════════════════════════════════════════════════════

  const initializeMission = useCallback(async () => {
    // Prevent concurrent or duplicate initialization
    if (globalState.initialized || globalState.initializing) {
      return
    }
    globalState.initializing = true
    
    try {
      // Check localStorage for saved mission
      const savedMissionId = localStorage.getItem(MISSION_ID_KEY)
      
      if (savedMissionId) {
        console.log('[MissionData] Found saved mission:', savedMissionId)
        try {
          // Verify mission still exists
          await fetchMission(savedMissionId)
          if (mountedRef.current) {
            await selectMission(savedMissionId)
          }
          globalState.initialized = true
          return
        } catch {
          console.log('[MissionData] Saved mission not found, clearing')
          localStorage.removeItem(MISSION_ID_KEY)
        }
      }
      
      // Try to find any active mission
      const missions = await fetchMissions()
      if (missions.length > 0 && mountedRef.current) {
        console.log('[MissionData] Auto-selecting first mission:', missions[0])
        await selectMission(missions[0])
      } else {
        console.log('[MissionData] No missions found')
      }
      globalState.initialized = true
    } catch (error) {
      console.error('[MissionData] Failed to fetch missions:', error)
    } finally {
      globalState.initializing = false
    }
  }, [selectMission])

  // ═══════════════════════════════════════════════════════════════
  // Polling for updates
  // ═══════════════════════════════════════════════════════════════

  const startPolling = useCallback(() => {
    if (pollRef.current) return
    
    pollRef.current = setInterval(() => {
      if (currentMissionId) {
        loadMissionData(currentMissionId)
      }
    }, POLL_INTERVAL)
  }, [currentMissionId, loadMissionData])

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [])

  // ═══════════════════════════════════════════════════════════════
  // Effects
  // ═══════════════════════════════════════════════════════════════

  // Initialize on mount
  useEffect(() => {
    mountedRef.current = true
    initializeMission()
    return () => {
      mountedRef.current = false
      stopPolling()
    }
  }, [initializeMission, stopPolling])

  // Start polling when mission is selected
  useEffect(() => {
    if (currentMissionId) {
      startPolling()
    }
    return () => stopPolling()
  }, [currentMissionId, startPolling, stopPolling])

  // ═══════════════════════════════════════════════════════════════
  // Return
  // ═══════════════════════════════════════════════════════════════

  return {
    currentMissionId,
    selectMission,
    refreshData: () => currentMissionId && loadMissionData(currentMissionId),
    isLoading: isLoadingRef.current,
  }
}
