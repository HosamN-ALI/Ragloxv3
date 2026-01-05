// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Mission Selector Component
// Dropdown to select and switch between missions
// ═══════════════════════════════════════════════════════════════

import { useState, useEffect } from 'react'
import { ChevronDown, Target, Plus, RefreshCw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'
import { fetchMissions, fetchMission } from '@/services/api'
import { useMissionData } from '@/hooks/useMissionData'

interface MissionInfo {
  id: string
  name: string
  status: string
  targets: number
  vulns: number
}

export function MissionSelector() {
  const [isOpen, setIsOpen] = useState(false)
  const [missions, setMissions] = useState<MissionInfo[]>([])
  const [isLoading, setIsLoading] = useState(false)
  
  const { currentMissionId, missionStats } = useEventStore()
  const { selectMission } = useMissionData()
  
  const currentMission = missions.find(m => m.id === currentMissionId)

  // Load missions list
  const loadMissions = async () => {
    setIsLoading(true)
    try {
      const missionIds = await fetchMissions()
      const missionDetails = await Promise.all(
        missionIds.map(async (id) => {
          try {
            const m = await fetchMission(id)
            return {
              id: m.mission_id,
              name: m.name,
              status: m.status,
              targets: m.statistics.targets_discovered,
              vulns: m.statistics.vulns_found,
            }
          } catch {
            return null
          }
        })
      )
      setMissions(missionDetails.filter(Boolean) as MissionInfo[])
    } catch (error) {
      console.error('Failed to load missions:', error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadMissions()
  }, [])

  const getStatusDot = (status: string) => {
    switch (status) {
      case 'running': return 'bg-green-400 animate-pulse'
      case 'paused': return 'bg-yellow-400'
      case 'completed': return 'bg-blue-400'
      case 'failed': return 'bg-red-400'
      default: return 'bg-zinc-400'
    }
  }

  return (
    <div className="relative">
      {/* Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          'flex items-center gap-2 px-3 py-1.5 rounded-lg',
          'bg-zinc-800/50 border border-zinc-700/50',
          'hover:bg-zinc-800 hover:border-zinc-600',
          'transition-all duration-200',
          isOpen && 'bg-zinc-800 border-zinc-600'
        )}
      >
        <Target className="h-4 w-4 text-royal-blue" />
        
        {currentMission ? (
          <>
            <div className={cn('w-2 h-2 rounded-full', getStatusDot(currentMission.status))} />
            <span className="text-sm font-medium text-text-primary-dark max-w-[200px] truncate">
              {currentMission.name}
            </span>
            <span className="text-xs text-text-muted-dark">
              ({missionStats.targets_discovered}T / {missionStats.vulns_found}V)
            </span>
          </>
        ) : (
          <span className="text-sm text-text-muted-dark">No Mission Selected</span>
        )}
        
        <ChevronDown className={cn(
          'h-4 w-4 text-text-muted-dark transition-transform',
          isOpen && 'rotate-180'
        )} />
      </button>

      {/* Dropdown */}
      {isOpen && (
        <>
          {/* Backdrop */}
          <div 
            className="fixed inset-0 z-40" 
            onClick={() => setIsOpen(false)} 
          />
          
          {/* Menu */}
          <div className={cn(
            'absolute top-full left-0 mt-2 z-50',
            'w-80 rounded-xl overflow-hidden',
            'bg-zinc-900 border border-zinc-700',
            'shadow-2xl shadow-black/50'
          )}>
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
              <span className="text-sm font-semibold text-text-primary-dark">
                Active Missions
              </span>
              <button
                onClick={loadMissions}
                className="p-1.5 rounded-lg hover:bg-zinc-800 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
              >
                <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
              </button>
            </div>

            {/* Mission List */}
            <div className="max-h-64 overflow-y-auto">
              {missions.length === 0 ? (
                <div className="px-4 py-6 text-center">
                  <Target className="h-8 w-8 mx-auto mb-2 text-text-muted-dark" />
                  <p className="text-sm text-text-muted-dark">No missions found</p>
                  <p className="text-xs text-text-muted-dark mt-1">Create a new mission to get started</p>
                </div>
              ) : (
                missions.map((mission) => (
                  <button
                    key={mission.id}
                    onClick={() => {
                      selectMission(mission.id)
                      setIsOpen(false)
                    }}
                    className={cn(
                      'w-full px-4 py-3 text-left',
                      'hover:bg-zinc-800 transition-colors',
                      'border-b border-zinc-800/50 last:border-b-0',
                      mission.id === currentMissionId && 'bg-royal-blue/10 border-l-2 border-l-royal-blue'
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <div className={cn('w-2.5 h-2.5 rounded-full', getStatusDot(mission.status))} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-text-primary-dark truncate">
                          {mission.name}
                        </p>
                        <p className="text-xs text-text-muted-dark">
                          {mission.targets} targets · {mission.vulns} vulns · {mission.status}
                        </p>
                      </div>
                      {mission.id === currentMissionId && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-royal-blue/20 text-royal-blue font-medium">
                          ACTIVE
                        </span>
                      )}
                    </div>
                  </button>
                ))
              )}
            </div>

            {/* Footer */}
            <div className="px-4 py-3 border-t border-zinc-800 bg-zinc-900/50">
              <a
                href="/mission/new"
                className={cn(
                  'flex items-center justify-center gap-2',
                  'w-full px-4 py-2 rounded-lg',
                  'bg-royal-blue/10 text-royal-blue',
                  'hover:bg-royal-blue/20 transition-colors',
                  'text-sm font-medium'
                )}
              >
                <Plus className="h-4 w-4" />
                New Mission
              </a>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
