// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Workspace C: Loot & Access View
// Session management, credentials, and artifacts
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { useState, useMemo } from 'react'
import {
  Terminal,
  Key,
  FileArchive,
  Folder,
  File,
  FileText,
  Database,
  Download,
  Eye,
  Clock,
  Server,
  ChevronRight,
  Shield,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useMissionStore } from '@/stores/missionStore'
import { useShallow } from 'zustand/shallow'
import { CredentialVault } from '@/components/loot/CredentialVault'
import { SessionManager } from '@/components/loot/SessionTerminal'
// Types imported from stores

// ═══════════════════════════════════════════════════════════════
// Tab Configuration
// ═══════════════════════════════════════════════════════════════

type LootTab = 'sessions' | 'credentials' | 'artifacts'

interface TabConfig {
  id: LootTab
  label: string
  icon: React.ElementType
  badge?: number
}

// ═══════════════════════════════════════════════════════════════
// Artifacts Gallery Component
// ═══════════════════════════════════════════════════════════════

function ArtifactsGallery() {
  // Use useShallow to prevent infinite loops with Map.values()
  const artifactsMap = useMissionStore(useShallow((state) => state.artifacts))
  const artifacts = useMemo(() => Array.from(artifactsMap.values()), [artifactsMap])
  const [selectedArtifact, setSelectedArtifact] = useState<string | null>(null)
  
  const getFileIcon = (type: string) => {
    switch (type) {
      case 'credentials': return Key
      case 'config': return FileText
      case 'database': return Database
      case 'key': return Shield
      case 'document': return File
      default: return FileArchive
    }
  }
  
  const getFileColor = (type: string) => {
    switch (type) {
      case 'credentials': return 'text-yellow-400'
      case 'config': return 'text-blue-400'
      case 'database': return 'text-purple-400'
      case 'key': return 'text-red-400'
      case 'document': return 'text-cyan-400'
      default: return 'text-zinc-400'
    }
  }
  
  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
  
  const selectedItem = artifacts.find(a => a.id === selectedArtifact)
  
  if (artifacts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <FileArchive className="h-12 w-12 text-text-muted-dark mb-4" />
        <h3 className="text-lg font-medium text-text-secondary-dark mb-2">
          No Artifacts Extracted
        </h3>
        <p className="text-sm text-text-muted-dark max-w-md">
          Files extracted during post-exploitation will appear here.
        </p>
      </div>
    )
  }
  
  return (
    <div className="flex h-full gap-4">
      {/* File List */}
      <div className="w-80 flex-shrink-0 space-y-2 overflow-y-auto pr-2 scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-transparent">
        {/* Group by target */}
        {Object.entries(
          artifacts.reduce((acc, a) => {
            if (!acc[a.target_id]) acc[a.target_id] = []
            acc[a.target_id].push(a)
            return acc
          }, {} as Record<string, typeof artifacts>)
        ).map(([targetId, targetArtifacts]) => (
          <div key={targetId}>
            <div className="flex items-center gap-2 mb-2 px-2">
              <Server className="h-3.5 w-3.5 text-text-muted-dark" />
              <span className="text-xs font-mono text-text-muted-dark truncate">
                {targetId.slice(0, 12)}...
              </span>
            </div>
            
            <div className="space-y-1">
              {targetArtifacts.map((artifact) => {
                const Icon = getFileIcon(artifact.file_type)
                const isSelected = selectedArtifact === artifact.id
                
                return (
                  <button
                    key={artifact.id}
                    onClick={() => setSelectedArtifact(artifact.id)}
                    className={cn(
                      'w-full p-3 rounded-xl border text-left transition-all',
                      isSelected
                        ? 'border-royal-blue bg-royal-blue/10 ring-1 ring-royal-blue/50'
                        : 'border-zinc-800 bg-zinc-900/50 hover:border-zinc-700'
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <div className={cn(
                        'p-2 rounded-lg',
                        isSelected ? 'bg-royal-blue/20' : 'bg-zinc-800'
                      )}>
                        <Icon className={cn('h-4 w-4', getFileColor(artifact.file_type))} />
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-text-primary-dark truncate">
                          {artifact.file_name}
                        </p>
                        <p className="text-xs text-text-muted-dark">
                          {formatSize(artifact.size_bytes)}
                        </p>
                      </div>
                      
                      {isSelected && (
                        <ChevronRight className="h-4 w-4 text-royal-blue" />
                      )}
                    </div>
                  </button>
                )
              })}
            </div>
          </div>
        ))}
      </div>
      
      {/* Preview Panel */}
      <div className="flex-1 rounded-xl border border-zinc-800 bg-zinc-900/30 overflow-hidden">
        {selectedItem ? (
          <div className="h-full flex flex-col">
            {/* Header */}
            <div className="p-4 border-b border-zinc-800">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {React.createElement(getFileIcon(selectedItem.file_type), {
                    className: cn('h-5 w-5', getFileColor(selectedItem.file_type))
                  })}
                  <div>
                    <h3 className="text-base font-semibold text-text-primary-dark">
                      {selectedItem.file_name}
                    </h3>
                    <p className="text-xs text-text-muted-dark font-mono">
                      {selectedItem.file_path}
                    </p>
                  </div>
                </div>
                
                <button className="p-2 rounded-lg hover:bg-zinc-800 text-text-muted-dark hover:text-text-secondary-dark transition-colors">
                  <Download className="h-4 w-4" />
                </button>
              </div>
            </div>
            
            {/* Meta */}
            <div className="px-4 py-2 border-b border-zinc-800 bg-zinc-800/30">
              <div className="flex items-center gap-4 text-xs text-text-muted-dark">
                <span className="flex items-center gap-1.5">
                  <Clock className="h-3 w-3" />
                  {new Date(selectedItem.extracted_at).toLocaleString()}
                </span>
                <span>{formatSize(selectedItem.size_bytes)}</span>
                <span className="uppercase">{selectedItem.file_type}</span>
              </div>
            </div>
            
            {/* Content Preview */}
            <div className="flex-1 overflow-y-auto p-4">
              {selectedItem.content_preview ? (
                <pre className="text-xs font-mono text-text-secondary-dark whitespace-pre-wrap">
                  {selectedItem.content_preview}
                </pre>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-center">
                  <Eye className="h-8 w-8 text-text-muted-dark mb-3" />
                  <p className="text-sm text-text-muted-dark">
                    Preview not available for this file type
                  </p>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <Folder className="h-12 w-12 text-text-muted-dark mb-4" />
            <p className="text-sm text-text-muted-dark">
              Select an artifact to preview
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Stats Summary Component
// ═══════════════════════════════════════════════════════════════

function LootStats() {
  // Use useShallow to prevent infinite loops with Map.values()
  const { sessionsMap, credentialsMap, artifactsMap } = useMissionStore(
    useShallow((state) => ({
      sessionsMap: state.activeSessions,
      credentialsMap: state.credentials,
      artifactsMap: state.artifacts,
    }))
  )
  
  // Convert Maps to arrays with useMemo for stability
  const sessions = useMemo(() => Array.from(sessionsMap.values()), [sessionsMap])
  const credentials = useMemo(() => Array.from(credentialsMap.values()), [credentialsMap])
  const artifacts = useMemo(() => Array.from(artifactsMap.values()), [artifactsMap])
  
  const verifiedCreds = useMemo(() => 
    credentials.filter(c => c.validation_status === 'verified'),
    [credentials]
  )
  const privilegedCreds = useMemo(() => 
    credentials.filter(c => 
      ['root', 'admin', 'system'].includes(c.privilege_level.toLowerCase())
    ),
    [credentials]
  )
  const activeSessions = useMemo(() => 
    sessions.filter(s => s.status === 'active'),
    [sessions]
  )
  
  return (
    <div className="grid grid-cols-5 gap-3 mb-6">
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Terminal className="h-4 w-4 text-green-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Sessions</span>
        </div>
        <div className="flex items-baseline gap-1">
          <span className="text-2xl font-bold text-green-400">{activeSessions.length}</span>
          <span className="text-xs text-text-muted-dark">/ {sessions.length}</span>
        </div>
      </div>
      
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Key className="h-4 w-4 text-yellow-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Credentials</span>
        </div>
        <span className="text-2xl font-bold text-yellow-400">{credentials.length}</span>
      </div>
      
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Shield className="h-4 w-4 text-orange-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Privileged</span>
        </div>
        <span className="text-2xl font-bold text-orange-400">{privilegedCreds.length}</span>
      </div>
      
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Eye className="h-4 w-4 text-cyan-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Verified</span>
        </div>
        <span className="text-2xl font-bold text-cyan-400">{verifiedCreds.length}</span>
      </div>
      
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <FileArchive className="h-4 w-4 text-purple-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Artifacts</span>
        </div>
        <span className="text-2xl font-bold text-purple-400">{artifacts.length}</span>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Loot View Component
// ═══════════════════════════════════════════════════════════════

export interface LootViewProps {
  onKillSession?: (sessionId: string) => void
  onExecuteCommand?: (sessionId: string, command: string) => void
  onTestCredential?: (credId: string) => void
}

export function LootView({ onKillSession, onExecuteCommand, onTestCredential }: LootViewProps) {
  // Use useShallow to prevent infinite loops with Map.values()
  const { sessionsMap, credentialsMap, artifactsMap } = useMissionStore(
    useShallow((state) => ({
      sessionsMap: state.activeSessions,
      credentialsMap: state.credentials,
      artifactsMap: state.artifacts,
    }))
  )
  
  // Convert Maps to arrays with useMemo for stability
  const sessions = useMemo(() => Array.from(sessionsMap.values()), [sessionsMap])
  const credentials = useMemo(() => Array.from(credentialsMap.values()), [credentialsMap])
  const artifacts = useMemo(() => Array.from(artifactsMap.values()), [artifactsMap])
  
  const [activeTab, setActiveTab] = useState<LootTab>('sessions')
  
  const tabs: TabConfig[] = useMemo(() => [
    { id: 'sessions', label: 'Sessions', icon: Terminal, badge: sessions.filter(s => s.status === 'active').length || undefined },
    { id: 'credentials', label: 'Credentials', icon: Key, badge: credentials.length || undefined },
    { id: 'artifacts', label: 'Artifacts', icon: FileArchive, badge: artifacts.length || undefined },
  ], [sessions, credentials, artifacts])
  
  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-bold text-text-primary-dark mb-1">
          Loot & Access
        </h1>
        <p className="text-sm text-text-muted-dark">
          Active sessions, harvested credentials, and extracted artifacts
        </p>
      </div>
      
      {/* Stats Summary */}
      <LootStats />
      
      {/* Tab Navigation */}
      <div className="flex items-center gap-1 p-1 rounded-xl bg-zinc-800/50 border border-zinc-700 mb-6 w-fit">
        {tabs.map((tab) => {
          const Icon = tab.icon
          const isActive = activeTab === tab.id
          
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all',
                isActive
                  ? 'bg-zinc-700 text-text-primary-dark'
                  : 'text-text-muted-dark hover:text-text-secondary-dark'
              )}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
              {tab.badge !== undefined && tab.badge > 0 && (
                <span className={cn(
                  'px-1.5 py-0.5 rounded-full text-[10px] font-semibold',
                  isActive
                    ? 'bg-royal-blue text-white'
                    : 'bg-zinc-600 text-zinc-300'
                )}>
                  {tab.badge}
                </span>
              )}
            </button>
          )
        })}
      </div>
      
      {/* Tab Content */}
      <div className="flex-1 overflow-hidden">
        {activeTab === 'sessions' && (
          <SessionManager
            sessions={sessions}
            onKillSession={onKillSession}
            onCommand={onExecuteCommand}
          />
        )}
        
        {activeTab === 'credentials' && (
          <CredentialVault
            onTestCredential={onTestCredential}
            showStats={false}
          />
        )}
        
        {activeTab === 'artifacts' && (
          <ArtifactsGallery />
        )}
      </div>
    </div>
  )
}

export default LootView
