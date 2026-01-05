// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Target Details Drawer (Identity Card Style)
// Large identity card with OS logo and status stamp
// Inspired by Manus.im / Modern Agentic Design
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Server,
  Monitor,
  Globe,
  Shield,
  Bug,
  Terminal,
  RefreshCw,
  Crosshair,
  X,
  ShieldAlert,
  Laptop,
  HardDrive,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/Button'
import { useEventStore } from '@/stores/eventStore'
import type { Vulnerability, Session } from '@/types'

// OS Icons mapping
const osIcons: Record<string, React.ElementType> = {
  windows: Monitor,
  linux: Terminal,
  macos: Laptop,
  unknown: Server,
}

// OS detection helper function
function detectOsType(os: string | undefined): string {
  if (!os) return 'unknown'
  const osLower = os.toLowerCase()
  if (/win|windows|win10|win11|win7/i.test(osLower)) return 'windows'
  if (/linux|ubuntu|debian|centos|redhat|fedora|arch/i.test(osLower)) return 'linux'
  if (/mac|darwin|macos|osx/i.test(osLower)) return 'macos'
  return 'unknown'
}

export function TargetDetailsDrawer() {
  const selectedTargetId = useEventStore((state) => state.selectedTargetId)
  const targets = useEventStore((state) => state.targets)
  const vulnerabilities = useEventStore((state) => state.vulnerabilities)
  const sessions = useEventStore((state) => state.sessions)
  const setSelectedTarget = useEventStore((state) => state.setSelectedTarget)
  const addToast = useEventStore((state) => state.addToast)
  
  const selectedTarget = React.useMemo(() => 
    selectedTargetId ? targets.get(selectedTargetId) : null
  , [selectedTargetId, targets])
  
  const targetVulns = React.useMemo(() => {
    if (!selectedTargetId) return []
    return Array.from(vulnerabilities.values()).filter(
      (v) => v.target_id === selectedTargetId
    )
  }, [selectedTargetId, vulnerabilities])
  
  const targetSessions = React.useMemo(() => {
    if (!selectedTargetId) return []
    return Array.from(sessions.values()).filter(
      (s) => s.target_id === selectedTargetId
    )
  }, [selectedTargetId, sessions])
  
  const handleClose = () => setSelectedTarget(null)
  
  const handleScanAgain = async () => {
    addToast({
      type: 'info',
      title: 'Scan Initiated',
      description: `Starting scan for ${selectedTarget?.ip}`,
    })
  }
  
  const handleExploit = async () => {
    if (targetVulns.length === 0) {
      addToast({
        type: 'warning',
        title: 'No Vulnerabilities',
        description: 'No exploitable vulnerabilities found on this target.',
      })
      return
    }
    
    addToast({
      type: 'info',
      title: 'Exploit Queued',
      description: 'Exploitation attempt has been queued.',
    })
  }
  
  if (!selectedTarget) return null
  
  // Determine OS icon using helper function
  const osType = detectOsType(selectedTarget.os)
  const OsIcon = osIcons[osType]
  
  const isCompromised = selectedTarget.status === 'exploited' || selectedTarget.status === 'owned'
  
  return (
    <>
      {/* Backdrop */}
      <div 
        className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm animate-fade-in"
        onClick={handleClose}
      />
      
      {/* Drawer */}
      <div className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-md glass border-l border-white/5 shadow-2xl animate-slide-in-right overflow-y-auto">
        {/* Close Button */}
        <button
          onClick={handleClose}
          className="absolute top-4 right-4 p-2 rounded-xl hover:bg-white/5 transition-colors"
        >
          <X className="h-5 w-5 text-text-muted-dark" />
        </button>
        
        {/* Identity Card Header */}
        <div className="p-6 pt-12">
          <div className="flex items-start gap-4">
            {/* Large OS Icon */}
            <div className={cn(
              'p-4 rounded-2xl',
              isCompromised ? 'bg-red-50' : 'bg-blue-50'
            )}>
              <OsIcon className={cn(
                'h-10 w-10',
                isCompromised ? 'text-critical' : 'text-royal-blue'
              )} />
            </div>
            
            <div className="flex-1 min-w-0">
              {/* Big IP Address */}
              <h2 className="text-2xl font-semibold text-text-primary-dark font-mono">
                {selectedTarget.ip}
              </h2>
              <p className="text-sm text-text-muted-dark mt-1">
                {selectedTarget.hostname || 'Unknown hostname'}
              </p>
              
              {/* Status Badges */}
              <div className="flex items-center gap-2 mt-3">
                {isCompromised && (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-red-50 text-red-700 text-xs font-medium">
                    <ShieldAlert className="h-3 w-3" />
                    COMPROMISED
                  </span>
                )}
                <span className={cn(
                  'px-2.5 py-1 rounded-lg text-xs font-medium',
                  selectedTarget.priority === 'critical' ? 'bg-red-50 text-red-700' :
                  selectedTarget.priority === 'high' ? 'bg-amber-50 text-amber-700' :
                  'bg-slate-100 text-slate-600'
                )}>
                  {selectedTarget.priority || 'medium'} priority
                </span>
              </div>
            </div>
          </div>
        </div>
        
        {/* Divider */}
        <div className="h-px bg-white/5 mx-6" />
        
        {/* System Info - Compact */}
        <div className="p-6">
          <h3 className="text-xs font-medium text-text-muted-dark uppercase tracking-wide mb-3">
            System Information
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <InfoItem icon={HardDrive} label="OS" value={selectedTarget.os || 'Unknown'} />
            <InfoItem icon={Shield} label="Status" value={selectedTarget.status} />
            <InfoItem icon={Globe} label="Ports" value={`${Object.keys(selectedTarget.ports).length} open`} />
            <InfoItem icon={Bug} label="Vulns" value={`${targetVulns.length} found`} />
          </div>
        </div>
        
        {/* Open Ports - Compact Table */}
        {Object.keys(selectedTarget.ports).length > 0 && (
          <div className="px-6 pb-6">
            <h3 className="text-xs font-medium text-text-muted-dark uppercase tracking-wide mb-3">
              Open Ports
            </h3>
            <div className="space-y-1">
              {Object.entries(selectedTarget.ports).slice(0, 6).map(([port, service]) => (
                <div
                  key={port}
                  className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-white/5 transition-colors"
                >
                  <span className="font-mono text-sm text-royal-blue">{port}</span>
                  <span className="text-xs text-text-muted-dark">{service}</span>
                </div>
              ))}
              {Object.keys(selectedTarget.ports).length > 6 && (
                <p className="text-xs text-text-muted-dark text-center py-2">
                  +{Object.keys(selectedTarget.ports).length - 6} more ports
                </p>
              )}
            </div>
          </div>
        )}
        
        {/* Vulnerabilities - Minimal List */}
        {targetVulns.length > 0 && (
          <div className="px-6 pb-6">
            <h3 className="text-xs font-medium text-text-muted-dark uppercase tracking-wide mb-3">
              Vulnerabilities
            </h3>
            <div className="space-y-2">
              {targetVulns.slice(0, 4).map((vuln) => (
                <VulnItem key={vuln.vuln_id} vuln={vuln} />
              ))}
              {targetVulns.length > 4 && (
                <p className="text-xs text-text-muted-dark text-center py-2">
                  +{targetVulns.length - 4} more vulnerabilities
                </p>
              )}
            </div>
          </div>
        )}
        
        {/* Sessions */}
        {targetSessions.length > 0 && (
          <div className="px-6 pb-6">
            <h3 className="text-xs font-medium text-text-muted-dark uppercase tracking-wide mb-3">
              Active Sessions
            </h3>
            <div className="space-y-2">
              {targetSessions.map((session) => (
                <SessionItem key={session.session_id} session={session} />
              ))}
            </div>
          </div>
        )}
        
        {/* Action Buttons - Sticky Bottom */}
        <div className="sticky bottom-0 p-6 pt-4 bg-gradient-to-t from-bg-dark via-bg-dark to-transparent">
          <div className="flex gap-3">
            <Button 
              variant="ghost" 
              className="flex-1 gap-2 rounded-xl hover:bg-white/5" 
              onClick={handleScanAgain}
            >
              <RefreshCw className="h-4 w-4" />
              Scan Again
            </Button>
            <Button
              className={cn(
                'flex-1 gap-2 rounded-xl',
                targetVulns.length === 0 && 'opacity-50'
              )}
              onClick={handleExploit}
              disabled={targetVulns.length === 0}
            >
              <Crosshair className="h-4 w-4" />
              Exploit
            </Button>
          </div>
        </div>
      </div>
    </>
  )
}

// Info Item Component
function InfoItem({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ElementType
  label: string
  value: string
}) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="h-4 w-4 text-text-muted-dark/50" />
      <div>
        <p className="text-[10px] text-text-muted-dark uppercase">{label}</p>
        <p className="text-sm text-text-primary-dark">{value}</p>
      </div>
    </div>
  )
}

// Vulnerability Item Component
function VulnItem({ vuln }: { vuln: Vulnerability }) {
  return (
    <div className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-white/5 transition-colors">
      <div className="flex-1 min-w-0">
        <p className="text-sm text-text-primary-dark truncate">{vuln.type}</p>
        {vuln.name && (
          <p className="text-xs text-text-muted-dark truncate">{vuln.name}</p>
        )}
      </div>
      <div className="flex items-center gap-2 flex-shrink-0 ml-2">
        {vuln.cvss && (
          <span className="text-[10px] font-mono text-text-muted-dark">
            {vuln.cvss.toFixed(1)}
          </span>
        )}
        <span className={cn(
          'px-1.5 py-0.5 rounded text-[10px] font-medium',
          vuln.severity === 'critical' ? 'bg-red-50 text-red-700' :
          vuln.severity === 'high' ? 'bg-amber-50 text-amber-700' :
          'bg-slate-100 text-slate-600'
        )}>
          {vuln.severity}
        </span>
      </div>
    </div>
  )
}

// Session Item Component
function SessionItem({ session }: { session: Session }) {
  return (
    <div className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-white/5 transition-colors">
      <div className="flex items-center gap-2">
        <Terminal className="h-4 w-4 text-success" />
        <div>
          <p className="text-sm text-text-primary-dark">{session.type}</p>
          {session.user && (
            <p className="text-xs text-text-muted-dark">{session.user}</p>
          )}
        </div>
      </div>
      <span className={cn(
        'px-1.5 py-0.5 rounded text-[10px] font-medium',
        session.status === 'active' ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-600'
      )}>
        {session.privilege}
      </span>
    </div>
  )
}
