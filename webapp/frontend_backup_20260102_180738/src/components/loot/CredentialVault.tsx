// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Credential Vault Component
// Secure credential management for Loot & Access workspace
// Design: Palantir-inspired, professional data table with validation
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  Key,
  Eye,
  EyeOff,
  Copy,
  Check,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
  Database,
  User,
  Server,
  Shield,
  ChevronDown,
  ChevronUp,
  Search,
  FileText,
  RefreshCw,
  Lock,
  Hash,
  Crown,
  UserCog,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useMissionStore, selectCredentials, type EnhancedCredential } from '@/stores/missionStore'

// ═══════════════════════════════════════════════════════════════
// Validation Status Configuration
// ═══════════════════════════════════════════════════════════════

interface ValidationStatusConfig {
  icon: React.ElementType
  color: string
  bgColor: string
  label: string
}

const validationStatusConfig: Record<EnhancedCredential['validation_status'], ValidationStatusConfig> = {
  verified: { icon: CheckCircle2, color: 'text-green-400', bgColor: 'bg-green-500/10', label: 'Verified' },
  unverified: { icon: AlertCircle, color: 'text-yellow-400', bgColor: 'bg-yellow-500/10', label: 'Unverified' },
  invalid: { icon: XCircle, color: 'text-red-400', bgColor: 'bg-red-500/10', label: 'Invalid' },
  testing: { icon: Loader2, color: 'text-blue-400', bgColor: 'bg-blue-500/10', label: 'Testing' },
}

// ═══════════════════════════════════════════════════════════════
// Credential Type Configuration
// ═══════════════════════════════════════════════════════════════

interface CredTypeConfig {
  icon: React.ElementType
  color: string
  label: string
}

const credTypeConfig: Record<string, CredTypeConfig> = {
  password: { icon: Lock, color: 'text-blue-400', label: 'Password' },
  ssh_key: { icon: Key, color: 'text-purple-400', label: 'SSH Key' },
  api_key: { icon: Hash, color: 'text-cyan-400', label: 'API Key' },
  token: { icon: Shield, color: 'text-green-400', label: 'Token' },
  ntlm: { icon: Database, color: 'text-orange-400', label: 'NTLM Hash' },
  kerberos: { icon: Crown, color: 'text-yellow-400', label: 'Kerberos' },
  certificate: { icon: FileText, color: 'text-pink-400', label: 'Certificate' },
  other: { icon: Key, color: 'text-zinc-400', label: 'Other' },
}

const getCredTypeConfig = (type: string): CredTypeConfig => {
  return credTypeConfig[type.toLowerCase()] || credTypeConfig.other
}

// ═══════════════════════════════════════════════════════════════
// Privilege Level Configuration
// ═══════════════════════════════════════════════════════════════

const privilegeConfig: Record<string, { color: string; icon: React.ElementType }> = {
  root: { color: 'text-red-400', icon: Crown },
  admin: { color: 'text-orange-400', icon: UserCog },
  system: { color: 'text-red-400', icon: Crown },
  user: { color: 'text-blue-400', icon: User },
  guest: { color: 'text-zinc-400', icon: User },
  service: { color: 'text-purple-400', icon: Server },
  unknown: { color: 'text-zinc-500', icon: User },
}

const getPrivilegeConfig = (level: string) => {
  return privilegeConfig[level.toLowerCase()] || privilegeConfig.unknown
}

// ═══════════════════════════════════════════════════════════════
// Validation Status Badge
// ═══════════════════════════════════════════════════════════════

function ValidationBadge({ status }: { status: EnhancedCredential['validation_status'] }) {
  const config = validationStatusConfig[status]
  const Icon = config.icon
  
  return (
    <span className={cn(
      'inline-flex items-center gap-1.5 px-2 py-1 rounded-lg text-[10px] font-semibold uppercase tracking-wider',
      config.bgColor, config.color
    )}>
      <Icon className={cn('h-3 w-3', status === 'testing' && 'animate-spin')} />
      {config.label}
    </span>
  )
}

// ═══════════════════════════════════════════════════════════════
// Password Display Component
// ═══════════════════════════════════════════════════════════════

interface PasswordDisplayProps {
  password?: string
  passwordHash?: string
  credId: string
}

function PasswordDisplay({ password, passwordHash }: PasswordDisplayProps) {
  const [visible, setVisible] = React.useState(false)
  const [copied, setCopied] = React.useState(false)
  
  const value = password || passwordHash || '••••••••'
  const maskedValue = password ? '•'.repeat(Math.min(password.length, 12)) : (passwordHash ? `${passwordHash.slice(0, 8)}...` : '••••••••')
  
  const handleCopy = async () => {
    if (password) {
      await navigator.clipboard.writeText(password)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }
  
  return (
    <div className="flex items-center gap-2">
      <code className={cn(
        'flex-1 px-2 py-1 rounded bg-zinc-800/80 border border-zinc-700 text-xs font-mono truncate',
        visible ? 'text-text-primary-dark' : 'text-text-muted-dark'
      )}>
        {visible ? value : maskedValue}
      </code>
      
      <button
        onClick={() => setVisible(!visible)}
        className="p-1.5 rounded hover:bg-zinc-700 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
        title={visible ? 'Hide' : 'Reveal'}
      >
        {visible ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
      </button>
      
      {password && (
        <button
          onClick={handleCopy}
          className="p-1.5 rounded hover:bg-zinc-700 text-text-muted-dark hover:text-text-secondary-dark transition-colors"
          title="Copy"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
      )}
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Credential Row Component
// ═══════════════════════════════════════════════════════════════

interface CredentialRowProps {
  credential: EnhancedCredential
  isExpanded: boolean
  onToggle: () => void
  onTest: () => void
}

function CredentialRow({ credential, isExpanded, onToggle, onTest }: CredentialRowProps) {
  const typeConfig = getCredTypeConfig(credential.type)
  const TypeIcon = typeConfig.icon
  const privConfig = getPrivilegeConfig(credential.privilege_level)
  const PrivIcon = privConfig.icon
  
  return (
    <>
      {/* Main Row */}
      <tr 
        className={cn(
          'group hover:bg-zinc-800/50 transition-colors cursor-pointer',
          isExpanded && 'bg-zinc-800/30'
        )}
        onClick={onToggle}
      >
        {/* Type */}
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="flex items-center gap-2">
            <div className={cn('p-1.5 rounded-lg bg-zinc-800/80 border border-zinc-700')}>
              <TypeIcon className={cn('h-4 w-4', typeConfig.color)} />
            </div>
            <span className="text-xs font-medium text-text-secondary-dark">
              {typeConfig.label}
            </span>
          </div>
        </td>
        
        {/* Username */}
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="flex items-center gap-2">
            <User className="h-3.5 w-3.5 text-text-muted-dark" />
            <span className="text-sm font-mono text-text-primary-dark">
              {credential.username || 'N/A'}
            </span>
            {credential.domain && (
              <span className="text-xs text-text-muted-dark">
                @{credential.domain}
              </span>
            )}
          </div>
        </td>
        
        {/* Password/Hash (Masked) */}
        <td className="px-4 py-3">
          <PasswordDisplay
            password={credential.password}
            passwordHash={credential.password_hash}
            credId={credential.cred_id}
          />
        </td>
        
        {/* Source */}
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="flex items-center gap-1.5">
            <FileText className="h-3.5 w-3.5 text-text-muted-dark" />
            <span className="text-xs text-text-secondary-dark font-mono truncate max-w-[120px]">
              {credential.source || credential.source_file || 'Unknown'}
            </span>
          </div>
        </td>
        
        {/* Privilege Level */}
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="flex items-center gap-1.5">
            <PrivIcon className={cn('h-3.5 w-3.5', privConfig.color)} />
            <span className={cn('text-xs font-semibold uppercase', privConfig.color)}>
              {credential.privilege_level}
            </span>
          </div>
        </td>
        
        {/* Validation Status */}
        <td className="px-4 py-3 whitespace-nowrap">
          <ValidationBadge status={credential.validation_status} />
        </td>
        
        {/* Actions */}
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              onClick={(e) => { e.stopPropagation(); onTest(); }}
              className={cn(
                'p-1.5 rounded hover:bg-zinc-700 text-text-muted-dark hover:text-blue-400 transition-colors',
                credential.validation_status === 'testing' && 'animate-pulse'
              )}
              title="Test Credential"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
            {isExpanded ? (
              <ChevronUp className="h-4 w-4 text-text-muted-dark" />
            ) : (
              <ChevronDown className="h-4 w-4 text-text-muted-dark" />
            )}
          </div>
        </td>
      </tr>
      
      {/* Expanded Details */}
      {isExpanded && (
        <tr>
          <td colSpan={7} className="px-4 py-3 bg-zinc-900/50">
            <div className="grid grid-cols-3 gap-4 p-3 rounded-lg bg-zinc-800/50 border border-zinc-700">
              <div>
                <span className="text-[10px] text-text-muted-dark uppercase tracking-wider block mb-1">
                  Credential ID
                </span>
                <code className="text-xs text-text-secondary-dark font-mono">
                  {credential.cred_id}
                </code>
              </div>
              <div>
                <span className="text-[10px] text-text-muted-dark uppercase tracking-wider block mb-1">
                  Target ID
                </span>
                <code className="text-xs text-text-secondary-dark font-mono">
                  {credential.target_id}
                </code>
              </div>
              <div>
                <span className="text-[10px] text-text-muted-dark uppercase tracking-wider block mb-1">
                  Last Tested
                </span>
                <span className="text-xs text-text-secondary-dark">
                  {credential.last_tested 
                    ? new Date(credential.last_tested).toLocaleString() 
                    : 'Never'}
                </span>
              </div>
              {credential.impact_assessment && (
                <div className="col-span-3">
                  <span className="text-[10px] text-text-muted-dark uppercase tracking-wider block mb-1">
                    Impact Assessment
                  </span>
                  <p className="text-xs text-text-secondary-dark">
                    {credential.impact_assessment}
                  </p>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ═══════════════════════════════════════════════════════════════
// Stats Summary Component
// ═══════════════════════════════════════════════════════════════

interface StatsSummaryProps {
  credentials: EnhancedCredential[]
}

function StatsSummary({ credentials }: StatsSummaryProps) {
  const stats = React.useMemo(() => {
    const verified = credentials.filter(c => c.validation_status === 'verified').length
    const privileged = credentials.filter(c => 
      ['root', 'admin', 'system'].includes(c.privilege_level.toLowerCase())
    ).length
    const byType = credentials.reduce((acc, c) => {
      const type = c.type.toLowerCase()
      acc[type] = (acc[type] || 0) + 1
      return acc
    }, {} as Record<string, number>)
    
    return { total: credentials.length, verified, privileged, byType }
  }, [credentials])
  
  return (
    <div className="grid grid-cols-4 gap-3 mb-6">
      {/* Total */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Key className="h-4 w-4 text-blue-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Total</span>
        </div>
        <span className="text-2xl font-bold text-text-primary-dark">{stats.total}</span>
      </div>
      
      {/* Verified */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <CheckCircle2 className="h-4 w-4 text-green-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Verified</span>
        </div>
        <span className="text-2xl font-bold text-green-400">{stats.verified}</span>
      </div>
      
      {/* Privileged */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Crown className="h-4 w-4 text-orange-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Privileged</span>
        </div>
        <span className="text-2xl font-bold text-orange-400">{stats.privileged}</span>
      </div>
      
      {/* Type Distribution */}
      <div className="p-3 rounded-xl bg-zinc-900/50 border border-zinc-800">
        <div className="flex items-center gap-2 mb-1">
          <Database className="h-4 w-4 text-purple-400" />
          <span className="text-[10px] text-text-muted-dark uppercase tracking-wider">Types</span>
        </div>
        <div className="flex flex-wrap gap-1">
          {Object.entries(stats.byType).slice(0, 3).map(([type, count]) => (
            <span key={type} className="text-[10px] text-text-muted-dark bg-zinc-800 px-1.5 py-0.5 rounded">
              {type}: {count}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Filter Bar Component
// ═══════════════════════════════════════════════════════════════

interface FilterBarProps {
  searchTerm: string
  onSearchChange: (term: string) => void
  filterType: string | null
  onFilterTypeChange: (type: string | null) => void
  filterStatus: EnhancedCredential['validation_status'] | null
  onFilterStatusChange: (status: EnhancedCredential['validation_status'] | null) => void
}

function FilterBar({
  searchTerm,
  onSearchChange,
  filterType,
  onFilterTypeChange,
  filterStatus,
  onFilterStatusChange,
}: FilterBarProps) {
  return (
    <div className="flex items-center gap-3 mb-4">
      {/* Search */}
      <div className="flex-1 relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted-dark" />
        <input
          type="text"
          placeholder="Search by username, domain, source..."
          value={searchTerm}
          onChange={(e) => onSearchChange(e.target.value)}
          className={cn(
            'w-full pl-10 pr-4 py-2 rounded-lg text-sm',
            'bg-zinc-800 border border-zinc-700 text-text-primary-dark',
            'placeholder:text-text-muted-dark',
            'focus:outline-none focus:border-royal-blue focus:ring-1 focus:ring-royal-blue/50'
          )}
        />
      </div>
      
      {/* Type Filter */}
      <select
        value={filterType || ''}
        onChange={(e) => onFilterTypeChange(e.target.value || null)}
        className={cn(
          'px-3 py-2 rounded-lg text-sm appearance-none',
          'bg-zinc-800 border border-zinc-700 text-text-secondary-dark',
          'focus:outline-none focus:border-royal-blue'
        )}
      >
        <option value="">All Types</option>
        {Object.keys(credTypeConfig).map(type => (
          <option key={type} value={type}>
            {credTypeConfig[type].label}
          </option>
        ))}
      </select>
      
      {/* Status Filter */}
      <select
        value={filterStatus || ''}
        onChange={(e) => onFilterStatusChange(e.target.value as EnhancedCredential['validation_status'] || null)}
        className={cn(
          'px-3 py-2 rounded-lg text-sm appearance-none',
          'bg-zinc-800 border border-zinc-700 text-text-secondary-dark',
          'focus:outline-none focus:border-royal-blue'
        )}
      >
        <option value="">All Status</option>
        {Object.keys(validationStatusConfig).map(status => (
          <option key={status} value={status}>
            {validationStatusConfig[status as EnhancedCredential['validation_status']].label}
          </option>
        ))}
      </select>
    </div>
  )
}

// ═══════════════════════════════════════════════════════════════
// Main Credential Vault Component
// ═══════════════════════════════════════════════════════════════

export interface CredentialVaultProps {
  onTestCredential?: (credId: string) => void
  showStats?: boolean
}

export function CredentialVault({ onTestCredential, showStats = true }: CredentialVaultProps) {
  const credentials = useMissionStore(selectCredentials)
  const updateCredentialStatus = useMissionStore(s => s.updateCredentialStatus)
  
  const [expandedCreds, setExpandedCreds] = React.useState<Set<string>>(new Set())
  const [searchTerm, setSearchTerm] = React.useState('')
  const [filterType, setFilterType] = React.useState<string | null>(null)
  const [filterStatus, setFilterStatus] = React.useState<EnhancedCredential['validation_status'] | null>(null)
  
  // Filter credentials
  const filteredCredentials = React.useMemo(() => {
    return credentials.filter(cred => {
      // Search filter
      if (searchTerm) {
        const term = searchTerm.toLowerCase()
        const matchesSearch = 
          cred.username?.toLowerCase().includes(term) ||
          cred.domain?.toLowerCase().includes(term) ||
          cred.source?.toLowerCase().includes(term) ||
          cred.source_file?.toLowerCase().includes(term)
        if (!matchesSearch) return false
      }
      
      // Type filter
      if (filterType && cred.type.toLowerCase() !== filterType.toLowerCase()) {
        return false
      }
      
      // Status filter
      if (filterStatus && cred.validation_status !== filterStatus) {
        return false
      }
      
      return true
    })
  }, [credentials, searchTerm, filterType, filterStatus])
  
  const toggleExpanded = (credId: string) => {
    setExpandedCreds(prev => {
      const next = new Set(prev)
      if (next.has(credId)) {
        next.delete(credId)
      } else {
        next.add(credId)
      }
      return next
    })
  }
  
  const handleTest = (credId: string) => {
    // Set to testing status
    updateCredentialStatus(credId, 'testing')
    
    // Call external handler
    onTestCredential?.(credId)
    
    // Simulate test completion after delay (in real app, this would be via WebSocket)
    setTimeout(() => {
      updateCredentialStatus(credId, Math.random() > 0.3 ? 'verified' : 'invalid')
    }, 2000)
  }
  
  if (credentials.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Lock className="h-12 w-12 text-text-muted-dark mb-4" />
        <h3 className="text-lg font-medium text-text-secondary-dark mb-2">
          No Credentials Harvested
        </h3>
        <p className="text-sm text-text-muted-dark max-w-md">
          Credentials discovered during exploitation will appear here.
        </p>
      </div>
    )
  }
  
  return (
    <div className="flex flex-col h-full">
      {/* Stats Summary */}
      {showStats && <StatsSummary credentials={credentials} />}
      
      {/* Filter Bar */}
      <FilterBar
        searchTerm={searchTerm}
        onSearchChange={setSearchTerm}
        filterType={filterType}
        onFilterTypeChange={setFilterType}
        filterStatus={filterStatus}
        onFilterStatusChange={setFilterStatus}
      />
      
      {/* Results Count */}
      <div className="mb-3 text-xs text-text-muted-dark">
        Showing {filteredCredentials.length} of {credentials.length} credentials
      </div>
      
      {/* Credentials Table */}
      <div className="flex-1 overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900/30">
        <table className="w-full min-w-[800px]">
          <thead>
            <tr className="border-b border-zinc-800">
              <th className="px-4 py-3 text-left text-[10px] font-semibold text-text-muted-dark uppercase tracking-wider">
                Type
              </th>
              <th className="px-4 py-3 text-left text-[10px] font-semibold text-text-muted-dark uppercase tracking-wider">
                Username
              </th>
              <th className="px-4 py-3 text-left text-[10px] font-semibold text-text-muted-dark uppercase tracking-wider">
                Password / Hash
              </th>
              <th className="px-4 py-3 text-left text-[10px] font-semibold text-text-muted-dark uppercase tracking-wider">
                Source
              </th>
              <th className="px-4 py-3 text-left text-[10px] font-semibold text-text-muted-dark uppercase tracking-wider">
                Privilege
              </th>
              <th className="px-4 py-3 text-left text-[10px] font-semibold text-text-muted-dark uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3 w-20"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/50">
            {filteredCredentials.map(cred => (
              <CredentialRow
                key={cred.cred_id}
                credential={cred}
                isExpanded={expandedCreds.has(cred.cred_id)}
                onToggle={() => toggleExpanded(cred.cred_id)}
                onTest={() => handleTest(cred.cred_id)}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default CredentialVault
