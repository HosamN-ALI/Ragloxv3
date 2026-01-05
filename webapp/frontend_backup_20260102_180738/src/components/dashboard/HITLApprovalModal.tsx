// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - HITL Approval Modal
// Modal for reviewing and approving/rejecting high-risk actions
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import {
  AlertTriangle,
  Terminal,
  Target,
  Clock,
  CheckCircle,
  XCircle,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { formatDateTime } from '@/lib/utils'
import { Modal, ModalFooter } from '@/components/ui/Modal'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Input } from '@/components/ui/Input'
import { useEventStore } from '@/stores/eventStore'
import type { ApprovalRequest, RiskLevel } from '@/types'

interface HITLApprovalModalProps {
  approval: ApprovalRequest | null
  onClose: () => void
}

export function HITLApprovalModal({ approval, onClose }: HITLApprovalModalProps) {
  const { removeApprovalRequest, addToast } = useEventStore()
  const [comment, setComment] = React.useState('')
  const [isLoading, setIsLoading] = React.useState(false)
  
  if (!approval) return null
  
  const handleApprove = async () => {
    setIsLoading(true)
    try {
      const response = await fetch(`/api/missions/approve/${approval.action_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_comment: comment || undefined }),
      })
      
      if (response.ok) {
        removeApprovalRequest(approval.action_id)
        addToast({
          type: 'success',
          title: 'Action Approved',
          description: 'The operation will proceed.',
        })
        onClose()
      } else {
        throw new Error('Failed to approve')
      }
    } catch {
      addToast({
        type: 'error',
        title: 'Approval Failed',
        description: 'Failed to approve the action. Please try again.',
      })
    } finally {
      setIsLoading(false)
    }
  }
  
  const handleReject = async () => {
    setIsLoading(true)
    try {
      const response = await fetch(`/api/missions/reject/${approval.action_id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rejection_reason: comment || 'User rejected',
          user_comment: comment || undefined,
        }),
      })
      
      if (response.ok) {
        removeApprovalRequest(approval.action_id)
        addToast({
          type: 'info',
          title: 'Action Rejected',
          description: 'The system will seek alternative approaches.',
        })
        onClose()
      } else {
        throw new Error('Failed to reject')
      }
    } catch {
      addToast({
        type: 'error',
        title: 'Rejection Failed',
        description: 'Failed to reject the action. Please try again.',
      })
    } finally {
      setIsLoading(false)
    }
  }
  
  const riskColors: Record<RiskLevel, string> = {
    low: 'border-success',
    medium: 'border-warning',
    high: 'border-orange-500',
    critical: 'border-critical',
  }
  
  const riskBadgeVariants: Record<RiskLevel, 'success' | 'warning' | 'critical' | 'secondary'> = {
    low: 'success',
    medium: 'warning',
    high: 'warning',
    critical: 'critical',
  }
  
  return (
    <Modal
      isOpen={!!approval}
      onClose={onClose}
      title="Action Requires Approval"
      className={cn('max-w-xl border-t-4', riskColors[approval.risk_level])}
    >
      {/* Risk Assessment Header */}
      <div className="flex items-center gap-3 p-4 rounded-lg bg-bg-elevated-dark mb-4">
        <div className={cn(
          'p-2 rounded-lg',
          approval.risk_level === 'critical' || approval.risk_level === 'high'
            ? 'bg-critical/10'
            : 'bg-warning/10'
        )}>
          <AlertTriangle className={cn(
            'h-6 w-6',
            approval.risk_level === 'critical' || approval.risk_level === 'high'
              ? 'text-critical'
              : 'text-warning'
          )} />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-semibold text-text-primary-dark">
              {approval.action_type.toUpperCase()}
            </span>
            <Badge variant={riskBadgeVariants[approval.risk_level]}>
              {approval.risk_level.toUpperCase()} RISK
            </Badge>
          </div>
          <p className="text-sm text-text-secondary-dark mt-1">
            {approval.action_description}
          </p>
        </div>
      </div>
      
      {/* Target Information */}
      {(approval.target_ip || approval.target_hostname) && (
        <div className="flex items-center gap-3 mb-4">
          <Target className="h-4 w-4 text-text-muted-dark" />
          <span className="text-sm text-text-secondary-dark">Target:</span>
          <span className="text-sm font-mono text-text-primary-dark">
            {approval.target_ip}
            {approval.target_hostname && ` (${approval.target_hostname})`}
          </span>
        </div>
      )}
      
      {/* Risk Reasons */}
      {approval.risk_reasons.length > 0 && (
        <div className="mb-4">
          <h4 className="text-sm font-medium text-text-secondary-dark mb-2">
            Risk Factors:
          </h4>
          <ul className="space-y-1">
            {approval.risk_reasons.map((reason, idx) => (
              <li key={idx} className="flex items-start gap-2 text-sm">
                <span className="text-warning">•</span>
                <span className="text-text-secondary-dark">{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      
      {/* Potential Impact */}
      {approval.potential_impact && (
        <div className="mb-4 p-3 rounded-lg bg-critical/5 border border-critical/20">
          <h4 className="text-sm font-medium text-critical mb-1">
            Potential Impact:
          </h4>
          <p className="text-sm text-text-secondary-dark">
            {approval.potential_impact}
          </p>
        </div>
      )}
      
      {/* Command Preview */}
      {approval.command_preview && (
        <div className="mb-4">
          <h4 className="text-sm font-medium text-text-secondary-dark mb-2">
            <Terminal className="h-4 w-4 inline mr-1" />
            Command Preview:
          </h4>
          <pre className="p-3 rounded-lg bg-bg-elevated-dark font-mono text-xs text-text-primary-dark overflow-x-auto">
            {approval.command_preview}
          </pre>
        </div>
      )}
      
      {/* Expiration */}
      {approval.expires_at && (
        <div className="flex items-center gap-2 text-sm text-text-muted-dark mb-4">
          <Clock className="h-4 w-4" />
          <span>Expires: {formatDateTime(approval.expires_at)}</span>
        </div>
      )}
      
      {/* Comment Input */}
      <div className="mb-4">
        <label className="text-sm font-medium text-text-secondary-dark block mb-2">
          Comment (optional):
        </label>
        <Input
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          placeholder="Add a comment for the audit log..."
        />
      </div>
      
      {/* Actions */}
      <ModalFooter>
        <Button
          variant="outline"
          onClick={handleReject}
          disabled={isLoading}
          className="gap-2"
        >
          <XCircle className="h-4 w-4" />
          Reject
        </Button>
        <Button
          onClick={handleApprove}
          disabled={isLoading}
          className="gap-2"
        >
          <CheckCircle className="h-4 w-4" />
          Approve
        </Button>
      </ModalFooter>
    </Modal>
  )
}
