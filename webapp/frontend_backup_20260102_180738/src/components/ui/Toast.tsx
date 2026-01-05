// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Toast Component (shadcn/ui pattern)
// ═══════════════════════════════════════════════════════════════

import { X, CheckCircle, AlertTriangle, AlertCircle, Info } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEventStore } from '@/stores/eventStore'
import type { Toast as ToastType } from '@/types'

const toastIcons = {
  success: CheckCircle,
  warning: AlertTriangle,
  error: AlertCircle,
  info: Info,
}

const toastStyles = {
  success: 'border-success/30 bg-success/10',
  warning: 'border-warning/30 bg-warning/10',
  error: 'border-critical/30 bg-critical/10',
  info: 'border-info/30 bg-info/10',
}

const iconStyles = {
  success: 'text-success',
  warning: 'text-warning',
  error: 'text-critical',
  info: 'text-info',
}

function ToastItem({ toast }: { toast: ToastType }) {
  const { removeToast } = useEventStore()
  const Icon = toastIcons[toast.type]
  
  return (
    <div
      className={cn(
        'pointer-events-auto w-full max-w-sm rounded-lg border bg-bg-card-dark p-4 shadow-lg',
        'animate-slide-in-right',
        toastStyles[toast.type]
      )}
    >
      <div className="flex items-start gap-3">
        <Icon className={cn('h-5 w-5 flex-shrink-0', iconStyles[toast.type])} />
        
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-text-primary-dark">
            {toast.title}
          </p>
          {toast.description && (
            <p className="mt-1 text-sm text-text-secondary-dark">
              {toast.description}
            </p>
          )}
          {toast.action && (
            <button
              onClick={toast.action.onClick}
              className="mt-2 text-sm font-medium text-royal-blue hover:text-royal-blue-light"
            >
              {toast.action.label}
            </button>
          )}
        </div>
        
        <button
          onClick={() => removeToast(toast.id)}
          className="flex-shrink-0 rounded p-1 hover:bg-bg-elevated-dark"
        >
          <X className="h-4 w-4 text-text-muted-dark" />
        </button>
      </div>
    </div>
  )
}

export function ToastContainer() {
  const { toasts } = useEventStore()
  
  if (toasts.length === 0) return null
  
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} />
      ))}
    </div>
  )
}

export { ToastItem }
