// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Badge Component (shadcn/ui pattern)
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { cn } from '@/lib/utils'

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'secondary' | 'success' | 'warning' | 'critical' | 'outline'
}

const badgeVariants = {
  default: 'bg-royal-blue text-white',
  secondary: 'bg-bg-elevated-dark text-text-secondary-dark',
  success: 'bg-success/20 text-success border-success/30',
  warning: 'bg-warning/20 text-warning border-warning/30',
  critical: 'bg-critical/20 text-critical border-critical/30',
  outline: 'border border-border-dark text-text-secondary-dark',
}

function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  return (
    <div
      className={cn(
        'inline-flex items-center rounded-full border border-transparent px-2.5 py-0.5 text-xs font-semibold',
        'transition-colors focus:outline-none focus:ring-2 focus:ring-royal-blue focus:ring-offset-2',
        badgeVariants[variant],
        className
      )}
      {...props}
    />
  )
}

export { Badge }
