// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Input Component (shadcn/ui pattern)
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { cn } from '@/lib/utils'

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          'flex h-10 w-full rounded-md border border-border-dark bg-bg-elevated-dark px-3 py-2 text-sm',
          'ring-offset-bg-dark placeholder:text-text-muted-dark',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-royal-blue focus-visible:ring-offset-2',
          'disabled:cursor-not-allowed disabled:opacity-50',
          'text-text-primary-dark',
          className
        )}
        ref={ref}
        {...props}
      />
    )
  }
)
Input.displayName = 'Input'

export { Input }
