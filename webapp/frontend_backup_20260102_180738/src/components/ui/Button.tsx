// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Button Component (shadcn/ui pattern)
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { cn } from '@/lib/utils'

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link'
  size?: 'default' | 'sm' | 'lg' | 'icon'
}

const buttonVariants = {
  default: 'bg-royal-blue text-white hover:bg-royal-blue-dark',
  destructive: 'bg-critical text-white hover:bg-critical-dark',
  outline: 'border border-border-dark bg-transparent hover:bg-bg-elevated-dark hover:text-text-primary-dark',
  secondary: 'bg-bg-elevated-dark text-text-primary-dark hover:bg-slate-700',
  ghost: 'hover:bg-bg-elevated-dark hover:text-text-primary-dark',
  link: 'text-royal-blue underline-offset-4 hover:underline',
}

const buttonSizes = {
  default: 'h-10 px-4 py-2',
  sm: 'h-9 rounded-md px-3',
  lg: 'h-11 rounded-md px-8',
  icon: 'h-10 w-10',
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'default', ...props }, ref) => {
    return (
      <button
        className={cn(
          'inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium',
          'ring-offset-bg-dark transition-colors focus-visible:outline-none focus-visible:ring-2',
          'focus-visible:ring-royal-blue focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
          buttonVariants[variant],
          buttonSizes[size],
          className
        )}
        ref={ref}
        {...props}
      />
    )
  }
)
Button.displayName = 'Button'

export { Button }
