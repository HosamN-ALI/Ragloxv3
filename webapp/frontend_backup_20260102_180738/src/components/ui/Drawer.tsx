// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Drawer Component (Slide-over panel)
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from './Button'

interface DrawerProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  description?: string
  children: React.ReactNode
  className?: string
  side?: 'left' | 'right'
  width?: 'sm' | 'md' | 'lg' | 'xl'
}

const widthClasses = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-lg',
  xl: 'max-w-xl',
}

export function Drawer({
  isOpen,
  onClose,
  title,
  description,
  children,
  className,
  side = 'right',
  width = 'md',
}: DrawerProps) {
  // Close on escape key
  React.useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose()
      }
    }
    
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [isOpen, onClose])
  
  // Prevent body scroll when drawer is open
  React.useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    
    return () => {
      document.body.style.overflow = ''
    }
  }, [isOpen])
  
  if (!isOpen) return null
  
  return (
    <div className="fixed inset-0 z-50">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/40 backdrop-blur-sm animate-fade-in"
        onClick={onClose}
      />
      
      {/* Drawer Panel */}
      <div
        className={cn(
          'absolute top-0 h-full w-full border-l border-border-dark bg-bg-card-dark shadow-xl',
          'animate-slide-in-right',
          widthClasses[width],
          side === 'right' ? 'right-0' : 'left-0',
          className
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-dark p-4">
          <div>
            {title && (
              <h2 className="text-lg font-semibold text-text-primary-dark">
                {title}
              </h2>
            )}
            {description && (
              <p className="text-sm text-text-secondary-dark mt-1">
                {description}
              </p>
            )}
          </div>
          <Button variant="ghost" size="icon" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>
        
        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4">{children}</div>
      </div>
    </div>
  )
}
