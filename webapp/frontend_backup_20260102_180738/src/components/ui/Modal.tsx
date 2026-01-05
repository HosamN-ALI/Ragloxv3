// ═══════════════════════════════════════════════════════════════
// RAGLOX v3.0 - Modal Component (shadcn/ui pattern)
// ═══════════════════════════════════════════════════════════════

import * as React from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from './Button'

interface ModalProps {
  isOpen: boolean
  onClose: () => void
  title?: string
  description?: string
  children: React.ReactNode
  className?: string
  showCloseButton?: boolean
}

export function Modal({
  isOpen,
  onClose,
  title,
  description,
  children,
  className,
  showCloseButton = true,
}: ModalProps) {
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
  
  // Prevent body scroll when modal is open
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
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-fade-in"
        onClick={onClose}
      />
      
      {/* Modal Content */}
      <div
        className={cn(
          'relative z-10 w-full max-w-lg rounded-lg border border-border-dark bg-bg-card-dark shadow-xl',
          'animate-fade-in',
          className
        )}
      >
        {/* Header */}
        {(title || showCloseButton) && (
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
            {showCloseButton && (
              <Button variant="ghost" size="icon" onClick={onClose}>
                <X className="h-4 w-4" />
              </Button>
            )}
          </div>
        )}
        
        {/* Body */}
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}

// Modal Footer helper
interface ModalFooterProps {
  children: React.ReactNode
  className?: string
}

export function ModalFooter({ children, className }: ModalFooterProps) {
  return (
    <div
      className={cn(
        'flex items-center justify-end gap-2 border-t border-border-dark p-4 -mx-4 -mb-4 mt-4',
        className
      )}
    >
      {children}
    </div>
  )
}
