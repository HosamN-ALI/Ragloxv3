import React, { useEffect, useRef, useState } from 'react';

export interface A11yProps {
    'aria-label'?: string;
    'aria-labelledby'?: string;
    'aria-describedby'?: string;
    'aria-expanded'?: boolean;
    'aria-haspopup'?: boolean;
    'aria-controls'?: string;
    'aria-live'?: 'off' | 'assertive' | 'polite';
    role?: string;
    tabIndex?: number;
}

/**
 * Announces messages to screen readers
 */
export const A11yAnnouncer: React.FC<{ message: string; priority?: 'polite' | 'assertive' }> = ({
    message,
    priority = 'polite'
}) => {
    const [announcement, setAnnouncement] = useState<string>('');

    useEffect(() => {
        if (message) {
            setAnnouncement(message);

            // Clear message after announcement
            const timeout = setTimeout(() => {
                setAnnouncement('');
            }, 1000);

            return () => clearTimeout(timeout);
        }
    }, [message]);

    return (
        <div
            role="status"
            aria-live={priority}
            aria-atomic="true"
            className="sr-only"
        >
            {announcement}
        </div>
    );
};

/**
 * Keyboard navigation helper
 */
export interface KeyboardNavConfig {
    onArrowKey?: (direction: 'up' | 'down' | 'left' | 'right') => void;
    onEnterKey?: () => void;
    onEscapeKey?: () => void;
    onTabKey?: (shiftKey: boolean) => void;
}

export const useKeyboardNavigation = (config: KeyboardNavConfig) => {
    useEffect(() => {
        const handleKeyDown = (event: KeyboardEvent) => {
            const { key, shiftKey } = event;

            switch (key) {
                case 'ArrowUp':
                    config.onArrowKey?.('up');
                    break;
                case 'ArrowDown':
                    config.onArrowKey?.('down');
                    break;
                case 'ArrowLeft':
                    config.onArrowKey?.('left');
                    break;
                case 'ArrowRight':
                    config.onArrowKey?.('right');
                    break;
                case 'Enter':
                    config.onEnterKey?.();
                    break;
                case 'Escape':
                    config.onEscapeKey?.();
                    break;
                case 'Tab':
                    config.onTabKey?.(shiftKey);
                    break;
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [config]);
};

/**
 * Focus management
 */
export const useFocusManagement = () => {
    const focusableElementsRef = useRef<HTMLElement[]>([]);

    const findFocusableElements = (container: HTMLElement) => {
        const focusableSelectors = [
            'a[href]',
            'button:not([disabled])',
            'input:not([disabled])',
            'select:not([disabled])',
            'textarea:not([disabled])',
            '[tabindex]:not([tabindex="-1"])'
        ].join(', ');

        return Array.from(container.querySelectorAll<HTMLElement>(focusableSelectors))
            .filter(el => !el.hasAttribute('hidden') && !el.hasAttribute('aria-hidden'));
    };

    const trapFocus = (container: HTMLElement) => {
        const focusableElements = findFocusableElements(container);
        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];

        if (firstElement) {
            firstElement.focus();
        }

        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Tab') {
                const activeElement = document.activeElement as HTMLElement;

                if (event.shiftKey && activeElement === firstElement) {
                    event.preventDefault();
                    lastElement?.focus();
                } else if (!event.shiftKey && activeElement === lastElement) {
                    event.preventDefault();
                    firstElement?.focus();
                }
            }
        };

        container.addEventListener('keydown', handleKeyDown);
        return () => container.removeEventListener('keydown', handleKeyDown);
    };

    return { trapFocus, findFocusableElements };
};

/**
 * Screen reader only content
 */
export const VisuallyHiddenComponent: React.FC<{ as?: React.ElementType; children: React.ReactNode }> = ({
    as: Component = 'div',
    children
}) => {
    return (
        <Component className="absolute -left-[10000px] w-px h-px overflow-hidden">
            {children}
        </Component>
    );
};
// Alias for backward compatibility
export const VisuallyHidden = VisuallyHiddenComponent;

/**
 * High contrast mode detection
 */
export const useHighContrastMode = () => {
    const [highContrast, setHighContrast] = useState(false);

    useEffect(() => {
        const checkHighContrast = () => {
            const mediaQuery = window.matchMedia('(prefers-contrast: high)');
            setHighContrast(mediaQuery.matches);
        };

        // Initial check
        checkHighContrast();

        // Listen for changes
        const mediaQuery = window.matchMedia('(prefers-contrast: high)');
        mediaQuery.addEventListener('change', checkHighContrast);

        return () => mediaQuery.removeEventListener('change', checkHighContrast);
    }, []);

    return { highContrast };
};

/**
 * Reduced motion preference
 */
export const useReducedMotion = () => {
    const [reducedMotion, setReducedMotion] = useState(false);

    useEffect(() => {
        const checkReducedMotion = () => {
            const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
            setReducedMotion(mediaQuery.matches);
        };

        // Initial check
        checkReducedMotion();

        // Listen for changes
        const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
        mediaQuery.addEventListener('change', checkReducedMotion);

        return () => mediaQuery.removeEventListener('change', checkReducedMotion);
    }, []);

    return { reducedMotion };
};

/**
 * ARIA live region for dynamic content
 */
export const LiveRegion: React.FC<{ message: string; priority?: 'polite' | 'assertive' }> = ({
    message,
    priority = 'polite'
}) => {
    return (
        <div
            role="status"
            aria-live={priority}
            aria-atomic="true"
            className="sr-only absolute -left-[10000px] w-px h-px overflow-hidden"
        >
            {message}
        </div>
    );
};

/**
 * Skip navigation link
 */
export const SkipLink: React.FC<{ targetId: string; text: string }> = ({
    targetId,
    text
}) => {
    return (
        <a
            href={`#${targetId}`}
            className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 bg-black text-white px-4 py-2 z-50"
        >
            {text}
        </a>
    );
};

/**
 * Progress indicator for screen readers
 */
export const ProgressAnnouncer: React.FC<{ progress: number; max?: number }> = ({
    progress,
    max = 100
}) => {
    const [announcement, setAnnouncement] = useState<string>('');

    useEffect(() => {
        const percentage = Math.round((progress / max) * 100);
        setAnnouncement(`Progress: ${percentage} percent`);
    }, [progress, max]);

    return <A11yAnnouncer message={announcement} />;
};

/**
 * Error message with proper ARIA attributes
 */
export const AccessibleError: React.FC<{ message: string; id?: string }> = ({
    message,
    id
}) => {
    return (
        <div
            id={id}
            role="alert"
            aria-live="assertive"
            aria-atomic="true"
            className="text-red-600 dark:text-red-400 text-sm mt-1"
        >
            {message}
        </div>
    );
};

/**
 * Loading state announcer
 */
export const LoadingState: React.FC<{ loading: boolean; text?: string }> = ({
    loading,
    text = 'Loading...'
}) => {
    if (!loading) return null;
    return <A11yAnnouncer message={text} />;
};