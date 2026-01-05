import { CSP_HEADER_STRING, XSS_PROTECTION_HEADER, HSTS_HEADER } from './config';

export interface SecurityMiddleware {
    enableCSP: boolean;
    enableXSSProtection: boolean;
    enableHSTS: boolean;
    enableRateLimiting: boolean;
}

export class SecurityManager {
    private static instance: SecurityManager;
    private cspEnabled: boolean;
    private xssProtectionEnabled: boolean;
    private hstsEnabled: boolean;
    private rateLimitingEnabled: boolean;

    constructor(config: SecurityMiddleware) {
        this.cspEnabled = config.enableCSP;
        this.xssProtectionEnabled = config.enableXSSProtection;
        this.hstsEnabled = config.enableHSTS;
        this.rateLimitingEnabled = config.enableRateLimiting;
    }

    public static getInstance(config?: SecurityMiddleware): SecurityManager {
        if (!SecurityManager.instance && config) {
            SecurityManager.instance = new SecurityManager(config);
        }
        return SecurityManager.instance;
    }

    /**
     * Sanitize user input to prevent XSS attacks
     */
    public sanitizeInput(input: string): string {
        const div = document.createElement('div');
        div.textContent = input;

        // Additional sanitization for common XSS patterns
        const sanitized = div.innerHTML
            .replace(/javascript:/gi, '')
            .replace(/on\w+=\s*["']/gi, '')
            .replace(/<script[^>]*>.*?<\/script>/gi, '')
            .replace(/<\/?script[^>]*>/gi, '')
            .replace(/data:\s*text\/html[^,]*,/gi, '');

        return sanitized;
    }

    /**
     * Validate UUID format
     */
    public validateUUID(uuid: string): boolean {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        return uuidRegex.test(uuid);
    }

    /**
     * Sanitize file names to prevent directory traversal
     */
    public sanitizeFilename(filename: string): string {
        return filename
            .replace(/[^a-zA-Z0-9.-]/g, '_')
            .replace(/\.\.+/g, '_')
            .replace(/^\.+/, '')
            .toLowerCase();
    }

    /**
     * Generate secure CSRF token
     */
    public generateCSRFToken(): string {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Check if content is potentially malicious
     */
    public isPotentiallyMalicious(content: string): boolean {
        const dangerousPatterns = [
            /<script/i,
            /javascript:/i,
            /onerror\s*=/i,
            /onload\s*=/i,
            /onclick\s*=/i,
            /eval\(/i,
            /expression\(/i,
            /data:\s*text\/html/i,
        ];

        return dangerousPatterns.some(pattern => pattern.test(content));
    }

    /**
     * Apply security headers to fetch requests
     */
    public applySecurityHeaders(headers: HeadersInit = {}): HeadersInit {
        const securityHeaders = new Headers(headers);

        if (this.cspEnabled) {
            securityHeaders.set('Content-Security-Policy', CSP_HEADER_STRING);
        }

        if (this.xssProtectionEnabled) {
            securityHeaders.set('X-XSS-Protection', XSS_PROTECTION_HEADER);
        }

        if (this.hstsEnabled) {
            securityHeaders.set('Strict-Transport-Security', HSTS_HEADER);
        }

        securityHeaders.set('X-Content-Type-Options', 'nosniff');
        securityHeaders.set('X-Frame-Options', 'DENY');
        securityHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');

        return securityHeaders;
    }

    /**
     * Rate limiting helper
     */
    private requestCounts: Map<string, { count: number; resetTime: number }> = new Map();
    private RATE_LIMIT_WINDOW = 60000; // 1 minute
    private MAX_REQUESTS = 100;

    public checkRateLimit(identifier: string): boolean {
        if (!this.rateLimitingEnabled) return true;

        const now = Date.now();
        const existing = this.requestCounts.get(identifier);

        if (existing) {
            if (now > existing.resetTime) {
                // Reset window
                this.requestCounts.set(identifier, { count: 1, resetTime: now + this.RATE_LIMIT_WINDOW });
                return true;
            } else if (existing.count < this.MAX_REQUESTS) {
                // Increment count
                existing.count++;
                return true;
            } else {
                return false; // Rate limit exceeded
            }
        } else {
            // First request
            this.requestCounts.set(identifier, { count: 1, resetTime: now + this.RATE_LIMIT_WINDOW });
            return true;
        }
    }

    /**
     * Clean up rate limiting data
     */
    public cleanupRateLimitData(): void {
        const now = Date.now();
        // @ts-ignore - Map iteration issue
        for (const [key, data] of Array.from(this.requestCounts.entries())) {
            if (now > data.resetTime) {
                this.requestCounts.delete(key);
            }
        }
    }
}

export const getSecurityManager = () => {
    return SecurityManager.getInstance({
        enableCSP: import.meta.env.VITE_CSP_ENABLED === 'true',
        enableXSSProtection: import.meta.env.VITE_XSS_PROTECTION === 'true',
        enableHSTS: import.meta.env.VITE_SECURITY_HEADERS === 'true',
        enableRateLimiting: import.meta.env.VITE_RATE_LIMIT_ENABLED === 'true',
    });
};