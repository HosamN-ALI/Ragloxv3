// Content Security Policy headers
export const CSP_HEADER = {
    "default-src": ["'self'"],
    "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'", "http://172.245.232.188:8000"],
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "img-src": ["'self'", "data:", "https:"],
    "connect-src": ["'self'", "ws://172.245.232.188:8000", "wss://172.245.232.188:8000"],
    "media-src": ["'self'"],
    "object-src": ["'none'"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"]
};

export const CSP_HEADER_STRING = Object.entries(CSP_HEADER)
    .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
    .join('; ');

export const XSS_PROTECTION_HEADER = '1; mode=block';

export const HSTS_HEADER = 'max-age=31536000; includeSubDomains; preload';