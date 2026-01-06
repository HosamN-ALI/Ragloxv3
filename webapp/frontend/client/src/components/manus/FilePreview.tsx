// RAGLOX v3.0 - File Preview Component
// Inline file preview in chat with syntax highlighting and copy functionality
// Part of the Chat UX features per development plan

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FileText,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Download,
  ExternalLink,
  Code,
  FileCode,
  FileLock,
  FileJson,
  FileType,
  FileTerminal,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface FilePreviewProps {
  filename: string;
  content: string;
  language?: string;
  isExpandedByDefault?: boolean;
  maxPreviewLines?: number;
  onDownload?: () => void;
  onOpenExternal?: () => void;
  className?: string;
}

export function FilePreview({
  filename,
  content,
  language,
  isExpandedByDefault = false,
  maxPreviewLines = 10,
  onDownload,
  onOpenExternal,
  className,
}: FilePreviewProps) {
  const [isExpanded, setIsExpanded] = useState(isExpandedByDefault);
  const [copied, setCopied] = useState(false);

  // Detect language from file extension if not provided
  const detectedLanguage = useMemo(() => {
    if (language) return language;
    const ext = filename.split('.').pop()?.toLowerCase();
    switch (ext) {
      case 'py': return 'python';
      case 'js': return 'javascript';
      case 'ts': return 'typescript';
      case 'tsx': return 'typescript';
      case 'jsx': return 'javascript';
      case 'json': return 'json';
      case 'yaml':
      case 'yml': return 'yaml';
      case 'sh':
      case 'bash': return 'bash';
      case 'conf':
      case 'cfg': return 'config';
      case 'sql': return 'sql';
      case 'xml': return 'xml';
      case 'html': return 'html';
      case 'css': return 'css';
      case 'md': return 'markdown';
      case 'txt': return 'text';
      default: return 'text';
    }
  }, [filename, language]);

  // Get appropriate icon for file type
  const FileIcon = useMemo(() => {
    switch (detectedLanguage) {
      case 'python':
      case 'javascript':
      case 'typescript':
        return FileCode;
      case 'json':
        return FileJson;
      case 'bash':
        return FileTerminal;
      case 'config':
        return FileLock;
      default:
        return FileText;
    }
  }, [detectedLanguage]);

  // Split content into lines
  const lines = useMemo(() => content.split('\n'), [content]);
  const totalLines = lines.length;
  const previewLines = lines.slice(0, maxPreviewLines);
  const hasMoreLines = totalLines > maxPreviewLines;

  // Handle copy
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      toast.success("File content copied to clipboard");
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      toast.error("Failed to copy content");
    }
  };

  return (
    <div
      className={cn(
        "rounded-xl overflow-hidden",
        className
      )}
      style={{
        background: '#1a1a1a',
        border: '1px solid rgba(255,255,255,0.08)',
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}
      >
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: 'rgba(74, 158, 255, 0.15)' }}
          >
            <FileIcon className="w-4 h-4" style={{ color: '#4a9eff' }} />
          </div>
          <div>
            <span className="font-medium text-sm" style={{ color: '#e8e8e8' }}>
              {filename}
            </span>
            <span className="text-xs ml-2" style={{ color: '#666666' }}>
              {totalLines} lines • {detectedLanguage}
            </span>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1">
          {/* Copy Button */}
          <button
            onClick={handleCopy}
            className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
            style={{ color: '#888888' }}
            title="Copy content"
            onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
            onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
          >
            {copied ? (
              <Check className="w-3.5 h-3.5" style={{ color: '#4ade80' }} />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </button>

          {/* Download Button */}
          {onDownload && (
            <button
              onClick={onDownload}
              className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
              style={{ color: '#888888' }}
              title="Download file"
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <Download className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Open External Button */}
          {onOpenExternal && (
            <button
              onClick={onOpenExternal}
              className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
              style={{ color: '#888888' }}
              title="Open in editor"
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Expand/Collapse Button */}
          {hasMoreLines && (
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
              style={{ color: '#888888' }}
              title={isExpanded ? "Collapse" : "Expand"}
              onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
            >
              {isExpanded ? (
                <ChevronUp className="w-4 h-4" />
              ) : (
                <ChevronDown className="w-4 h-4" />
              )}
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      <div
        className="overflow-auto"
        style={{
          backgroundColor: '#0d0d0d',
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
          fontSize: '13px',
          lineHeight: '1.6',
          maxHeight: isExpanded ? '400px' : 'auto',
        }}
      >
        <div className="p-4">
          {(isExpanded ? lines : previewLines).map((line, index) => (
            <div key={index} className="flex">
              {/* Line number */}
              <span
                className="select-none text-right pr-4 min-w-[3rem]"
                style={{ color: '#555555' }}
              >
                {index + 1}
              </span>
              {/* Line content */}
              <SyntaxHighlightedLine
                line={line}
                language={detectedLanguage}
              />
            </div>
          ))}
        </div>
      </div>

      {/* Show More indicator */}
      {!isExpanded && hasMoreLines && (
        <button
          onClick={() => setIsExpanded(true)}
          className="w-full py-2 text-xs flex items-center justify-center gap-2 transition-colors"
          style={{
            background: 'rgba(0, 0, 0, 0.3)',
            borderTop: '1px solid rgba(255,255,255,0.06)',
            color: '#888888',
          }}
          onMouseEnter={(e) => e.currentTarget.style.color = '#4a9eff'}
          onMouseLeave={(e) => e.currentTarget.style.color = '#888888'}
        >
          <ChevronDown className="w-3 h-3" />
          Show {totalLines - maxPreviewLines} more lines
        </button>
      )}
    </div>
  );
}

// Simple syntax highlighting component
function SyntaxHighlightedLine({ line, language }: { line: string; language: string }) {
  // Basic syntax highlighting patterns
  const highlightedContent = useMemo(() => {
    if (!line) return <span style={{ color: '#a0a0a0' }}>{' '}</span>;

    // Comment patterns
    const commentPatterns = [
      { pattern: /^(\s*#.*)$/, color: '#6a737d' },
      { pattern: /^(\s*\/\/.*)$/, color: '#6a737d' },
      { pattern: /(["'])(?:(?=(\\?))\2.)*?\1/g, color: '#98c379' }, // Strings
    ];

    // Keywords
    const keywords = /\b(import|from|def|class|if|else|elif|return|for|while|try|except|finally|with|as|in|not|and|or|is|None|True|False|const|let|var|function|export|default|async|await)\b/g;
    
    // Check for comments first
    if (line.trim().startsWith('#') || line.trim().startsWith('//')) {
      return <span style={{ color: '#6a737d' }}>{line}</span>;
    }

    // Basic highlighting
    let result = line;

    return (
      <span
        className="whitespace-pre-wrap"
        style={{ color: '#a0a0a0' }}
        dangerouslySetInnerHTML={{
          __html: line
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            // Strings
            .replace(/(["'`])(?:(?!\1)[^\\]|\\.)*\1/g, '<span style="color:#98c379">$&</span>')
            // Keywords
            .replace(/\b(import|from|def|class|if|else|elif|return|for|while|try|except|finally|with|as|in|not|and|or|is|None|True|False|const|let|var|function|export|default|async|await|interface|type|enum)\b/g, '<span style="color:#c678dd">$&</span>')
            // Numbers
            .replace(/\b(\d+\.?\d*)\b/g, '<span style="color:#d19a66">$&</span>')
            // Functions
            .replace(/(\w+)(?=\s*\()/g, '<span style="color:#61afef">$&</span>')
        }}
      />
    );
  }, [line, language]);

  return highlightedContent;
}

// Compact file badge for chat
export function FileBadge({
  filename,
  onClick,
}: {
  filename: string;
  onClick?: () => void;
}) {
  const ext = filename.split('.').pop()?.toLowerCase();
  
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs transition-colors"
      style={{
        background: 'rgba(74, 158, 255, 0.1)',
        color: '#4a9eff',
        border: '1px solid rgba(74, 158, 255, 0.2)',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = 'rgba(74, 158, 255, 0.2)';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = 'rgba(74, 158, 255, 0.1)';
      }}
    >
      <FileText className="w-3 h-3" />
      <span>{filename}</span>
    </button>
  );
}

export default FilePreview;
