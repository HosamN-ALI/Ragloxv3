// RAGLOX v3.0 - File Preview Component
// Preview generated file content with syntax highlighting
// Based on Manus.im design

import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  FileText,
  FileCode,
  FileJson,
  File,
  Copy,
  Check,
  Download,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Maximize2,
  X
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export interface FileData {
  id: string;
  name: string;
  type: "text" | "code" | "json" | "markdown" | "csv" | "unknown";
  content: string;
  language?: string;
  path?: string;
  size?: number;
  createdAt?: string;
}

interface FilePreviewProps {
  file: FileData;
  maxLines?: number;
  showFullButton?: boolean;
  onViewFull?: (file: FileData) => void;
  onDownload?: (file: FileData) => void;
  className?: string;
}

export function FilePreview({
  file,
  maxLines = 10,
  showFullButton = true,
  onViewFull,
  onDownload,
  className,
}: FilePreviewProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  // Split content into lines
  const lines = useMemo(() => file.content.split("\n"), [file.content]);
  const totalLines = lines.length;
  const hasMoreLines = totalLines > maxLines;
  
  // Display lines based on expanded state
  const displayLines = useMemo(() => {
    if (isExpanded || !hasMoreLines) {
      return lines;
    }
    return lines.slice(0, maxLines);
  }, [lines, isExpanded, hasMoreLines, maxLines]);

  // Get file icon based on type
  const FileIcon = useMemo(() => {
    switch (file.type) {
      case "code":
        return FileCode;
      case "json":
        return FileJson;
      case "text":
      case "markdown":
        return FileText;
      default:
        return File;
    }
  }, [file.type]);

  // Get language color
  const getLanguageColor = () => {
    switch (file.language?.toLowerCase()) {
      case "python":
        return "#3572A5";
      case "javascript":
      case "js":
        return "#f1e05a";
      case "typescript":
      case "ts":
        return "#2b7489";
      case "json":
        return "#292929";
      case "bash":
      case "shell":
        return "#4eaa25";
      case "yaml":
      case "yml":
        return "#cb171e";
      default:
        return "#888888";
    }
  };

  // Copy to clipboard
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(file.content);
      setCopied(true);
      toast.success("Copied to clipboard");
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      toast.error("Failed to copy");
    }
  };

  // Download file
  const handleDownload = () => {
    if (onDownload) {
      onDownload(file);
      return;
    }

    // Default download behavior
    const blob = new Blob([file.content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success(`Downloaded ${file.name}`);
  };

  return (
    <div
      className={cn("rounded-xl overflow-hidden", className)}
      style={{
        background: "#1f1f1f",
        border: "1px solid rgba(255, 255, 255, 0.06)",
        boxShadow: "0 2px 8px rgba(0, 0, 0, 0.15)",
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3"
        style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.06)" }}
      >
        <div className="flex items-center gap-3 min-w-0">
          {/* File Icon */}
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: "rgba(74, 158, 255, 0.15)" }}
          >
            <FileIcon className="w-4 h-4" style={{ color: "#4a9eff" }} />
          </div>

          {/* File Info */}
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span
                className="text-sm font-medium truncate"
                style={{ color: "#e8e8e8" }}
              >
                {file.name}
              </span>
              {file.language && (
                <span
                  className="px-1.5 py-0.5 rounded text-xs"
                  style={{
                    background: `${getLanguageColor()}20`,
                    color: getLanguageColor(),
                  }}
                >
                  {file.language}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-xs" style={{ color: "#666666" }}>
                {totalLines} lines
              </span>
              {file.size && (
                <span className="text-xs" style={{ color: "#666666" }}>
                  • {formatFileSize(file.size)}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1">
          <ActionButton onClick={handleCopy} title="Copy">
            {copied ? (
              <Check className="w-3.5 h-3.5" style={{ color: "#4ade80" }} />
            ) : (
              <Copy className="w-3.5 h-3.5" />
            )}
          </ActionButton>
          <ActionButton onClick={handleDownload} title="Download">
            <Download className="w-3.5 h-3.5" />
          </ActionButton>
          {showFullButton && onViewFull && (
            <ActionButton onClick={() => onViewFull(file)} title="View Full">
              <Maximize2 className="w-3.5 h-3.5" />
            </ActionButton>
          )}
        </div>
      </div>

      {/* Content */}
      <div
        className="overflow-auto"
        style={{
          background: "#141414",
          maxHeight: isExpanded ? "400px" : "auto",
        }}
      >
        <pre
          className="p-4 text-xs leading-relaxed"
          style={{
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            color: "#a0a0a0",
            margin: 0,
          }}
        >
          <code>
            {displayLines.map((line, index) => (
              <div key={index} className="flex">
                <span
                  className="select-none pr-4 text-right"
                  style={{ color: "#444444", minWidth: "40px" }}
                >
                  {index + 1}
                </span>
                <span style={{ color: "#e8e8e8" }}>{line || " "}</span>
              </div>
            ))}
          </code>
        </pre>
      </div>

      {/* Expand/Collapse Button */}
      {hasMoreLines && (
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="w-full flex items-center justify-center gap-2 py-2.5 text-xs transition-colors"
          style={{
            borderTop: "1px solid rgba(255, 255, 255, 0.06)",
            color: "#888888",
          }}
          onMouseEnter={(e) =>
            (e.currentTarget.style.background = "rgba(255,255,255,0.04)")
          }
          onMouseLeave={(e) =>
            (e.currentTarget.style.background = "transparent")
          }
        >
          {isExpanded ? (
            <>
              <ChevronUp className="w-4 h-4" />
              Show Less
            </>
          ) : (
            <>
              <ChevronDown className="w-4 h-4" />
              Show More ({totalLines - maxLines} more lines)
            </>
          )}
        </button>
      )}
    </div>
  );
}

// Action Button Component
interface ActionButtonProps {
  onClick: () => void;
  title?: string;
  children: React.ReactNode;
}

function ActionButton({ onClick, title, children }: ActionButtonProps) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="w-7 h-7 rounded flex items-center justify-center transition-all duration-150"
      style={{ color: "#888888" }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = "rgba(255,255,255,0.08)";
        e.currentTarget.style.color = "#e8e8e8";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = "transparent";
        e.currentTarget.style.color = "#888888";
      }}
    >
      {children}
    </button>
  );
}

// File Size Formatter
function formatFileSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

// Full File Viewer Modal
interface FileViewerModalProps {
  file: FileData | null;
  onClose: () => void;
}

export function FileViewerModal({ file, onClose }: FileViewerModalProps) {
  if (!file) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        style={{ background: "rgba(0, 0, 0, 0.8)" }}
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.95, opacity: 0 }}
          className="w-full max-w-4xl max-h-[90vh] overflow-hidden rounded-xl"
          style={{ background: "#1a1a1a" }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Modal Header */}
          <div
            className="flex items-center justify-between px-4 py-3"
            style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.06)" }}
          >
            <div className="flex items-center gap-2">
              <FileText className="w-5 h-5" style={{ color: "#4a9eff" }} />
              <span className="font-medium" style={{ color: "#e8e8e8" }}>
                {file.name}
              </span>
            </div>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded flex items-center justify-center transition-colors"
              style={{ color: "#888888" }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.background = "rgba(255,255,255,0.08)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.background = "transparent")
              }
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Modal Content */}
          <div className="overflow-auto" style={{ maxHeight: "calc(90vh - 60px)" }}>
            <FilePreview file={file} maxLines={1000} showFullButton={false} />
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

export default FilePreview;
