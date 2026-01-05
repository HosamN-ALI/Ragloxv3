// RAGLOX v3.0 - AI-PLAN Event Card Component (Manus-style)
// Displays AI planning events with Nuclei template suggestions

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Brain, 
  ChevronDown,
  FileCode,
  Cpu,
  Search
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { AIPlanData } from "@/types";

interface AIPlanCardProps {
  data: AIPlanData;
  className?: string;
}

export function AIPlanCard({ data, className }: AIPlanCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  // Subtype icons
  const subtypeIcons: Record<string, typeof Brain> = {
    nuclei_template_selection: FileCode,
    port_analysis: Search,
    exploit_suggestion: Cpu,
  };

  const Icon = subtypeIcons[data.subtype] || Brain;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        "rounded-xl overflow-hidden ai-plan-card",
        className
      )}
      style={{ 
        background: 'linear-gradient(135deg, rgba(167, 139, 250, 0.1) 0%, rgba(167, 139, 250, 0.05) 100%)',
        boxShadow: '0 4px 24px rgba(0,0,0,0.15)'
      }}
    >
      {/* Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-[#a78bfa]/5 transition-all duration-200"
      >
        <div 
          className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: 'rgba(167, 139, 250, 0.2)' }}
        >
          <Brain className="w-4 h-4" style={{ color: '#a78bfa' }} />
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold" style={{ color: '#a78bfa' }}>AI-PLAN</span>
            {data.port && (
              <span 
                className="text-xs px-2 py-0.5 rounded-full"
                style={{ background: 'rgba(167, 139, 250, 0.2)', color: '#c4b5fd' }}
              >
                Port {data.port}
              </span>
            )}
            {data.templates_count && (
              <span 
                className="text-xs px-2 py-0.5 rounded-full"
                style={{ background: 'rgba(167, 139, 250, 0.2)', color: '#c4b5fd' }}
              >
                {data.templates_count} templates
              </span>
            )}
          </div>
        </div>

        <ChevronDown className={cn(
          "w-4 h-4 transition-transform duration-200",
          isExpanded && "rotate-180"
        )} style={{ color: '#a78bfa' }} />
      </button>

      {/* Content */}
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-3">
              {/* Message */}
              <p className="text-sm" style={{ color: '#e8e8e8' }}>{data.message}</p>

              {/* Reasoning */}
              {data.reasoning && (
                <p className="text-sm italic" style={{ color: '#888888' }}>
                  {data.reasoning}
                </p>
              )}

              {/* Templates List */}
              {data.templates && data.templates.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-sm font-medium" style={{ color: '#a78bfa' }}>
                    <FileCode className="w-4 h-4" />
                    <span>Selected Templates:</span>
                  </div>
                  <div 
                    className="rounded-lg p-3"
                    style={{ background: 'rgba(0,0,0,0.2)' }}
                  >
                    <div className="flex flex-wrap gap-2">
                      {data.templates.slice(0, 5).map((template, index) => (
                        <span
                          key={index}
                          className="text-xs px-2 py-1 rounded font-mono"
                          style={{ background: 'rgba(167, 139, 250, 0.2)', color: '#c4b5fd' }}
                        >
                          {template}
                        </span>
                      ))}
                      {data.templates.length > 5 && (
                        <span 
                          className="text-xs px-2 py-1 rounded"
                          style={{ background: 'rgba(167, 139, 250, 0.1)', color: '#a78bfa' }}
                        >
                          +{data.templates.length - 5} more
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Collapsed Preview */}
      {!isExpanded && (
        <div className="px-4 pb-3">
          <p className="text-sm line-clamp-2" style={{ color: '#888888' }}>
            {data.message}
          </p>
        </div>
      )}
    </motion.div>
  );
}

export default AIPlanCard;
