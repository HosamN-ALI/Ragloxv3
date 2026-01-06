// RAGLOX v3.0 - Utility Panel Component
// Sliding panel for Files, Settings, Help, and Notifications
// Follows Manus design system with warm dark palette

import { useEffect, useRef } from "react";
import { motion } from "framer-motion";
import {
  X,
  FileText,
  Settings,
  HelpCircle,
  Bell,
  ExternalLink,
  Check,
  AlertTriangle,
  Info,
  Shield,
  Target,
  Terminal,
  BookOpen,
  Zap,
  FolderOpen,
  File,
  Download,
  Trash2,
  Clock,
  Globe,
  Keyboard,
  Moon,
  Volume2,
  VolumeX,
  Eye,
  EyeOff,
  RotateCcw,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { EventCard } from "@/types";

export type UtilityPanelType = "files" | "settings" | "help" | "notifications";

interface PreferencesState {
  liveTelemetry: boolean;
  showTooltips: boolean;
  compactPlan: boolean;
}

interface UtilityPanelProps {
  type: UtilityPanelType;
  events?: EventCard[];
  preferences?: PreferencesState;
  onTogglePreference?: (key: keyof PreferencesState) => void;
  onClose: () => void;
  className?: string;
}

const panelConfig = {
  files: {
    title: "Files",
    icon: FileText,
    description: "Mission files and artifacts",
  },
  settings: {
    title: "Settings",
    icon: Settings,
    description: "Preferences and configuration",
  },
  help: {
    title: "Help",
    icon: HelpCircle,
    description: "Documentation and support",
  },
  notifications: {
    title: "Notifications",
    icon: Bell,
    description: "Alerts and updates",
  },
};

export function UtilityPanel({
  type,
  events = [],
  preferences = {
    liveTelemetry: true,
    showTooltips: true,
    compactPlan: false,
  },
  onTogglePreference,
  onClose,
  className,
}: UtilityPanelProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const config = panelConfig[type];
  const Icon = config.icon;

  // Close on click outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    // Close on Escape key
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [onClose]);

  return (
    <motion.div
      ref={panelRef}
      initial={{ x: -320, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: -320, opacity: 0 }}
      transition={{ type: "spring", damping: 25, stiffness: 300 }}
      className={cn(
        "absolute left-[108px] top-0 bottom-0 w-[320px] z-50",
        "flex flex-col",
        className
      )}
      style={{
        background: "linear-gradient(180deg, #1a1a1a 0%, #141414 100%)",
        borderRight: "1px solid rgba(255, 255, 255, 0.06)",
        boxShadow: "4px 0 24px rgba(0, 0, 0, 0.3)",
      }}
    >
      {/* Panel Header */}
      <div
        className="flex items-center justify-between px-4 py-3 shrink-0"
        style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.06)" }}
      >
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: "rgba(74, 158, 255, 0.15)" }}
          >
            <Icon className="w-4 h-4" style={{ color: "#4a9eff" }} />
          </div>
          <div>
            <h2 className="font-medium" style={{ color: "#e8e8e8" }}>
              {config.title}
            </h2>
            <p className="text-xs" style={{ color: "#888888" }}>
              {config.description}
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          className="h-8 w-8 rounded-lg hover:bg-white/5"
        >
          <X className="w-4 h-4" style={{ color: "#888888" }} />
        </Button>
      </div>

      {/* Panel Content */}
      <ScrollArea className="flex-1">
        <div className="p-4">
          {type === "files" && <FilesContent />}
          {type === "settings" && (
            <SettingsContent
              preferences={preferences}
              onToggle={onTogglePreference}
            />
          )}
          {type === "help" && <HelpContent />}
          {type === "notifications" && <NotificationsContent events={events} />}
        </div>
      </ScrollArea>
    </motion.div>
  );
}

// ============================================
// Files Panel Content
// ============================================

function FilesContent() {
  const recentFiles = [
    { name: "scan_results.json", type: "json", size: "12 KB", time: "2 min ago" },
    { name: "nmap_output.txt", type: "text", size: "4 KB", time: "5 min ago" },
    { name: "credentials.csv", type: "csv", size: "1 KB", time: "10 min ago" },
    { name: "exploit_log.txt", type: "text", size: "8 KB", time: "15 min ago" },
  ];

  const folders = [
    { name: "Reconnaissance", count: 12 },
    { name: "Vulnerabilities", count: 8 },
    { name: "Credentials", count: 3 },
    { name: "Reports", count: 5 },
  ];

  return (
    <div className="space-y-6">
      {/* Folders Section */}
      <div>
        <h3 className="text-xs font-medium mb-3" style={{ color: "#888888" }}>
          FOLDERS
        </h3>
        <div className="space-y-1">
          {folders.map((folder) => (
            <button
              key={folder.name}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors"
              style={{ color: "#e8e8e8" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255, 255, 255, 0.04)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <FolderOpen className="w-4 h-4" style={{ color: "#f59e0b" }} />
              <span className="flex-1 text-left text-sm">{folder.name}</span>
              <span className="text-xs" style={{ color: "#666666" }}>
                {folder.count}
              </span>
              <ChevronRight className="w-4 h-4" style={{ color: "#666666" }} />
            </button>
          ))}
        </div>
      </div>

      {/* Recent Files Section */}
      <div>
        <h3 className="text-xs font-medium mb-3" style={{ color: "#888888" }}>
          RECENT FILES
        </h3>
        <div className="space-y-1">
          {recentFiles.map((file, index) => (
            <button
              key={index}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors"
              style={{ color: "#e8e8e8" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255, 255, 255, 0.04)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <File className="w-4 h-4" style={{ color: "#4a9eff" }} />
              <div className="flex-1 text-left">
                <span className="text-sm block">{file.name}</span>
                <span className="text-xs" style={{ color: "#666666" }}>
                  {file.size} • {file.time}
                </span>
              </div>
              <Download className="w-4 h-4 opacity-0 group-hover:opacity-100" style={{ color: "#888888" }} />
            </button>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="pt-4 border-t border-white/5 space-y-2">
        <Button
          variant="outline"
          className="w-full justify-start gap-2"
          style={{
            background: "rgba(74, 158, 255, 0.1)",
            borderColor: "rgba(74, 158, 255, 0.2)",
            color: "#4a9eff",
          }}
        >
          <Download className="w-4 h-4" />
          Export All Files
        </Button>
        <Button
          variant="ghost"
          className="w-full justify-start gap-2 text-red-400 hover:text-red-300 hover:bg-red-500/10"
        >
          <Trash2 className="w-4 h-4" />
          Clear All Files
        </Button>
      </div>
    </div>
  );
}

// ============================================
// Settings Panel Content
// ============================================

interface SettingsContentProps {
  preferences: PreferencesState;
  onToggle?: (key: keyof PreferencesState) => void;
}

interface SettingItem {
  icon: React.ElementType;
  label: string;
  description: string;
  key: keyof PreferencesState | null;
  enabled?: boolean;
  disabled?: boolean;
  action?: boolean;
}

function SettingsContent({ preferences, onToggle }: SettingsContentProps) {
  const settingsSections: { title: string; items: SettingItem[] }[] = [
    {
      title: "DISPLAY",
      items: [
        {
          icon: Eye,
          label: "Live Telemetry",
          description: "Show real-time mission data",
          key: "liveTelemetry",
          enabled: preferences.liveTelemetry,
        },
        {
          icon: Info,
          label: "Show Tooltips",
          description: "Display helpful hints on hover",
          key: "showTooltips",
          enabled: preferences.showTooltips,
        },
        {
          icon: Zap,
          label: "Compact Plan View",
          description: "Condensed task list display",
          key: "compactPlan",
          enabled: preferences.compactPlan,
        },
      ],
    },
    {
      title: "INTERFACE",
      items: [
        {
          icon: Moon,
          label: "Dark Mode",
          description: "Always enabled for RAGLOX",
          key: null,
          enabled: true,
          disabled: true,
        },
        {
          icon: Volume2,
          label: "Sound Effects",
          description: "Audio feedback for events",
          key: null,
          enabled: false,
        },
        {
          icon: Globe,
          label: "Language",
          description: "English (US)",
          key: null,
          action: true,
        },
      ],
    },
  ];

  return (
    <div className="space-y-6">
      {settingsSections.map((section) => (
        <div key={section.title}>
          <h3 className="text-xs font-medium mb-3" style={{ color: "#888888" }}>
            {section.title}
          </h3>
          <div className="space-y-1">
            {section.items.map((item) => (
              <div
                key={item.label}
                className={cn(
                  "flex items-center gap-3 px-3 py-3 rounded-lg transition-colors",
                  item.disabled && "opacity-50"
                )}
                style={{ background: "rgba(255, 255, 255, 0.02)" }}
              >
                <div
                  className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background: "rgba(74, 158, 255, 0.1)" }}
                >
                  <item.icon className="w-4 h-4" style={{ color: "#4a9eff" }} />
                </div>
                <div className="flex-1 min-w-0">
                  <span className="text-sm block" style={{ color: "#e8e8e8" }}>
                    {item.label}
                  </span>
                  <span className="text-xs" style={{ color: "#666666" }}>
                    {item.description}
                  </span>
                </div>
                {item.key && onToggle && !item.disabled ? (
                  <Switch
                    checked={item.enabled}
                    onCheckedChange={() => onToggle(item.key!)}
                    className="data-[state=checked]:bg-[#4a9eff]"
                  />
                ) : item.action ? (
                  <ChevronRight className="w-4 h-4" style={{ color: "#666666" }} />
                ) : (
                  <div
                    className="w-8 h-5 rounded-full flex items-center justify-center"
                    style={{ background: item.enabled ? "#4a9eff" : "#2a2a2a" }}
                  >
                    {item.enabled && <Check className="w-3 h-3 text-white" />}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Keyboard Shortcuts */}
      <div>
        <h3 className="text-xs font-medium mb-3" style={{ color: "#888888" }}>
          KEYBOARD SHORTCUTS
        </h3>
        <Button
          variant="ghost"
          className="w-full justify-start gap-3 text-left"
          style={{ color: "#e8e8e8" }}
        >
          <Keyboard className="w-4 h-4" style={{ color: "#4a9eff" }} />
          <span className="flex-1">View Shortcuts</span>
          <kbd
            className="px-2 py-0.5 rounded text-xs"
            style={{ background: "#2a2a2a", color: "#888888" }}
          >
            ?
          </kbd>
        </Button>
      </div>

      {/* Reset */}
      <div className="pt-4 border-t border-white/5">
        <Button
          variant="ghost"
          className="w-full justify-start gap-2 text-yellow-500 hover:text-yellow-400 hover:bg-yellow-500/10"
        >
          <RotateCcw className="w-4 h-4" />
          Reset to Defaults
        </Button>
      </div>
    </div>
  );
}

// ============================================
// Help Panel Content
// ============================================

function HelpContent() {
  const helpSections = [
    {
      title: "GETTING STARTED",
      items: [
        { icon: Target, label: "Mission Overview", link: "#" },
        { icon: Terminal, label: "Terminal Commands", link: "#" },
        { icon: Shield, label: "Security Best Practices", link: "#" },
      ],
    },
    {
      title: "DOCUMENTATION",
      items: [
        { icon: BookOpen, label: "User Guide", link: "#" },
        { icon: FileText, label: "API Reference", link: "#" },
        { icon: Zap, label: "Quick Start Tutorial", link: "#" },
      ],
    },
    {
      title: "SUPPORT",
      items: [
        { icon: HelpCircle, label: "FAQ", link: "#" },
        { icon: ExternalLink, label: "Community Forum", link: "#", external: true },
        { icon: ExternalLink, label: "Report a Bug", link: "#", external: true },
      ],
    },
  ];

  return (
    <div className="space-y-6">
      {helpSections.map((section) => (
        <div key={section.title}>
          <h3 className="text-xs font-medium mb-3" style={{ color: "#888888" }}>
            {section.title}
          </h3>
          <div className="space-y-1">
            {section.items.map((item) => (
              <a
                key={item.label}
                href={item.link}
                className="flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors group"
                style={{ color: "#e8e8e8" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255, 255, 255, 0.04)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <item.icon className="w-4 h-4" style={{ color: "#4a9eff" }} />
                <span className="flex-1 text-sm">{item.label}</span>
                {item.external && (
                  <ExternalLink className="w-3 h-3 opacity-50 group-hover:opacity-100" style={{ color: "#888888" }} />
                )}
              </a>
            ))}
          </div>
        </div>
      ))}

      {/* Version Info */}
      <div
        className="px-3 py-3 rounded-lg"
        style={{ background: "rgba(74, 158, 255, 0.05)" }}
      >
        <div className="flex items-center gap-2 mb-2">
          <Shield className="w-4 h-4" style={{ color: "#4a9eff" }} />
          <span className="text-sm font-medium" style={{ color: "#e8e8e8" }}>
            RAGLOX v3.0
          </span>
          <span
            className="px-2 py-0.5 rounded text-xs"
            style={{ background: "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)", color: "#000" }}
          >
            Pro
          </span>
        </div>
        <p className="text-xs" style={{ color: "#888888" }}>
          Autonomous Penetration Testing Agent with Human-in-the-Loop capabilities.
        </p>
      </div>
    </div>
  );
}

// ============================================
// Notifications Panel Content
// ============================================

interface NotificationsContentProps {
  events: EventCard[];
}

function NotificationsContent({ events }: NotificationsContentProps) {
  // Filter events for notifications
  const notifications = events.length > 0 
    ? events.slice(0, 10).map((event, index) => ({
        id: event.id || `notif-${index}`,
        type: event.type === "approval_request" ? "warning" : 
              event.status === "completed" ? "success" : "info",
        title: event.title,
        description: event.description || "",
        time: event.timestamp || new Date().toISOString(),
      }))
    : [
        {
          id: "1",
          type: "success",
          title: "Mission Started",
          description: "Reconnaissance phase initiated on target network.",
          time: new Date(Date.now() - 5 * 60000).toISOString(),
        },
        {
          id: "2",
          type: "warning",
          title: "Approval Required",
          description: "Exploit execution awaiting authorization.",
          time: new Date(Date.now() - 15 * 60000).toISOString(),
        },
        {
          id: "3",
          type: "info",
          title: "New Target Discovered",
          description: "Host 192.168.1.50 added to scan queue.",
          time: new Date(Date.now() - 30 * 60000).toISOString(),
        },
        {
          id: "4",
          type: "success",
          title: "Vulnerability Found",
          description: "CVE-2024-1234 detected on web server.",
          time: new Date(Date.now() - 45 * 60000).toISOString(),
        },
      ];

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case "success":
        return { icon: Check, color: "#4ade80", bg: "rgba(74, 222, 128, 0.15)" };
      case "warning":
        return { icon: AlertTriangle, color: "#f59e0b", bg: "rgba(245, 158, 11, 0.15)" };
      case "error":
        return { icon: X, color: "#ef4444", bg: "rgba(239, 68, 68, 0.15)" };
      default:
        return { icon: Info, color: "#4a9eff", bg: "rgba(74, 158, 255, 0.15)" };
    }
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now.getTime() - date.getTime()) / 60000);
    
    if (diff < 1) return "Just now";
    if (diff < 60) return `${diff} min ago`;
    if (diff < 1440) return `${Math.floor(diff / 60)} hr ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="space-y-4">
      {/* Header Actions */}
      <div className="flex items-center justify-between">
        <span className="text-xs" style={{ color: "#888888" }}>
          {notifications.length} notifications
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="text-xs h-7 px-2"
          style={{ color: "#4a9eff" }}
        >
          Mark all read
        </Button>
      </div>

      {/* Notifications List */}
      <div className="space-y-2">
        {notifications.map((notification) => {
          const { icon: NotifIcon, color, bg } = getNotificationIcon(notification.type);
          return (
            <div
              key={notification.id}
              className="flex gap-3 p-3 rounded-lg transition-colors cursor-pointer"
              style={{ background: "rgba(255, 255, 255, 0.02)" }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255, 255, 255, 0.04)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "rgba(255, 255, 255, 0.02)")}
            >
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                style={{ background: bg }}
              >
                <NotifIcon className="w-4 h-4" style={{ color }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-sm font-medium" style={{ color: "#e8e8e8" }}>
                    {notification.title}
                  </span>
                  <span className="text-xs shrink-0" style={{ color: "#666666" }}>
                    {formatTime(notification.time)}
                  </span>
                </div>
                <p className="text-xs mt-0.5 line-clamp-2" style={{ color: "#888888" }}>
                  {notification.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Empty State */}
      {notifications.length === 0 && (
        <div className="text-center py-8">
          <Bell className="w-8 h-8 mx-auto mb-2" style={{ color: "#666666" }} />
          <p className="text-sm" style={{ color: "#888888" }}>
            No notifications yet
          </p>
        </div>
      )}

      {/* View All */}
      <Button
        variant="outline"
        className="w-full"
        style={{
          background: "transparent",
          borderColor: "rgba(255, 255, 255, 0.1)",
          color: "#888888",
        }}
      >
        View All Notifications
      </Button>
    </div>
  );
}

export default UtilityPanel;
