// RAGLOX v3.0 - Enhanced Sidebar Component
// Professional enterprise-grade navigation with VSCode/Manus style
// Full integration with all routes

import { useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import {
  Home,
  Target,
  Terminal,
  Server,
  Bug,
  GitBranch,
  Wrench,
  BookOpen,
  Shield,
  FileText,
  Settings,
  HelpCircle,
  Bell,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Zap,
  Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { useState, useEffect } from "react";
import { useAuthStore } from "@/stores/authStore";
import { useMissionStore } from "@/stores/missionStore";

// ============================================
// Types
// ============================================

interface NavItem {
  id: string;
  icon: React.ElementType;
  label: string;
  path?: string;
  badge?: number | string;
  badgeColor?: string;
  isNew?: boolean;
  disabled?: boolean;
}

interface SidebarProps {
  collapsed?: boolean;
  onCollapsedChange?: (collapsed: boolean) => void;
  className?: string;
}

// ============================================
// Navigation Items
// ============================================

const mainNavItems: NavItem[] = [
  { id: "home", icon: Home, label: "Home", path: "/" },
  { id: "missions", icon: Target, label: "Missions", path: "/missions" },
  { id: "operations", icon: Terminal, label: "Operations", path: "/operations" },
  { id: "infrastructure", icon: Server, label: "Infrastructure", path: "/infrastructure" },
  { id: "exploitation", icon: Bug, label: "Exploitation", path: "/exploitation" },
  { id: "workflow", icon: GitBranch, label: "Workflow", path: "/workflow" },
  { id: "tools", icon: Wrench, label: "Tools", path: "/tools" },
  { id: "knowledge", icon: BookOpen, label: "Knowledge", path: "/knowledge" },
];

const bottomNavItems: NavItem[] = [
  { id: "settings", icon: Settings, label: "Settings", path: "/settings" },
  { id: "help", icon: HelpCircle, label: "Help" },
  { id: "logout", icon: LogOut, label: "Logout" },
];

// ============================================
// Enhanced Sidebar Component
// ============================================

export function EnhancedSidebar({
  collapsed: controlledCollapsed,
  onCollapsedChange,
  className,
}: SidebarProps) {
  const [location, setLocation] = useLocation();
  const [internalCollapsed, setInternalCollapsed] = useState(false);
  const [hoveredItem, setHoveredItem] = useState<string | null>(null);
  
  // Use controlled or internal state
  const collapsed = controlledCollapsed ?? internalCollapsed;
  const setCollapsed = onCollapsedChange ?? setInternalCollapsed;

  // Auth and Mission state
  const { logout, user } = useAuthStore();
  const { approvals, isConnected, mission } = useMissionStore();

  // Calculate badges
  const pendingApprovals = approvals.filter(a => 
    new Date(a.expires_at) > new Date()
  ).length;

  // Get active item based on location
  const getActiveItem = () => {
    if (location === "/") return "home";
    const path = location.split("/")[1];
    return path || "home";
  };

  const activeItem = getActiveItem();

  // Handle navigation
  const handleNavigation = async (item: NavItem) => {
    if (item.disabled) {
      toast.error(`${item.label} is coming soon`);
      return;
    }

    switch (item.id) {
      case "logout":
        await logout();
        toast.success("Logged out successfully");
        setLocation("/login");
        break;
      case "help":
        // Open help dialog or external docs
        window.open("https://github.com/HosamN-ALI/Ragloxv3", "_blank");
        break;
      default:
        if (item.path) {
          setLocation(item.path);
        }
    }
  };

  return (
    <motion.nav
      className={cn(
        "flex h-full flex-col justify-between py-4 relative",
        className
      )}
      initial={false}
      animate={{
        width: collapsed ? 64 : 200,
      }}
      transition={{ type: "spring", damping: 25, stiffness: 300 }}
      style={{
        background: "#0f0f0f",
        borderRight: "1px solid rgba(255, 255, 255, 0.06)",
      }}
    >
      {/* Logo / Brand */}
      <div className="px-3 mb-4">
        <div 
          className={cn(
            "flex items-center gap-2 px-2 py-2 rounded-lg cursor-pointer",
            "hover:bg-white/5 transition-colors"
          )}
          onClick={() => setLocation("/")}
        >
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center flex-shrink-0">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <AnimatePresence>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, width: 0 }}
                animate={{ opacity: 1, width: "auto" }}
                exit={{ opacity: 0, width: 0 }}
                className="overflow-hidden"
              >
                <span className="font-bold text-sm text-white whitespace-nowrap">
                  RAGLOX
                </span>
                <span className="text-[10px] text-gray-500 ml-1">v3.0</span>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Connection Status */}
      {!collapsed && (
        <motion.div 
          className="px-3 mb-3"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div 
            className="flex items-center gap-2 px-3 py-2 rounded-lg"
            style={{ background: "rgba(255,255,255,0.03)" }}
          >
            <div className="relative">
              <Activity className="w-4 h-4" style={{ color: isConnected ? "#4ade80" : "#888" }} />
              {isConnected && (
                <span 
                  className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full"
                  style={{ 
                    background: "#4ade80",
                    animation: "pulse 2s infinite"
                  }}
                />
              )}
            </div>
            <span className="text-xs" style={{ color: isConnected ? "#4ade80" : "#888" }}>
              {isConnected ? "Connected" : "Offline"}
            </span>
          </div>
        </motion.div>
      )}

      {/* Main Navigation */}
      <div className="flex-1 px-2 space-y-1 overflow-y-auto">
        {mainNavItems.map((item) => (
          <NavButton
            key={item.id}
            item={{
              ...item,
              badge: item.id === "operations" ? pendingApprovals : undefined,
              badgeColor: "#ef4444",
            }}
            isActive={activeItem === item.id}
            collapsed={collapsed}
            onHover={setHoveredItem}
            hoveredItem={hoveredItem}
            onClick={() => handleNavigation(item)}
          />
        ))}
      </div>

      {/* Bottom Navigation */}
      <div className="px-2 pt-2 border-t border-white/5 space-y-1">
        {bottomNavItems.map((item) => (
          <NavButton
            key={item.id}
            item={item}
            isActive={activeItem === item.id}
            collapsed={collapsed}
            onHover={setHoveredItem}
            hoveredItem={hoveredItem}
            onClick={() => handleNavigation(item)}
          />
        ))}
      </div>

      {/* User Info (when expanded) */}
      {!collapsed && user && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="px-3 pt-3 mt-2 border-t border-white/5"
        >
          <div className="flex items-center gap-2 px-2">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-gray-700 to-gray-800 flex items-center justify-center">
              <span className="text-xs font-medium text-white">
                {user.full_name?.[0]?.toUpperCase() || user.email?.[0]?.toUpperCase() || "U"}
              </span>
            </div>
            <div className="overflow-hidden">
              <p className="text-sm font-medium text-white truncate">
                {user.full_name || user.email}
              </p>
              <p className="text-[10px] text-gray-500 truncate">
                {user.email}
              </p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Collapse Toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className={cn(
          "absolute top-1/2 -translate-y-1/2 w-6 h-6 rounded-full",
          "flex items-center justify-center transition-all",
          "bg-[#1f1f1f] border border-white/10 hover:bg-[#2a2a2a]",
          collapsed ? "-right-3" : "-right-3"
        )}
      >
        {collapsed ? (
          <ChevronRight className="w-3 h-3 text-gray-400" />
        ) : (
          <ChevronLeft className="w-3 h-3 text-gray-400" />
        )}
      </button>
    </motion.nav>
  );
}

// ============================================
// Nav Button Component
// ============================================

interface NavButtonProps {
  item: NavItem;
  isActive: boolean;
  collapsed: boolean;
  onHover: (id: string | null) => void;
  hoveredItem: string | null;
  onClick: () => void;
}

function NavButton({
  item,
  isActive,
  collapsed,
  onHover,
  hoveredItem,
  onClick,
}: NavButtonProps) {
  const Icon = item.icon;
  const showTooltip = collapsed && hoveredItem === item.id;

  return (
    <div className="relative">
      <button
        type="button"
        onClick={onClick}
        onMouseEnter={() => onHover(item.id)}
        onMouseLeave={() => onHover(null)}
        className={cn(
          "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg",
          "transition-all duration-200 group relative",
          isActive
            ? "bg-white/10 text-white"
            : "text-gray-400 hover:bg-white/5 hover:text-white",
          item.disabled && "opacity-50 cursor-not-allowed"
        )}
      >
        {/* Active Indicator */}
        {isActive && (
          <motion.div
            layoutId="activeIndicator"
            className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 rounded-r-full"
            style={{ background: "#4a9eff" }}
          />
        )}

        {/* Icon */}
        <div className="relative flex-shrink-0">
          <Icon
            className={cn(
              "w-5 h-5 transition-colors",
              isActive ? "text-blue-400" : "group-hover:text-blue-400"
            )}
          />
          {/* Badge on Icon */}
          {collapsed && item.badge && (
            <span
              className="absolute -top-1 -right-1 min-w-[16px] h-4 rounded-full text-[10px] font-bold flex items-center justify-center text-white px-1"
              style={{ background: item.badgeColor || "#ef4444" }}
            >
              {item.badge}
            </span>
          )}
        </div>

        {/* Label (when expanded) */}
        <AnimatePresence>
          {!collapsed && (
            <motion.span
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: "auto" }}
              exit={{ opacity: 0, width: 0 }}
              className="text-sm font-medium whitespace-nowrap overflow-hidden"
            >
              {item.label}
            </motion.span>
          )}
        </AnimatePresence>

        {/* Badge (when expanded) */}
        {!collapsed && item.badge && (
          <span
            className="ml-auto min-w-[20px] h-5 rounded-full text-[10px] font-bold flex items-center justify-center text-white px-1.5"
            style={{ background: item.badgeColor || "#ef4444" }}
          >
            {item.badge}
          </span>
        )}

        {/* New Tag */}
        {!collapsed && item.isNew && (
          <span className="ml-auto text-[9px] font-bold text-green-400 bg-green-500/20 px-1.5 py-0.5 rounded">
            NEW
          </span>
        )}
      </button>

      {/* Tooltip (when collapsed) */}
      <AnimatePresence>
        {showTooltip && (
          <motion.div
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -10 }}
            className="absolute left-full top-1/2 -translate-y-1/2 ml-2 z-50"
          >
            <div
              className="px-3 py-2 rounded-lg text-sm font-medium text-white whitespace-nowrap flex items-center gap-2"
              style={{
                background: "#1f1f1f",
                border: "1px solid rgba(255,255,255,0.1)",
                boxShadow: "0 4px 24px rgba(0,0,0,0.4)",
              }}
            >
              {item.label}
              {item.badge && (
                <span
                  className="min-w-[18px] h-[18px] rounded-full text-[10px] font-bold flex items-center justify-center text-white px-1"
                  style={{ background: item.badgeColor || "#ef4444" }}
                >
                  {item.badge}
                </span>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ============================================
// CSS Keyframes (add to global styles)
// ============================================

const styles = `
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
`;

// Inject styles
if (typeof document !== "undefined") {
  const styleSheet = document.createElement("style");
  styleSheet.textContent = styles;
  document.head.appendChild(styleSheet);
}

export default EnhancedSidebar;
