// RAGLOX v3.0 - Sidebar Component (Manus Style)
// Enhanced with descriptive labels and actionable utilities

import { useLocation } from "wouter";
import {
  PenSquare,
  FileText,
  Settings,
  HelpCircle,
  Bell,
  Home,
  BookOpen,
  LogOut,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

export type SidebarUtility = "files" | "settings" | "help" | "notifications";

interface SidebarProps {
  activeItem?: string;
  activeUtility?: SidebarUtility | null;
  onItemClick?: (item: string) => void;
  className?: string;
}

export function Sidebar({
  activeItem = "home",
  activeUtility = null,
  onItemClick,
  className,
}: SidebarProps) {
  const [, setLocation] = useLocation();

  const interactiveUtilities: SidebarUtility[] = ["files", "settings", "help", "notifications"];

  const handleNavigation = (itemId: string) => {
    switch (itemId) {
      case "home":
        setLocation("/");
        onItemClick?.("close");
        break;
      case "new":
        setLocation("/?new=true");
        toast.success("Opening new mission wizard on Home page");
        onItemClick?.("close");
        break;
      case "knowledge":
        setLocation("/knowledge");
        onItemClick?.("close");
        break;
      case "logout":
        localStorage.removeItem("raglox_auth_token");
        localStorage.removeItem("raglox_auth_user");
        setLocation("/");
        toast.success("Logged out successfully");
        onItemClick?.("close");
        break;
      default:
        if (interactiveUtilities.includes(itemId as SidebarUtility)) {
          onItemClick?.(itemId);
        } else {
          onItemClick?.("close");
        }
    }
  };

  const topItems = [
    { id: "home", icon: Home, label: "Home" },
    { id: "new", icon: PenSquare, label: "New Mission" },
    { id: "knowledge", icon: BookOpen, label: "Knowledge" },
    { id: "files", icon: FileText, label: "Files" },
  ];

  const bottomItems = [
    { id: "settings", icon: Settings, label: "Settings" },
    { id: "help", icon: HelpCircle, label: "Help" },
    { id: "notifications", icon: Bell, label: "Alerts" },
    { id: "logout", icon: LogOut, label: "Logout" },
  ];

  const isItemActive = (itemId: string) => {
    if (interactiveUtilities.includes(itemId as SidebarUtility)) {
      return activeUtility === itemId;
    }
    return activeItem === itemId;
  };

  return (
    <nav
      className={cn(
        "flex h-full w-[108px] flex-col justify-between py-6",
        className
      )}
      style={{
        background: "#141414",
        borderRight: "1px solid rgba(255, 255, 255, 0.06)",
        boxShadow: "4px 0 16px rgba(0, 0, 0, 0.1)",
      }}
      aria-label="Primary"
    >
      <div className="flex flex-col items-center gap-3">
        {topItems.map((item) => (
          <SidebarIcon
            key={item.id}
            icon={item.icon}
            label={item.label}
            isActive={isItemActive(item.id)}
            onClick={() => handleNavigation(item.id)}
          />
        ))}
      </div>

      <div className="flex flex-col items-center gap-3">
        {bottomItems.map((item) => (
          <SidebarIcon
            key={item.id}
            icon={item.icon}
            label={item.label}
            isActive={isItemActive(item.id)}
            onClick={() => handleNavigation(item.id)}
          />
        ))}
      </div>
    </nav>
  );
}

interface SidebarIconProps {
  icon: React.ElementType;
  label: string;
  isActive?: boolean;
  onClick?: () => void;
}

function SidebarIcon({ icon: Icon, label, isActive, onClick }: SidebarIconProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "w-24 rounded-xl px-3 py-3 text-xs font-medium transition-colors duration-200",
        "flex flex-col items-center gap-2",
        isActive ? "bg-[#1f1f1f] text-[#4a9eff]" : "text-[#c5c5c5] hover:bg-[#1f1f1f] hover:text-[#4a9eff]"
      )}
      aria-label={label}
    >
      <Icon className="h-5 w-5" strokeWidth={1.6} />
      <span className="text-center leading-tight">{label}</span>
    </button>
  );
}

export default Sidebar;
