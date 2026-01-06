// RAGLOX v3.0 - App Layout Component
// Main layout wrapper with Enhanced Sidebar and Header
// Professional enterprise-grade design

import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import {
  ChevronRight,
  Home,
  Bell,
  Search,
  Command,
  Activity,
  AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { EnhancedSidebar } from "@/components/manus/EnhancedSidebar";
import { useMissionStore } from "@/stores/missionStore";
import { useAuthStore } from "@/stores/authStore";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { QuickNavigation } from "@/components/QuickNavigation";

// ============================================
// Types
// ============================================

interface AppLayoutProps {
  children: React.ReactNode;
  showHeader?: boolean;
  showSidebar?: boolean;
  fullWidth?: boolean;
  className?: string;
}

interface BreadcrumbItem {
  label: string;
  path?: string;
}

// ============================================
// Route Labels Map
// ============================================

const routeLabels: Record<string, string> = {
  "": "Home",
  home: "Home",
  missions: "Missions",
  operations: "Operations",
  infrastructure: "Infrastructure",
  exploitation: "Exploitation",
  workflow: "Workflow",
  tools: "Tools",
  knowledge: "Knowledge Base",
  security: "Security",
  reports: "Reports",
  settings: "Settings",
};

// ============================================
// App Layout Component
// ============================================

export function AppLayout({
  children,
  showHeader = true,
  showSidebar = true,
  fullWidth = false,
  className,
}: AppLayoutProps) {
  const [location, setLocation] = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [showCommandPalette, setShowCommandPalette] = useState(false);

  // Store state
  const { approvals, isConnected, mission } = useMissionStore();
  const { user } = useAuthStore();

  // Calculate pending approvals
  const pendingApprovals = approvals.filter(
    (a) => new Date(a.expires_at) > new Date()
  ).length;

  // Generate breadcrumbs from location
  const getBreadcrumbs = (): BreadcrumbItem[] => {
    const parts = location.split("/").filter(Boolean);
    const breadcrumbs: BreadcrumbItem[] = [{ label: "Home", path: "/" }];

    let currentPath = "";
    for (const part of parts) {
      currentPath += `/${part}`;
      const label = routeLabels[part] || part;
      breadcrumbs.push({ label, path: currentPath });
    }

    return breadcrumbs;
  };

  const breadcrumbs = getBreadcrumbs();

  // Keyboard shortcut for command palette
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setShowCommandPalette(true);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <div className="flex h-screen overflow-hidden bg-[#0a0a0a]">
      {/* Sidebar */}
      {showSidebar && (
        <EnhancedSidebar
          collapsed={sidebarCollapsed}
          onCollapsedChange={setSidebarCollapsed}
        />
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header */}
        {showHeader && (
          <header
            className="h-14 flex items-center justify-between px-4 flex-shrink-0"
            style={{
              background: "#0f0f0f",
              borderBottom: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            {/* Left: Breadcrumbs */}
            <div className="flex items-center gap-1 text-sm overflow-hidden">
              {breadcrumbs.map((crumb, index) => (
                <div key={index} className="flex items-center">
                  {index > 0 && (
                    <ChevronRight className="w-4 h-4 text-gray-600 mx-1 flex-shrink-0" />
                  )}
                  {crumb.path && index < breadcrumbs.length - 1 ? (
                    <button
                      onClick={() => setLocation(crumb.path!)}
                      className="text-gray-400 hover:text-white transition-colors truncate"
                    >
                      {crumb.label}
                    </button>
                  ) : (
                    <span className="text-white font-medium truncate">
                      {crumb.label}
                    </span>
                  )}
                </div>
              ))}
            </div>

            {/* Right: Actions */}
            <div className="flex items-center gap-2">
              {/* Command Palette Trigger */}
              <button
                onClick={() => setShowCommandPalette(true)}
                className={cn(
                  "flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm",
                  "bg-white/5 hover:bg-white/10 transition-colors",
                  "text-gray-400 hover:text-white"
                )}
              >
                <Search className="w-4 h-4" />
                <span className="hidden md:inline">Search</span>
                <kbd className="hidden md:flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded bg-white/10">
                  <Command className="w-3 h-3" />K
                </kbd>
              </button>

              {/* Connection Status */}
              <div
                className={cn(
                  "flex items-center gap-1.5 px-2 py-1 rounded-md text-xs",
                  isConnected
                    ? "text-green-400 bg-green-500/10"
                    : "text-gray-500 bg-white/5"
                )}
              >
                <Activity className="w-3 h-3" />
                <span className="hidden sm:inline">
                  {isConnected ? "Connected" : "Offline"}
                </span>
              </div>

              {/* Notifications */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="relative h-8 w-8"
                  >
                    <Bell className="w-4 h-4 text-gray-400" />
                    {pendingApprovals > 0 && (
                      <span className="absolute -top-0.5 -right-0.5 w-4 h-4 rounded-full bg-red-500 text-white text-[10px] flex items-center justify-center font-bold">
                        {pendingApprovals}
                      </span>
                    )}
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-80">
                  <DropdownMenuLabel className="flex items-center justify-between">
                    Notifications
                    {pendingApprovals > 0 && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-400">
                        {pendingApprovals} pending
                      </span>
                    )}
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {pendingApprovals > 0 ? (
                    <>
                      {approvals.slice(0, 3).map((approval) => (
                        <DropdownMenuItem
                          key={approval.action_id}
                          className="flex items-start gap-2 py-3"
                          onClick={() => setLocation("/operations")}
                        >
                          <AlertTriangle className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate">
                              Approval Required
                            </p>
                            <p className="text-xs text-muted-foreground truncate">
                              {approval.action_description}
                            </p>
                          </div>
                        </DropdownMenuItem>
                      ))}
                      {pendingApprovals > 3 && (
                        <DropdownMenuItem
                          className="text-center text-sm text-blue-400"
                          onClick={() => setLocation("/operations")}
                        >
                          View all {pendingApprovals} approvals
                        </DropdownMenuItem>
                      )}
                    </>
                  ) : (
                    <div className="py-8 text-center text-sm text-muted-foreground">
                      No new notifications
                    </div>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>

              {/* User Menu */}
              {user && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      className="h-8 px-2 gap-2"
                    >
                      <div className="w-6 h-6 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                        <span className="text-[10px] font-bold text-white">
                          {user.full_name?.[0]?.toUpperCase() || user.email?.[0]?.toUpperCase() || "U"}
                        </span>
                      </div>
                      <span className="hidden md:inline text-sm text-gray-300">
                        {user.full_name || user.email}
                      </span>
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuLabel>
                      <div>
                        <p className="font-medium">{user.full_name}</p>
                        <p className="text-xs text-muted-foreground">
                          {user.email}
                        </p>
                      </div>
                    </DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => setLocation("/settings")}>
                      Settings
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      className="text-red-400"
                      onClick={async () => {
                        await useAuthStore.getState().logout();
                        setLocation("/login");
                      }}
                    >
                      Log out
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </div>
          </header>
        )}

        {/* Page Content */}
        <main
          className={cn(
            "flex-1 overflow-auto",
            !fullWidth && "p-0",
            className
          )}
        >
          {children}
        </main>
      </div>

      {/* Quick Navigation Command Palette */}
      <QuickNavigation
        open={showCommandPalette}
        onOpenChange={setShowCommandPalette}
      />
    </div>
  );
}

export default AppLayout;
