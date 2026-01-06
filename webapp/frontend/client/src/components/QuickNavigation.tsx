// RAGLOX v3.0 - Quick Navigation Component
// Command palette for fast navigation between pages

import { useCallback, useEffect, useState } from "react";
import { useLocation } from "wouter";
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
  LayoutDashboard,
  Search,
  Zap,
} from "lucide-react";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";

// Navigation items with icons and shortcuts
const navigationItems = [
  {
    group: "Main",
    items: [
      { id: "dashboard", label: "Dashboard", icon: LayoutDashboard, path: "/dashboard", shortcut: "D" },
      { id: "missions", label: "Missions", icon: Target, path: "/missions", shortcut: "M" },
      { id: "operations", label: "Operations", icon: Terminal, path: "/operations", shortcut: "O" },
    ],
  },
  {
    group: "Security",
    items: [
      { id: "infrastructure", label: "Infrastructure", icon: Server, path: "/infrastructure" },
      { id: "exploitation", label: "Exploitation", icon: Bug, path: "/exploitation" },
      { id: "workflow", label: "Workflow", icon: GitBranch, path: "/workflow" },
    ],
  },
  {
    group: "Resources",
    items: [
      { id: "tools", label: "Tools", icon: Wrench, path: "/tools" },
      { id: "knowledge", label: "Knowledge Base", icon: BookOpen, path: "/knowledge", shortcut: "K" },
      { id: "reports", label: "Reports", icon: FileText, path: "/reports" },
    ],
  },
  {
    group: "System",
    items: [
      { id: "security", label: "Security", icon: Shield, path: "/security" },
      { id: "settings", label: "Settings", icon: Settings, path: "/settings", shortcut: "S" },
    ],
  },
];

// Quick actions
const quickActions = [
  { id: "new-mission", label: "Create New Mission", icon: Zap, action: "create-mission" },
];

interface QuickNavigationProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function QuickNavigation({ open, onOpenChange }: QuickNavigationProps) {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");

  // Handle navigation
  const handleSelect = useCallback(
    (path: string) => {
      setLocation(path);
      onOpenChange(false);
      setSearch("");
    },
    [setLocation, onOpenChange]
  );

  // Handle quick actions
  const handleAction = useCallback(
    (action: string) => {
      switch (action) {
        case "create-mission":
          setLocation("/missions");
          // Could trigger a dialog open state here
          break;
      }
      onOpenChange(false);
      setSearch("");
    },
    [setLocation, onOpenChange]
  );

  // Keyboard shortcuts for direct navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!open) return;

      // Check for shortcut keys when dialog is open
      if (e.altKey) {
        switch (e.key.toLowerCase()) {
          case "d":
            e.preventDefault();
            handleSelect("/dashboard");
            break;
          case "m":
            e.preventDefault();
            handleSelect("/missions");
            break;
          case "o":
            e.preventDefault();
            handleSelect("/operations");
            break;
          case "k":
            e.preventDefault();
            handleSelect("/knowledge");
            break;
          case "s":
            e.preventDefault();
            handleSelect("/settings");
            break;
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, handleSelect]);

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Quick Navigation"
      description="Search and navigate to any page"
    >
      <CommandInput
        placeholder="Search pages..."
        value={search}
        onValueChange={setSearch}
      />
      <CommandList>
        <CommandEmpty>
          <div className="flex flex-col items-center gap-2 py-4">
            <Search className="w-8 h-8 text-muted-foreground" />
            <p>No results found.</p>
            <p className="text-xs text-muted-foreground">
              Try searching for "missions", "settings", or "operations"
            </p>
          </div>
        </CommandEmpty>

        {/* Quick Actions */}
        <CommandGroup heading="Quick Actions">
          {quickActions.map((action) => (
            <CommandItem
              key={action.id}
              value={action.label}
              onSelect={() => handleAction(action.action)}
              className="cursor-pointer"
            >
              <action.icon className="mr-2 h-4 w-4 text-primary" />
              <span>{action.label}</span>
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandSeparator />

        {/* Navigation Groups */}
        {navigationItems.map((group) => (
          <CommandGroup key={group.group} heading={group.group}>
            {group.items.map((item) => (
              <CommandItem
                key={item.id}
                value={`${item.label} ${item.id}`}
                onSelect={() => handleSelect(item.path)}
                className="cursor-pointer"
              >
                <item.icon className="mr-2 h-4 w-4" />
                <span>{item.label}</span>
                {item.shortcut && (
                  <CommandShortcut>Alt+{item.shortcut}</CommandShortcut>
                )}
              </CommandItem>
            ))}
          </CommandGroup>
        ))}
      </CommandList>

      {/* Footer hint */}
      <div className="border-t border-border px-3 py-2 text-xs text-muted-foreground flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span>
            <kbd className="px-1.5 py-0.5 rounded bg-muted text-[10px]">↑↓</kbd> Navigate
          </span>
          <span>
            <kbd className="px-1.5 py-0.5 rounded bg-muted text-[10px]">Enter</kbd> Select
          </span>
          <span>
            <kbd className="px-1.5 py-0.5 rounded bg-muted text-[10px]">Esc</kbd> Close
          </span>
        </div>
        <span className="text-primary">RAGLOX v3.0</span>
      </div>
    </CommandDialog>
  );
}

export default QuickNavigation;
