// RAGLOX v3.0 - Missions Management Page
// Full integration with backend API for mission management

import React, { FormEvent, useEffect, useState } from "react";
import { useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Shield, 
  Target, 
  Zap, 
  Plus,
  Clock,
  Activity,
  Play,
  Pause,
  Square,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Loader2,
  ChevronRight,
  Search,
  Filter,
  Bug,
  Key,
  Terminal
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { missionApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { Mission, MissionStatistics, MissionStatus } from "@/types";

// Mission status colors and icons
const statusConfig: Record<string, { color: string; icon: typeof Activity; label: string }> = {
  created: { color: "bg-gray-500", icon: Clock, label: "Created" },
  starting: { color: "bg-blue-500", icon: Loader2, label: "Starting" },
  running: { color: "bg-green-500", icon: Activity, label: "Running" },
  paused: { color: "bg-yellow-500", icon: Pause, label: "Paused" },
  waiting_for_approval: { color: "bg-orange-500", icon: AlertCircle, label: "Awaiting Approval" },
  completing: { color: "bg-blue-500", icon: Loader2, label: "Completing" },
  completed: { color: "bg-emerald-500", icon: CheckCircle, label: "Completed" },
  failed: { color: "bg-red-500", icon: AlertCircle, label: "Failed" },
  cancelled: { color: "bg-gray-500", icon: Square, label: "Cancelled" },
  archived: { color: "bg-gray-600", icon: CheckCircle, label: "Archived" },
};

interface MissionWithDetails extends Partial<Mission> {
  mission_id: string;
  statistics?: MissionStatistics;
}

export default function Missions() {
  const [, setLocation] = useLocation();
  const [missions, setMissions] = useState<MissionWithDetails[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  
  // New mission form state
  const [newMission, setNewMission] = useState({
    name: "",
    description: "",
    scope: "",
    goals: "",
  });

  useEffect(() => {
    loadMissions();
  }, []);

  const loadMissions = async () => {
    setIsLoading(true);
    try {
      // Get list of mission IDs
      const missionIds = await missionApi.list();
      
      // Fetch details for each mission
      const missionsWithDetails = await Promise.all(
        missionIds.map(async (id) => {
          try {
            const details = await missionApi.get(id);
            const stats = await missionApi.stats(id).catch(() => undefined);
            return { 
              ...details, 
              mission_id: id,
              statistics: stats 
            } as MissionWithDetails;
          } catch (error) {
            // If we can't get details, return minimal info
            return { mission_id: id } as MissionWithDetails;
          }
        })
      );
      
      setMissions(missionsWithDetails);
    } catch (error) {
      console.error("Failed to load missions:", error);
      toast.error("Failed to load missions", {
        description: "Could not connect to the backend server",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateMission = async (event?: FormEvent<HTMLFormElement> | React.MouseEvent<HTMLButtonElement>) => {
    // Prevent default form submission behavior
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }
    
    console.log("[Missions] handleCreateMission called", newMission);

    const trimmedName = newMission.name.trim();
    const trimmedScope = newMission.scope.trim();

    if (!trimmedName || !trimmedScope) {
      console.log("[Missions] Missing required fields", { trimmedName, trimmedScope });
      toast.error("Missing required fields", {
        description: "Please provide mission name and scope",
      });
      return;
    }

    // Prevent double submission
    if (isCreating) {
      console.log("[Missions] Already creating mission, ignoring duplicate call");
      return;
    }

    setIsCreating(true);
    try {
      console.log("[Missions] Sending create mission request...");
      const scopeArray = trimmedScope
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      const goalsArray = newMission.goals
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      
      const response = await missionApi.create({
        name: trimmedName,
        description: newMission.description?.trim() || undefined,
        scope: scopeArray,
        goals: goalsArray.length > 0 ? goalsArray : ["reconnaissance"],
      });

      console.log("[Missions] Mission created", response);
      toast.success("Mission created", {
        description: `Mission "${trimmedName}" created successfully`,
      });

      setIsCreateDialogOpen(false);
      setNewMission({ name: "", description: "", scope: "", goals: "" });
      
      // Navigate to the new mission
      setLocation(`/operations/${response.mission_id}`);
    } catch (error) {
      console.error("Failed to create mission:", error);
      toast.error("Failed to create mission", {
        description: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      setIsCreating(false);
    }
  };

  const handleMissionAction = async (missionId: string, action: "start" | "pause" | "resume" | "stop") => {
    try {
      const actionMap = {
        start: missionApi.start,
        pause: missionApi.pause,
        resume: missionApi.resume,
        stop: missionApi.stop,
      };

      await actionMap[action](missionId);
      toast.success(`Mission ${action}ed`, {
        description: `Mission operation completed successfully`,
      });
      loadMissions();
    } catch (error) {
      console.error(`Failed to ${action} mission:`, error);
      toast.error(`Failed to ${action} mission`, {
        description: error instanceof Error ? error.message : "Unknown error",
      });
    }
  };

  // Filter missions
  const filteredMissions = missions.filter((mission) => {
    const matchesSearch = !searchQuery || 
      mission.mission_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (mission.name?.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesStatus = statusFilter === "all" || 
      mission.status === statusFilter;
    
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card sticky top-0 z-50">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-2 cursor-pointer" onClick={() => setLocation("/")}>
            <Shield className="w-8 h-8 text-primary" />
            <span className="font-bold text-xl">RAGLOX</span>
            <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded ml-2">
              v3.0
            </span>
          </div>
          <nav className="flex items-center gap-4">
            <Button variant="ghost" onClick={() => setLocation("/")}>
              Home
            </Button>
            <Button variant="ghost" className="text-primary" onClick={() => setLocation("/missions")}>
              Missions
            </Button>
            <Button variant="ghost" onClick={() => setLocation("/knowledge")}>
              Knowledge
            </Button>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="container py-8">
        {/* Page Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold">Missions</h1>
            <p className="text-muted-foreground mt-1">
              Manage and monitor your security operations
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Button variant="outline" onClick={loadMissions} className="gap-2">
              <RefreshCw className="w-4 h-4" />
              Refresh
            </Button>
            <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
              <DialogTrigger asChild>
                <Button className="gap-2">
                  <Plus className="w-4 h-4" />
                  New Mission
                </Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-lg">
                <form onSubmit={handleCreateMission} className="space-y-4">
                  <DialogHeader>
                    <DialogTitle>Create New Mission</DialogTitle>
                    <DialogDescription>
                      Configure a new security operation mission
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 py-4">
                    <div className="space-y-2">
                      <Label htmlFor="name">Mission Name *</Label>
                      <Input
                        id="name"
                        placeholder="Internal Network Assessment"
                        value={newMission.name}
                        onChange={(e) => setNewMission({ ...newMission, name: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="description">Description</Label>
                      <Textarea
                        id="description"
                        placeholder="Describe the mission objectives..."
                        value={newMission.description}
                        onChange={(e) => setNewMission({ ...newMission, description: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="scope">Scope * (CIDRs, IPs, domains - one per line)</Label>
                      <Textarea
                        id="scope"
                        placeholder="192.168.1.0/24&#10;10.0.0.1&#10;example.com"
                        value={newMission.scope}
                        onChange={(e) => setNewMission({ ...newMission, scope: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="goals">Goals (one per line)</Label>
                      <Textarea
                        id="goals"
                        placeholder="domain_admin&#10;data_exfil&#10;persistence"
                        value={newMission.goals}
                        onChange={(e) => setNewMission({ ...newMission, goals: e.target.value })}
                      />
                    </div>
                  </div>
                  <DialogFooter>
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => setIsCreateDialogOpen(false)}
                    >
                      Cancel
                    </Button>
                    <Button 
                      type="submit" 
                      disabled={isCreating}
                      onClick={(e) => {
                        console.log("[Missions] Create Mission button clicked");
                        handleCreateMission(e);
                      }}
                    >
                      {isCreating && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                      Create Mission
                    </Button>
                  </DialogFooter>
                </form>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-4 mb-6">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search missions..."
              className="pl-9"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-48">
              <Filter className="w-4 h-4 mr-2" />
              <SelectValue placeholder="Filter by status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Statuses</SelectItem>
              <SelectItem value="created">Created</SelectItem>
              <SelectItem value="running">Running</SelectItem>
              <SelectItem value="paused">Paused</SelectItem>
              <SelectItem value="waiting_for_approval">Awaiting Approval</SelectItem>
              <SelectItem value="completed">Completed</SelectItem>
              <SelectItem value="failed">Failed</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Missions Grid */}
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 animate-spin text-primary" />
            <span className="ml-3 text-muted-foreground">Loading missions...</span>
          </div>
        ) : filteredMissions.length === 0 ? (
          <Card className="text-center py-16">
            <CardContent>
              <Target className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
              <h3 className="text-lg font-semibold mb-2">No missions found</h3>
              <p className="text-muted-foreground mb-6">
                {searchQuery || statusFilter !== "all"
                  ? "Try adjusting your filters"
                  : "Create your first mission to get started"}
              </p>
              <Button onClick={() => setIsCreateDialogOpen(true)}>
                <Plus className="w-4 h-4 mr-2" />
                Create Mission
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <AnimatePresence>
              {filteredMissions.map((mission, index) => (
                <motion.div
                  key={mission.mission_id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ delay: index * 0.05 }}
                >
                  <MissionCard
                    mission={mission}
                    onClick={() => setLocation(`/operations/${mission.mission_id}`)}
                    onAction={handleMissionAction}
                  />
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </main>
    </div>
  );
}

// Mission Card Component
interface MissionCardProps {
  mission: MissionWithDetails;
  onClick: () => void;
  onAction: (missionId: string, action: "start" | "pause" | "resume" | "stop") => void;
}

function MissionCard({ mission, onClick, onAction }: MissionCardProps) {
  const status = (mission.status || "created") as string;
  const config = statusConfig[status] || statusConfig.created;
  const StatusIcon = config.icon;

  const stats = mission.statistics || {
    targets_discovered: 0,
    vulns_found: 0,
    creds_harvested: 0,
    sessions_established: 0,
    goals_achieved: 0,
    goals_total: 0,
  };

  const canStart = status === "created" || status === "paused";
  const canPause = status === "running";
  const canStop = status === "running" || status === "paused" || status === "waiting_for_approval";

  return (
    <Card 
      className="cursor-pointer hover:border-primary/50 transition-all duration-200 group"
      onClick={onClick}
    >
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <CardTitle className="text-base font-medium truncate group-hover:text-primary transition-colors">
              {mission.name || `Mission ${mission.mission_id.slice(0, 8)}...`}
            </CardTitle>
            <CardDescription className="text-xs mt-1 truncate">
              {mission.mission_id}
            </CardDescription>
          </div>
          <Badge 
            variant="outline" 
            className={cn(
              "ml-2 shrink-0",
              config.color === "bg-green-500" && "border-green-500/50 text-green-500",
              config.color === "bg-yellow-500" && "border-yellow-500/50 text-yellow-500",
              config.color === "bg-red-500" && "border-red-500/50 text-red-500",
              config.color === "bg-blue-500" && "border-blue-500/50 text-blue-500",
              config.color === "bg-orange-500" && "border-orange-500/50 text-orange-500",
            )}
          >
            <StatusIcon className={cn(
              "w-3 h-3 mr-1",
              status === "starting" || status === "completing" ? "animate-spin" : ""
            )} />
            {config.label}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        {/* Stats Grid */}
        <div className="grid grid-cols-4 gap-2 mb-4">
          <div className="text-center p-2 rounded-lg bg-muted/50">
            <Target className="w-4 h-4 mx-auto mb-1 text-blue-400" />
            <div className="text-sm font-semibold">{stats.targets_discovered}</div>
            <div className="text-[10px] text-muted-foreground">Targets</div>
          </div>
          <div className="text-center p-2 rounded-lg bg-muted/50">
            <Bug className="w-4 h-4 mx-auto mb-1 text-red-400" />
            <div className="text-sm font-semibold">{stats.vulns_found}</div>
            <div className="text-[10px] text-muted-foreground">Vulns</div>
          </div>
          <div className="text-center p-2 rounded-lg bg-muted/50">
            <Key className="w-4 h-4 mx-auto mb-1 text-yellow-400" />
            <div className="text-sm font-semibold">{stats.creds_harvested}</div>
            <div className="text-[10px] text-muted-foreground">Creds</div>
          </div>
          <div className="text-center p-2 rounded-lg bg-muted/50">
            <Terminal className="w-4 h-4 mx-auto mb-1 text-green-400" />
            <div className="text-sm font-semibold">{stats.sessions_established}</div>
            <div className="text-[10px] text-muted-foreground">Sessions</div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-border">
          <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
            {canStart && (
              <Button 
                size="sm" 
                variant="ghost" 
                className="h-8 px-2"
                onClick={(e) => {
                  e.stopPropagation();
                  onAction(mission.mission_id, status === "paused" ? "resume" : "start");
                }}
              >
                <Play className="w-4 h-4 text-green-500" />
              </Button>
            )}
            {canPause && (
              <Button 
                size="sm" 
                variant="ghost" 
                className="h-8 px-2"
                onClick={(e) => {
                  e.stopPropagation();
                  onAction(mission.mission_id, "pause");
                }}
              >
                <Pause className="w-4 h-4 text-yellow-500" />
              </Button>
            )}
            {canStop && (
              <Button 
                size="sm" 
                variant="ghost" 
                className="h-8 px-2"
                onClick={(e) => {
                  e.stopPropagation();
                  onAction(mission.mission_id, "stop");
                }}
              >
                <Square className="w-4 h-4 text-red-500" />
              </Button>
            )}
          </div>
          <Button size="sm" variant="ghost" className="h-8 gap-1">
            Open
            <ChevronRight className="w-4 h-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
