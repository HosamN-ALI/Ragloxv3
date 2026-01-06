// RAGLOX v3.0 - Workflow Page
// Penetration Testing Workflow Engine with Phase Management
// Professional enterprise-grade design

import { useState, useEffect } from "react";
import { useParams } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import {
  GitBranch,
  Play,
  Pause,
  Square,
  RefreshCw,
  Check,
  Clock,
  AlertCircle,
  ChevronRight,
  Target,
  Shield,
  Key,
  Terminal,
  Loader2,
  Activity,
  Zap,
  FileText,
  Trash2,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  workflowApi,
  WORKFLOW_PHASES,
  getPhaseStatusColor,
  getPhaseProgress,
  formatDuration,
  type WorkflowStatus,
  type PhaseResult,
  type StartWorkflowRequest,
} from "@/lib/workflowApi";

// ============================================
// Phase Icons
// ============================================

const phaseIcons: Record<string, React.ElementType> = {
  initialization: Activity,
  strategic_planning: Target,
  reconnaissance: Shield,
  initial_access: Zap,
  post_exploitation: Key,
  lateral_movement: GitBranch,
  goal_achievement: Check,
  reporting: FileText,
  cleanup: Trash2,
};

// ============================================
// Workflow Page
// ============================================

export default function Workflow() {
  const params = useParams<{ missionId?: string }>();
  const [isLoading, setIsLoading] = useState(true);
  const [workflowStatus, setWorkflowStatus] = useState<WorkflowStatus | null>(null);
  const [phaseResults, setPhaseResults] = useState<PhaseResult[]>([]);
  const [isStartDialogOpen, setIsStartDialogOpen] = useState(false);
  const [isStarting, setIsStarting] = useState(false);

  // Start workflow form
  const [newWorkflow, setNewWorkflow] = useState<Partial<StartWorkflowRequest>>({
    mission_id: params.missionId || "",
    mission_goals: [],
    scope: [],
    stealth_level: "normal",
    max_duration_hours: 4,
    environment_type: "simulated",
  });

  // Temp form inputs
  const [goalsInput, setGoalsInput] = useState("");
  const [scopeInput, setScopeInput] = useState("");

  // Load workflow data
  useEffect(() => {
    if (params.missionId) {
      loadWorkflowData(params.missionId);
    } else {
      setIsLoading(false);
    }
  }, [params.missionId]);

  const loadWorkflowData = async (missionId: string) => {
    setIsLoading(true);
    try {
      const [status, phases] = await Promise.all([
        workflowApi.getStatus(missionId).catch(() => null),
        workflowApi.getPhases(missionId).catch(() => []),
      ]);

      if (status) setWorkflowStatus(status);
      if (phases) setPhaseResults(phases);
    } catch (error) {
      console.error("Failed to load workflow data:", error);
    } finally {
      setIsLoading(false);
    }
  };

  // Start workflow
  const handleStartWorkflow = async () => {
    if (!newWorkflow.mission_id) {
      toast.error("Please enter a mission ID");
      return;
    }

    // Parse goals and scope
    const goals = goalsInput.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    const scope = scopeInput.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);

    if (goals.length === 0) {
      toast.error("Please enter at least one goal");
      return;
    }
    if (scope.length === 0) {
      toast.error("Please enter at least one scope target");
      return;
    }

    setIsStarting(true);
    try {
      const status = await workflowApi.startWorkflow({
        mission_id: newWorkflow.mission_id,
        mission_goals: goals,
        scope: scope,
        stealth_level: newWorkflow.stealth_level as "low" | "normal" | "high",
        max_duration_hours: newWorkflow.max_duration_hours,
        environment_type: newWorkflow.environment_type as "simulated" | "ssh" | "vm",
      });

      setWorkflowStatus(status);
      setIsStartDialogOpen(false);
      toast.success("Workflow started successfully");

      // Start polling for updates
      pollWorkflowStatus(status.mission_id);
    } catch (error) {
      toast.error("Failed to start workflow");
    } finally {
      setIsStarting(false);
    }
  };

  // Poll for updates
  const pollWorkflowStatus = async (missionId: string) => {
    const interval = setInterval(async () => {
      try {
        const [status, phases] = await Promise.all([
          workflowApi.getStatus(missionId),
          workflowApi.getPhases(missionId),
        ]);

        setWorkflowStatus(status);
        setPhaseResults(phases);

        // Stop polling when completed or failed
        if (
          status.current_phase === "cleanup" &&
          phases.some((p) => p.phase === "cleanup" && p.status === "completed")
        ) {
          clearInterval(interval);
        }
      } catch (error) {
        clearInterval(interval);
      }
    }, 5000);
  };

  // Control handlers
  const handlePause = async () => {
    if (!workflowStatus) return;
    try {
      await workflowApi.pauseWorkflow(workflowStatus.mission_id);
      toast.info("Workflow paused");
      loadWorkflowData(workflowStatus.mission_id);
    } catch (error) {
      toast.error("Failed to pause workflow");
    }
  };

  const handleResume = async () => {
    if (!workflowStatus) return;
    try {
      await workflowApi.resumeWorkflow(workflowStatus.mission_id);
      toast.success("Workflow resumed");
      loadWorkflowData(workflowStatus.mission_id);
    } catch (error) {
      toast.error("Failed to resume workflow");
    }
  };

  const handleStop = async () => {
    if (!workflowStatus) return;
    try {
      await workflowApi.stopWorkflow(workflowStatus.mission_id);
      toast.info("Workflow stopped");
      loadWorkflowData(workflowStatus.mission_id);
    } catch (error) {
      toast.error("Failed to stop workflow");
    }
  };

  // Calculate progress
  const progress = workflowStatus ? getPhaseProgress(phaseResults) : 0;
  const currentPhaseIndex = workflowStatus
    ? WORKFLOW_PHASES.findIndex((p) => p.phase === workflowStatus.current_phase)
    : -1;

  return (
    <AppLayout>
      <div className="h-full flex flex-col">
        {/* Header */}
        <div
          className="px-6 py-4 flex items-center justify-between"
          style={{
            background: "#0f0f0f",
            borderBottom: "1px solid rgba(255,255,255,0.06)",
          }}
        >
          <div className="flex items-center gap-3">
            <GitBranch className="w-6 h-6 text-purple-400" />
            <div>
              <h1 className="text-xl font-semibold text-white">Workflow Engine</h1>
              <p className="text-sm text-gray-500">
                Automated Penetration Testing Phases
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {workflowStatus && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handlePause}
                  disabled={!workflowStatus}
                >
                  <Pause className="w-4 h-4 mr-2" />
                  Pause
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleResume}
                  disabled={!workflowStatus}
                >
                  <Play className="w-4 h-4 mr-2" />
                  Resume
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleStop}
                  disabled={!workflowStatus}
                  className="text-red-400 hover:text-red-300"
                >
                  <Square className="w-4 h-4 mr-2" />
                  Stop
                </Button>
              </>
            )}
            <Dialog open={isStartDialogOpen} onOpenChange={setIsStartDialogOpen}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Play className="w-4 h-4 mr-2" />
                  Start Workflow
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-lg">
                <DialogHeader>
                  <DialogTitle>Start New Workflow</DialogTitle>
                  <DialogDescription>
                    Configure and start an automated penetration testing workflow
                  </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label>Mission ID *</Label>
                    <Input
                      placeholder="Enter mission ID or name"
                      value={newWorkflow.mission_id}
                      onChange={(e) =>
                        setNewWorkflow({ ...newWorkflow, mission_id: e.target.value })
                      }
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Goals * (comma or newline separated)</Label>
                    <Textarea
                      placeholder="e.g., Domain Admin, Exfiltrate sensitive data"
                      rows={3}
                      value={goalsInput}
                      onChange={(e) => setGoalsInput(e.target.value)}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Scope * (comma or newline separated)</Label>
                    <Textarea
                      placeholder="e.g., 192.168.1.0/24, 10.0.0.0/16"
                      rows={3}
                      value={scopeInput}
                      onChange={(e) => setScopeInput(e.target.value)}
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Stealth Level</Label>
                      <Select
                        value={newWorkflow.stealth_level}
                        onValueChange={(v) =>
                          setNewWorkflow({ ...newWorkflow, stealth_level: v as any })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="low">Low (Aggressive)</SelectItem>
                          <SelectItem value="normal">Normal</SelectItem>
                          <SelectItem value="high">High (Stealthy)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Environment</Label>
                      <Select
                        value={newWorkflow.environment_type}
                        onValueChange={(v) =>
                          setNewWorkflow({ ...newWorkflow, environment_type: v as any })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="simulated">Simulated</SelectItem>
                          <SelectItem value="ssh">SSH</SelectItem>
                          <SelectItem value="vm">Virtual Machine</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Max Duration (hours)</Label>
                    <Input
                      type="number"
                      min={1}
                      max={48}
                      value={newWorkflow.max_duration_hours}
                      onChange={(e) =>
                        setNewWorkflow({
                          ...newWorkflow,
                          max_duration_hours: parseInt(e.target.value) || 4,
                        })
                      }
                    />
                  </div>
                </div>

                <DialogFooter>
                  <Button variant="outline" onClick={() => setIsStartDialogOpen(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleStartWorkflow} disabled={isStarting}>
                    {isStarting ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Starting...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 mr-2" />
                        Start
                      </>
                    )}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          {isLoading ? (
            <div className="flex items-center justify-center h-full">
              <Loader2 className="w-8 h-8 animate-spin text-purple-400" />
            </div>
          ) : !workflowStatus && !params.missionId ? (
            <EmptyWorkflowState onStart={() => setIsStartDialogOpen(true)} />
          ) : (
            <div className="space-y-6">
              {/* Status Overview */}
              {workflowStatus && (
                <div className="grid grid-cols-5 gap-4">
                  <StatCard
                    label="Targets Found"
                    value={workflowStatus.targets_discovered}
                    icon={Target}
                    color="#4a9eff"
                  />
                  <StatCard
                    label="Vulnerabilities"
                    value={workflowStatus.vulns_discovered}
                    icon={AlertCircle}
                    color="#ef4444"
                  />
                  <StatCard
                    label="Credentials"
                    value={workflowStatus.creds_discovered}
                    icon={Key}
                    color="#f59e0b"
                  />
                  <StatCard
                    label="Sessions"
                    value={workflowStatus.sessions_established}
                    icon={Terminal}
                    color="#4ade80"
                  />
                  <StatCard
                    label="Goals Achieved"
                    value={`${workflowStatus.goals_achieved}/${workflowStatus.goals_total}`}
                    icon={Check}
                    color="#a855f7"
                  />
                </div>
              )}

              {/* Progress Bar */}
              {workflowStatus && (
                <Card className="bg-[#141414] border-white/5">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm">Overall Progress</CardTitle>
                      <span className="text-sm text-gray-400">
                        {formatDuration(workflowStatus.duration_minutes)}
                      </span>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <Progress value={progress} className="h-2 mb-2" />
                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <span>
                        Phase {currentPhaseIndex + 1} of {WORKFLOW_PHASES.length}
                      </span>
                      <span>{progress}% Complete</span>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Phase Timeline */}
              <Card className="bg-[#141414] border-white/5">
                <CardHeader>
                  <CardTitle>Workflow Phases</CardTitle>
                  <CardDescription>
                    Automated penetration testing workflow progression
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-1">
                    {WORKFLOW_PHASES.map((phase, index) => {
                      const result = phaseResults.find((r) => r.phase === phase.phase);
                      const Icon = phaseIcons[phase.phase] || GitBranch;
                      const isCurrent = workflowStatus?.current_phase === phase.phase;
                      const statusColor = result
                        ? getPhaseStatusColor(result.status)
                        : "#333";

                      return (
                        <PhaseCard
                          key={phase.phase}
                          phase={phase}
                          result={result}
                          isCurrent={isCurrent}
                          index={index}
                          Icon={Icon}
                          statusColor={statusColor}
                        />
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}

// ============================================
// Helper Components
// ============================================

function EmptyWorkflowState({ onStart }: { onStart: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center h-full">
      <GitBranch className="w-20 h-20 text-gray-600 mb-6" />
      <h2 className="text-2xl font-semibold text-white mb-2">No Active Workflow</h2>
      <p className="text-gray-500 text-center max-w-md mb-6">
        Start an automated penetration testing workflow to begin the assessment
        process with AI-guided phases.
      </p>
      <Button onClick={onStart} size="lg">
        <Play className="w-5 h-5 mr-2" />
        Start New Workflow
      </Button>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number | string;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <Card className="bg-[#141414] border-white/5">
      <CardContent className="pt-4">
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center"
            style={{ background: `${color}20` }}
          >
            <Icon className="w-5 h-5" style={{ color }} />
          </div>
          <div>
            <div className="text-xl font-bold text-white">{value}</div>
            <div className="text-xs text-gray-500">{label}</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface PhaseCardProps {
  phase: (typeof WORKFLOW_PHASES)[number];
  result?: PhaseResult;
  isCurrent: boolean;
  index: number;
  Icon: React.ElementType;
  statusColor: string;
}

function PhaseCard({ phase, result, isCurrent, index, Icon, statusColor }: PhaseCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className={cn(
        "flex items-center gap-4 p-4 rounded-lg transition-all",
        isCurrent
          ? "bg-purple-500/10 border border-purple-500/30"
          : "bg-white/[0.02] hover:bg-white/[0.04]"
      )}
    >
      {/* Phase Number */}
      <div
        className="w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm"
        style={{
          background: statusColor,
          color: statusColor === "#333" ? "#888" : "#fff",
        }}
      >
        {result?.status === "completed" ? (
          <Check className="w-4 h-4" />
        ) : result?.status === "running" ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          index + 1
        )}
      </div>

      {/* Phase Icon */}
      <div
        className="w-10 h-10 rounded-lg flex items-center justify-center"
        style={{ background: `${statusColor}20` }}
      >
        <Icon className="w-5 h-5" style={{ color: statusColor }} />
      </div>

      {/* Phase Info */}
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="font-medium text-white">{phase.name}</span>
          {isCurrent && (
            <Badge variant="outline" className="border-purple-500/50 text-purple-400 text-xs">
              Current
            </Badge>
          )}
        </div>
        <p className="text-xs text-gray-500">{phase.description}</p>
      </div>

      {/* Phase Status */}
      <div className="text-right">
        {result && (
          <>
            <Badge
              variant="outline"
              className={cn(
                "text-xs",
                result.status === "completed" && "border-green-500/50 text-green-400",
                result.status === "running" && "border-blue-500/50 text-blue-400",
                result.status === "failed" && "border-red-500/50 text-red-400",
                result.status === "pending" && "border-gray-500/50 text-gray-400"
              )}
            >
              {result.status}
            </Badge>
            {result.duration_seconds > 0 && (
              <div className="text-xs text-gray-600 mt-1">
                {Math.round(result.duration_seconds / 60)}m
              </div>
            )}
          </>
        )}
      </div>
    </motion.div>
  );
}

export { Workflow };
