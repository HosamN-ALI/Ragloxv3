// RAGLOX v3.0 - Dashboard Page
// Main dashboard for authenticated users - NO DEMO DATA

import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import {
  Shield,
  Target,
  Activity,
  Plus,
  Clock,
  Loader2,
  Server,
  AlertCircle,
  CheckCircle,
  RefreshCw,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { missionApi, authApi } from "@/lib/api";
import { useAuth } from "@/stores/authStore";
import { AppLayout } from "@/components/layout/AppLayout";
import { toast } from "sonner";

export default function Dashboard() {
  const [, setLocation] = useLocation();
  const { user, setUser } = useAuth();
  const [missions, setMissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [vmStatus, setVmStatus] = useState<{
    vm_status: string;
    vm_ip: string | null;
    message: string;
  } | null>(null);
  const [isVmLoading, setIsVmLoading] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setIsLoading(true);
    try {
      // Load missions
      const missionList = await missionApi.list();
      setMissions(missionList);

      // Load VM status
      await refreshVmStatus();
    } catch (error) {
      console.error("Failed to load dashboard data:", error);
      toast.error("Failed to load dashboard data");
    } finally {
      setIsLoading(false);
    }
  };

  const refreshVmStatus = async () => {
    setIsVmLoading(true);
    try {
      const status = await authApi.vmStatus();
      setVmStatus(status);
      
      // Update user state if VM status changed
      if (user && status.vm_status !== user.vm_status) {
        setUser({
          ...user,
          vm_status: status.vm_status as any,
          vm_ip: status.vm_ip || undefined,
        });
      }
    } catch (error) {
      console.error("Failed to get VM status:", error);
    } finally {
      setIsVmLoading(false);
    }
  };

  const getVmStatusColor = (status: string) => {
    switch (status) {
      case "ready":
        return "bg-green-500/10 text-green-500 border-green-500/30";
      case "creating":
      case "configuring":
        return "bg-yellow-500/10 text-yellow-500 border-yellow-500/30";
      case "pending":
        return "bg-blue-500/10 text-blue-500 border-blue-500/30";
      case "failed":
        return "bg-red-500/10 text-red-500 border-red-500/30";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const getVmStatusIcon = (status: string) => {
    switch (status) {
      case "ready":
        return <CheckCircle className="w-5 h-5" />;
      case "creating":
      case "configuring":
        return <Loader2 className="w-5 h-5 animate-spin" />;
      case "pending":
        return <Clock className="w-5 h-5" />;
      case "failed":
        return <AlertCircle className="w-5 h-5" />;
      default:
        return <Server className="w-5 h-5" />;
    }
  };

  return (
    <AppLayout>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Dashboard</h1>
            <p className="text-muted-foreground">
              Welcome back, {user?.full_name || "User"}
            </p>
          </div>
          <Button onClick={() => setLocation("/missions")} className="gap-2">
            <Plus className="w-4 h-4" />
            New Mission
          </Button>
        </div>

        {/* VM Status Card */}
        {vmStatus && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <Card className="border-primary/20">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Server className="w-5 h-5 text-primary" />
                    Your Security VM
                  </CardTitle>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={refreshVmStatus}
                    disabled={isVmLoading}
                  >
                    <RefreshCw className={`w-4 h-4 ${isVmLoading ? "animate-spin" : ""}`} />
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-lg ${getVmStatusColor(vmStatus.vm_status)}`}>
                    {getVmStatusIcon(vmStatus.vm_status)}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium capitalize">{vmStatus.vm_status}</span>
                      {vmStatus.vm_status === "creating" && (
                        <Badge variant="secondary" className="text-xs">
                          Provisioning...
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground">{vmStatus.message}</p>
                    {vmStatus.vm_ip && (
                      <p className="text-sm font-mono mt-1">
                        IP: {vmStatus.vm_ip}
                      </p>
                    )}
                  </div>
                  {vmStatus.vm_status === "ready" && (
                    <Button variant="outline" size="sm" className="gap-2">
                      <Zap className="w-4 h-4" />
                      Connect
                    </Button>
                  )}
                </div>

                {(vmStatus.vm_status === "creating" || vmStatus.vm_status === "configuring") && (
                  <div className="mt-4">
                    <Progress value={vmStatus.vm_status === "configuring" ? 70 : 30} className="h-2" />
                    <p className="text-xs text-muted-foreground mt-1">
                      {vmStatus.vm_status === "configuring" 
                        ? "Installing security tools..." 
                        : "Creating VM instance..."}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatsCard
            title="Active Missions"
            value={missions.length}
            icon={Target}
            description="Total missions"
          />
          <StatsCard
            title="VM Status"
            value={vmStatus?.vm_status === "ready" ? "Online" : "Provisioning"}
            icon={Server}
            description={vmStatus?.vm_ip || "Waiting for IP"}
          />
          <StatsCard
            title="Account Status"
            value={user?.status || "Active"}
            icon={Shield}
            description={user?.role || "Operator"}
          />
        </div>

        {/* Recent Missions */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Recent Missions</CardTitle>
            <CardDescription>Your security assessment missions</CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
              </div>
            ) : missions.length > 0 ? (
              <div className="space-y-2">
                {missions.slice(0, 5).map((missionId) => (
                  <MissionRow
                    key={missionId}
                    missionId={missionId}
                    onClick={() => setLocation(`/operations/${missionId}`)}
                  />
                ))}
                {missions.length > 5 && (
                  <Button
                    variant="ghost"
                    className="w-full mt-2"
                    onClick={() => setLocation("/missions")}
                  >
                    View all {missions.length} missions
                  </Button>
                )}
              </div>
            ) : (
              <div className="text-center py-8">
                <Target className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <p className="text-muted-foreground mb-4">No missions yet</p>
                <Button onClick={() => setLocation("/missions")} className="gap-2">
                  <Plus className="w-4 h-4" />
                  Create Your First Mission
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <QuickActionCard
            title="New Mission"
            description="Start a security assessment"
            icon={Target}
            onClick={() => setLocation("/missions")}
          />
          <QuickActionCard
            title="Knowledge Base"
            description="Browse techniques & tools"
            icon={Activity}
            onClick={() => setLocation("/knowledge")}
          />
          <QuickActionCard
            title="Infrastructure"
            description="Manage VMs & resources"
            icon={Server}
            onClick={() => setLocation("/infrastructure")}
          />
          <QuickActionCard
            title="Reports"
            description="View assessment reports"
            icon={Shield}
            onClick={() => setLocation("/reports")}
          />
        </div>
      </div>
    </AppLayout>
  );
}

// Stats Card Component
interface StatsCardProps {
  title: string;
  value: string | number;
  icon: React.ElementType;
  description: string;
}

function StatsCard({ title, value, icon: Icon, description }: StatsCardProps) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-lg bg-primary/10">
            <Icon className="w-6 h-6 text-primary" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground">{title}</p>
            <p className="text-2xl font-bold">{value}</p>
            <p className="text-xs text-muted-foreground">{description}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// Mission Row Component
interface MissionRowProps {
  missionId: string;
  onClick: () => void;
}

function MissionRow({ missionId, onClick }: MissionRowProps) {
  const [mission, setMission] = useState<{
    name?: string;
    status?: string;
    created_at?: string;
  } | null>(null);

  useEffect(() => {
    missionApi.get(missionId)
      .then((data) => setMission(data))
      .catch(() => setMission({ name: `Mission ${missionId.slice(0, 8)}` }));
  }, [missionId]);

  const getStatusColor = (status?: string) => {
    switch (status?.toLowerCase()) {
      case "running":
        return "bg-green-500/10 text-green-500";
      case "paused":
        return "bg-yellow-500/10 text-yellow-500";
      case "completed":
        return "bg-blue-500/10 text-blue-500";
      case "failed":
        return "bg-red-500/10 text-red-500";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  return (
    <div
      className="flex items-center justify-between p-3 rounded-lg border border-border hover:bg-muted/50 cursor-pointer transition-colors"
      onClick={onClick}
    >
      <div className="flex items-center gap-3">
        <Target className="w-4 h-4 text-muted-foreground" />
        <span className="font-medium">{mission?.name || `Mission ${missionId.slice(0, 8)}...`}</span>
      </div>
      <Badge variant="secondary" className={getStatusColor(mission?.status)}>
        {mission?.status || "Unknown"}
      </Badge>
    </div>
  );
}

// Quick Action Card Component
interface QuickActionCardProps {
  title: string;
  description: string;
  icon: React.ElementType;
  onClick: () => void;
}

function QuickActionCard({ title, description, icon: Icon, onClick }: QuickActionCardProps) {
  return (
    <Card
      className="cursor-pointer hover:border-primary/50 transition-colors"
      onClick={onClick}
    >
      <CardContent className="pt-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Icon className="w-5 h-5 text-primary" />
          </div>
          <div>
            <p className="font-medium">{title}</p>
            <p className="text-xs text-muted-foreground">{description}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
