// RAGLOX v3.0 - Home Page
// Landing page with mission selection and creation dialog

import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import {
  Shield,
  Target,
  Zap,
  ArrowRight,
  Plus,
  Clock,
  Activity,
  Loader2,
  X,
  LogOut,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { missionApi } from "@/lib/api";
import { useMissionStore } from "@/stores/missionStore";
import { useAuth } from "@/stores/authStore";
import { DEFAULT_MISSION_ID } from "@/lib/config";
import { toast } from "sonner";

export default function Home() {
  const [, setLocation] = useLocation();
  const [missions, setMissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);

  // Auth
  const { user, logout, isAuthenticated } = useAuth();

  // Mission store
  const { createMission, isControlLoading } = useMissionStore();

  // Create mission form state
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
    try {
      const data = await missionApi.list();
      setMissions(data);
    } catch (error) {
      // API not available - use demo data silently
      console.log("API not available, using demo mode");
      // Set demo mission as fallback
      setMissions([DEFAULT_MISSION_ID]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleStartDemo = () => {
    setLocation(`/operations/${DEFAULT_MISSION_ID}`);
  };

  const handleGoToOperations = () => {
    setLocation("/operations");
  };

  const handleLogout = async () => {
    await logout();
    setLocation("/login");
  };

  const handleCreateMission = async () => {
    // Validation
    if (!newMission.name.trim()) {
      toast.error("Mission name is required");
      return;
    }
    if (!newMission.scope.trim()) {
      toast.error("At least one target scope is required");
      return;
    }
    if (!newMission.goals.trim()) {
      toast.error("At least one goal is required");
      return;
    }

    // Parse scope and goals (comma or newline separated)
    const scope = newMission.scope
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    const goals = newMission.goals
      .split(/[,\n]/)
      .map((g) => g.trim())
      .filter((g) => g.length > 0);

    // Create mission
    const missionId = await createMission({
      name: newMission.name.trim(),
      description: newMission.description.trim() || undefined,
      scope,
      goals,
    });

    if (missionId) {
      toast.success("Mission created successfully!");
      setIsCreateDialogOpen(false);
      setNewMission({ name: "", description: "", scope: "", goals: "" });

      // Navigate to the new mission
      setLocation(`/operations/${missionId}`);
    } else {
      toast.error("Failed to create mission");
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-primary" />
            <span className="font-bold text-xl">RAGLOX</span>
            <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded ml-2">
              v3.0
            </span>
          </div>
          <nav className="flex items-center gap-4">
            <Button variant="ghost" onClick={() => setLocation("/missions")}>
              Missions
            </Button>
            <Button variant="ghost" onClick={handleGoToOperations}>
              Operations
            </Button>
            <Button variant="ghost" onClick={() => setLocation("/knowledge")}>
              Knowledge
            </Button>
            <Button variant="default" onClick={handleStartDemo}>
              Start Demo
            </Button>
            {isAuthenticated && user && (
              <div className="flex items-center gap-2 ml-4 pl-4 border-l border-border">
                <span className="text-sm text-muted-foreground">
                  {user.username}
                </span>
                <Button variant="ghost" size="icon" onClick={handleLogout}>
                  <LogOut className="w-4 h-4" />
                </Button>
              </div>
            )}
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 px-4">
        <div className="container max-w-4xl text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <h1 className="text-5xl font-bold mb-6">
              <span className="text-primary">AI-Powered</span> Security Operations
            </h1>
            <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
              RAGLOX is an autonomous penetration testing platform that combines
              AI intelligence with human oversight for enterprise-grade security operations.
            </p>
            <div className="flex items-center justify-center gap-4">
              <Button size="lg" onClick={handleStartDemo} className="gap-2">
                <Zap className="w-5 h-5" />
                Start Demo Mission
              </Button>
              <Button size="lg" variant="outline" onClick={handleGoToOperations} className="gap-2">
                <ArrowRight className="w-5 h-5" />
                Go to Operations
              </Button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 px-4 bg-muted/30">
        <div className="container">
          <h2 className="text-3xl font-bold text-center mb-12">
            Enterprise Security Platform
          </h2>
          <div className="grid md:grid-cols-3 gap-6">
            <FeatureCard
              icon={Target}
              title="Autonomous Recon"
              description="AI-driven reconnaissance that discovers targets, services, and vulnerabilities automatically."
            />
            <FeatureCard
              icon={Shield}
              title="Human-in-the-Loop"
              description="Critical actions require human approval, ensuring safe and controlled operations."
            />
            <FeatureCard
              icon={Activity}
              title="Real-time Monitoring"
              description="Live updates via WebSocket, terminal output, and comprehensive event logging."
            />
          </div>
        </div>
      </section>

      {/* Recent Missions */}
      <section className="py-16 px-4">
        <div className="container">
          <div className="flex items-center justify-between mb-8">
            <h2 className="text-2xl font-bold">Recent Missions</h2>

            {/* Create Mission Dialog */}
            <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
              <DialogTrigger asChild>
                <Button variant="outline" className="gap-2">
                  <Plus className="w-4 h-4" />
                  New Mission
                </Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-[500px]">
                <DialogHeader>
                  <DialogTitle>Create New Mission</DialogTitle>
                  <DialogDescription>
                    Configure a new security assessment mission. Define the scope and goals for the AI to pursue.
                  </DialogDescription>
                </DialogHeader>

                <div className="grid gap-4 py-4">
                  {/* Mission Name */}
                  <div className="grid gap-2">
                    <Label htmlFor="name">Mission Name *</Label>
                    <Input
                      id="name"
                      placeholder="e.g., Production Network Assessment"
                      value={newMission.name}
                      onChange={(e) => setNewMission({ ...newMission, name: e.target.value })}
                    />
                  </div>

                  {/* Description */}
                  <div className="grid gap-2">
                    <Label htmlFor="description">Description</Label>
                    <Textarea
                      id="description"
                      placeholder="Optional description of the mission objectives..."
                      value={newMission.description}
                      onChange={(e) => setNewMission({ ...newMission, description: e.target.value })}
                      rows={2}
                    />
                  </div>

                  {/* Scope */}
                  <div className="grid gap-2">
                    <Label htmlFor="scope">Target Scope *</Label>
                    <Textarea
                      id="scope"
                      placeholder="Enter IP addresses, ranges, or hostnames (one per line or comma-separated)&#10;e.g., 192.168.1.0/24, target.example.com"
                      value={newMission.scope}
                      onChange={(e) => setNewMission({ ...newMission, scope: e.target.value })}
                      rows={3}
                    />
                    <p className="text-xs text-muted-foreground">
                      Separate multiple targets with commas or newlines
                    </p>
                  </div>

                  {/* Goals */}
                  <div className="grid gap-2">
                    <Label htmlFor="goals">Mission Goals *</Label>
                    <Textarea
                      id="goals"
                      placeholder="Define what the mission should achieve (one per line or comma-separated)&#10;e.g., Identify vulnerabilities, Gain initial access, Escalate privileges"
                      value={newMission.goals}
                      onChange={(e) => setNewMission({ ...newMission, goals: e.target.value })}
                      rows={3}
                    />
                    <p className="text-xs text-muted-foreground">
                      Separate multiple goals with commas or newlines
                    </p>
                  </div>
                </div>

                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => setIsCreateDialogOpen(false)}
                    disabled={isControlLoading}
                  >
                    Cancel
                  </Button>
                  <Button
                    onClick={handleCreateMission}
                    disabled={isControlLoading}
                  >
                    {isControlLoading ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Creating...
                      </>
                    ) : (
                      <>
                        <Plus className="mr-2 h-4 w-4" />
                        Create Mission
                      </>
                    )}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full" />
            </div>
          ) : missions.length > 0 ? (
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
              {missions.slice(0, 6).map((missionId) => (
                <MissionCard
                  key={missionId}
                  missionId={missionId}
                  onClick={() => setLocation(`/operations/${missionId}`)}
                />
              ))}
            </div>
          ) : (
            <Card className="text-center py-12">
              <CardContent>
                <p className="text-muted-foreground mb-4">No missions found</p>
                <div className="flex items-center justify-center gap-4">
                  <Button onClick={handleStartDemo}>Start Demo Mission</Button>
                  <Button variant="outline" onClick={() => setIsCreateDialogOpen(true)}>
                    <Plus className="mr-2 h-4 w-4" />
                    Create New Mission
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-8">
        <div className="container text-center text-sm text-muted-foreground">
          <p>RAGLOX v3.0 - AI-Powered Security Operations Platform</p>
          <p className="mt-2">Built with React, TypeScript, and TailwindCSS</p>
        </div>
      </footer>
    </div>
  );
}

// Feature Card Component
interface FeatureCardProps {
  icon: React.ElementType;
  title: string;
  description: string;
}

function FeatureCard({ icon: Icon, title, description }: FeatureCardProps) {
  return (
    <Card className="bg-card hover:border-primary/50 transition-colors">
      <CardHeader>
        <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
          <Icon className="w-6 h-6 text-primary" />
        </div>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <CardDescription className="text-base">{description}</CardDescription>
      </CardContent>
    </Card>
  );
}

// Mission Card Component
interface MissionCardProps {
  missionId: string;
  onClick: () => void;
}

function MissionCard({ missionId, onClick }: MissionCardProps) {
  const [mission, setMission] = useState<{
    name?: string;
    status?: string;
    target_count?: number;
    created_at?: string;
  } | null>(null);

  useEffect(() => {
    // Try to load mission details
    missionApi.get(missionId)
      .then((data) => setMission(data))
      .catch(() => {
        // Use fallback data
        setMission({
          name: `Mission ${missionId.slice(0, 8)}`,
          status: "active",
          target_count: 0,
        });
      });
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

  const formatTimeAgo = (dateString?: string) => {
    if (!dateString) return "Unknown";
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffDays > 0) return `${diffDays}d ago`;
    if (diffHours > 0) return `${diffHours}h ago`;
    if (diffMins > 0) return `${diffMins}m ago`;
    return "Just now";
  };

  return (
    <Card
      className="cursor-pointer hover:border-primary/50 transition-colors"
      onClick={onClick}
    >
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-medium truncate">
            {mission?.name || `Mission ${missionId.slice(0, 8)}...`}
          </CardTitle>
          <Badge variant="secondary" className={getStatusColor(mission?.status)}>
            {mission?.status || "Unknown"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          <div className="flex items-center gap-1">
            <Target className="w-4 h-4" />
            <span>{mission?.target_count ?? 0} targets</span>
          </div>
          <div className="flex items-center gap-1">
            <Clock className="w-4 h-4" />
            <span>{formatTimeAgo(mission?.created_at)}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
