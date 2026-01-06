// RAGLOX v3.0 - Infrastructure Page
// SSH Environment Management with real-time terminal
// Professional enterprise-grade design

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Server,
  Plus,
  RefreshCw,
  Trash2,
  Terminal,
  Wifi,
  WifiOff,
  Activity,
  Cpu,
  HardDrive,
  Clock,
  Play,
  X,
  Copy,
  Check,
  Loader2,
  AlertCircle,
  ChevronRight,
  Send,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { infrastructureApi, type Environment, type ExecutionResult, type SystemInfo } from "@/lib/infrastructureApi";
import { useAuthStore } from "@/stores/authStore";

// ============================================
// Types
// ============================================

interface TerminalLine {
  type: "command" | "output" | "error" | "system";
  content: string;
  timestamp: Date;
}

// ============================================
// Infrastructure Page
// ============================================

export default function Infrastructure() {
  const { user } = useAuthStore();
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedEnv, setSelectedEnv] = useState<Environment | null>(null);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState<TerminalLine[]>([]);
  const [currentCommand, setCurrentCommand] = useState("");
  const [isExecuting, setIsExecuting] = useState(false);
  const terminalRef = useRef<HTMLDivElement>(null);

  // Create form state
  const [newEnv, setNewEnv] = useState({
    name: "",
    host: "",
    port: "22",
    username: "",
    password: "",
    privateKey: "",
  });

  // Load environments
  useEffect(() => {
    loadEnvironments();
  }, [user]);

  const loadEnvironments = async () => {
    if (!user?.id) return;
    
    setIsLoading(true);
    try {
      const envs = await infrastructureApi.listEnvironments(user.id);
      setEnvironments(envs);
    } catch (error) {
      console.error("Failed to load environments:", error);
      // Demo mode - show empty state
      setEnvironments([]);
    } finally {
      setIsLoading(false);
    }
  };

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalOutput]);

  // Create environment
  const handleCreateEnvironment = async () => {
    if (!newEnv.name || !newEnv.host || !newEnv.username) {
      toast.error("Please fill in all required fields");
      return;
    }

    setIsCreating(true);
    try {
      const env = await infrastructureApi.createEnvironment({
        name: newEnv.name,
        host: newEnv.host,
        port: parseInt(newEnv.port) || 22,
        username: newEnv.username,
        password: newEnv.password || undefined,
        private_key: newEnv.privateKey || undefined,
      });
      
      setEnvironments([...environments, env]);
      setIsCreateDialogOpen(false);
      setNewEnv({ name: "", host: "", port: "22", username: "", password: "", privateKey: "" });
      toast.success("Environment created successfully");
    } catch (error) {
      console.error("Failed to create environment:", error);
      toast.error("Failed to create environment");
    } finally {
      setIsCreating(false);
    }
  };

  // Delete environment
  const handleDeleteEnvironment = async (envId: string) => {
    try {
      await infrastructureApi.deleteEnvironment(envId);
      setEnvironments(environments.filter(e => e.environment_id !== envId));
      if (selectedEnv?.environment_id === envId) {
        setSelectedEnv(null);
        setTerminalOutput([]);
      }
      toast.success("Environment deleted");
    } catch (error) {
      toast.error("Failed to delete environment");
    }
  };

  // Execute command
  const handleExecuteCommand = async () => {
    if (!currentCommand.trim() || !selectedEnv || isExecuting) return;

    const command = currentCommand.trim();
    setCurrentCommand("");
    setIsExecuting(true);

    // Add command to terminal
    setTerminalOutput(prev => [...prev, {
      type: "command",
      content: `$ ${command}`,
      timestamp: new Date(),
    }]);

    try {
      const result = await infrastructureApi.executeCommand(
        selectedEnv.environment_id,
        command
      );

      // Add output
      if (result.stdout) {
        setTerminalOutput(prev => [...prev, {
          type: "output",
          content: result.stdout,
          timestamp: new Date(),
        }]);
      }

      if (result.stderr) {
        setTerminalOutput(prev => [...prev, {
          type: "error",
          content: result.stderr,
          timestamp: new Date(),
        }]);
      }
    } catch (error) {
      setTerminalOutput(prev => [...prev, {
        type: "error",
        content: `Error: ${error instanceof Error ? error.message : "Command failed"}`,
        timestamp: new Date(),
      }]);
    } finally {
      setIsExecuting(false);
    }
  };

  // Handle key press in terminal
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleExecuteCommand();
    }
  };

  return (
    <AppLayout>
      <div className="flex h-full">
        {/* Left Panel - Environment List */}
        <div
          className="w-80 flex-shrink-0 flex flex-col"
          style={{
            background: "#0f0f0f",
            borderRight: "1px solid rgba(255,255,255,0.06)",
          }}
        >
          {/* Header */}
          <div className="p-4 border-b border-white/5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-blue-400" />
                <h2 className="font-semibold text-white">Environments</h2>
              </div>
              <Button
                size="sm"
                variant="ghost"
                onClick={loadEnvironments}
                disabled={isLoading}
              >
                <RefreshCw className={cn("w-4 h-4", isLoading && "animate-spin")} />
              </Button>
            </div>

            {/* Create Button */}
            <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
              <DialogTrigger asChild>
                <Button className="w-full gap-2" size="sm">
                  <Plus className="w-4 h-4" />
                  New Environment
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create SSH Environment</DialogTitle>
                  <DialogDescription>
                    Connect to a remote server via SSH for penetration testing.
                  </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="name">Name *</Label>
                      <Input
                        id="name"
                        placeholder="Target Server"
                        value={newEnv.name}
                        onChange={(e) => setNewEnv({ ...newEnv, name: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="host">Host *</Label>
                      <Input
                        id="host"
                        placeholder="192.168.1.100"
                        value={newEnv.host}
                        onChange={(e) => setNewEnv({ ...newEnv, host: e.target.value })}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="port">Port</Label>
                      <Input
                        id="port"
                        placeholder="22"
                        value={newEnv.port}
                        onChange={(e) => setNewEnv({ ...newEnv, port: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="username">Username *</Label>
                      <Input
                        id="username"
                        placeholder="root"
                        value={newEnv.username}
                        onChange={(e) => setNewEnv({ ...newEnv, username: e.target.value })}
                      />
                    </div>
                  </div>

                  <Tabs defaultValue="password" className="w-full">
                    <TabsList className="w-full">
                      <TabsTrigger value="password" className="flex-1">Password</TabsTrigger>
                      <TabsTrigger value="key" className="flex-1">Private Key</TabsTrigger>
                    </TabsList>
                    <TabsContent value="password" className="mt-2">
                      <Input
                        type="password"
                        placeholder="Enter password"
                        value={newEnv.password}
                        onChange={(e) => setNewEnv({ ...newEnv, password: e.target.value })}
                      />
                    </TabsContent>
                    <TabsContent value="key" className="mt-2">
                      <Textarea
                        placeholder="Paste private key here..."
                        rows={4}
                        value={newEnv.privateKey}
                        onChange={(e) => setNewEnv({ ...newEnv, privateKey: e.target.value })}
                        className="font-mono text-xs"
                      />
                    </TabsContent>
                  </Tabs>
                </div>

                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => setIsCreateDialogOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button onClick={handleCreateEnvironment} disabled={isCreating}>
                    {isCreating ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Connecting...
                      </>
                    ) : (
                      <>
                        <Plus className="w-4 h-4 mr-2" />
                        Create
                      </>
                    )}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>

          {/* Environment List */}
          <div className="flex-1 overflow-auto p-2 space-y-2">
            {isLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
              </div>
            ) : environments.length === 0 ? (
              <div className="text-center py-12">
                <Server className="w-12 h-12 mx-auto mb-4 text-gray-600" />
                <p className="text-gray-400 text-sm">No environments</p>
                <p className="text-gray-600 text-xs mt-1">Create one to get started</p>
              </div>
            ) : (
              environments.map((env) => (
                <EnvironmentCard
                  key={env.environment_id}
                  environment={env}
                  isSelected={selectedEnv?.environment_id === env.environment_id}
                  onClick={() => {
                    setSelectedEnv(env);
                    setTerminalOutput([{
                      type: "system",
                      content: `Connected to ${env.name} (${env.host})`,
                      timestamp: new Date(),
                    }]);
                  }}
                  onDelete={() => handleDeleteEnvironment(env.environment_id)}
                />
              ))
            )}
          </div>
        </div>

        {/* Right Panel - Terminal */}
        <div className="flex-1 flex flex-col min-w-0">
          {selectedEnv ? (
            <>
              {/* Terminal Header */}
              <div
                className="flex items-center justify-between px-4 py-3"
                style={{
                  background: "#141414",
                  borderBottom: "1px solid rgba(255,255,255,0.06)",
                }}
              >
                <div className="flex items-center gap-3">
                  <Terminal className="w-4 h-4 text-green-400" />
                  <span className="font-medium text-white">{selectedEnv.name}</span>
                  <span className="text-gray-500 text-sm">
                    {selectedEnv.username}@{selectedEnv.host}
                  </span>
                  <Badge
                    variant="outline"
                    className={cn(
                      "text-xs",
                      selectedEnv.status === "connected"
                        ? "border-green-500/50 text-green-400"
                        : "border-gray-500/50 text-gray-400"
                    )}
                  >
                    {selectedEnv.status}
                  </Badge>
                </div>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setSelectedEnv(null);
                    setTerminalOutput([]);
                  }}
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>

              {/* Terminal Output */}
              <div
                ref={terminalRef}
                className="flex-1 overflow-auto p-4 font-mono text-sm"
                style={{
                  background: "#0d0d0d",
                }}
              >
                {terminalOutput.map((line, i) => (
                  <TerminalLineComponent key={i} line={line} />
                ))}
                {isExecuting && (
                  <div className="flex items-center gap-2 text-gray-500">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Executing...</span>
                  </div>
                )}
              </div>

              {/* Terminal Input */}
              <div
                className="flex items-center gap-2 p-3"
                style={{
                  background: "#141414",
                  borderTop: "1px solid rgba(255,255,255,0.06)",
                }}
              >
                <span className="text-green-400 font-mono">$</span>
                <input
                  type="text"
                  value={currentCommand}
                  onChange={(e) => setCurrentCommand(e.target.value)}
                  onKeyDown={handleKeyPress}
                  placeholder="Enter command..."
                  disabled={isExecuting}
                  className="flex-1 bg-transparent border-none outline-none text-white font-mono text-sm placeholder:text-gray-600"
                  autoFocus
                />
                <Button
                  size="sm"
                  onClick={handleExecuteCommand}
                  disabled={!currentCommand.trim() || isExecuting}
                >
                  <Send className="w-4 h-4" />
                </Button>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <Terminal className="w-16 h-16 mx-auto mb-4 text-gray-600" />
                <h3 className="text-xl font-medium text-white mb-2">
                  Select an Environment
                </h3>
                <p className="text-gray-400 text-sm max-w-sm">
                  Choose an SSH environment from the left panel to start executing commands
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppLayout>
  );
}

// ============================================
// Environment Card Component
// ============================================

interface EnvironmentCardProps {
  environment: Environment;
  isSelected: boolean;
  onClick: () => void;
  onDelete: () => void;
}

function EnvironmentCard({ environment, isSelected, onClick, onDelete }: EnvironmentCardProps) {
  const isConnected = environment.status === "connected";

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        "p-3 rounded-lg cursor-pointer transition-all",
        "border border-transparent",
        isSelected
          ? "bg-blue-500/10 border-blue-500/30"
          : "bg-white/5 hover:bg-white/10"
      )}
      onClick={onClick}
    >
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "w-2 h-2 rounded-full",
              isConnected ? "bg-green-400" : "bg-gray-500"
            )}
          />
          <span className="font-medium text-white text-sm">{environment.name}</span>
        </div>
        <Button
          size="sm"
          variant="ghost"
          className="h-6 w-6 p-0 text-gray-500 hover:text-red-400"
          onClick={(e) => {
            e.stopPropagation();
            onDelete();
          }}
        >
          <Trash2 className="w-3 h-3" />
        </Button>
      </div>
      <div className="text-xs text-gray-500 font-mono">
        {environment.username}@{environment.host}:{environment.port}
      </div>
    </motion.div>
  );
}

// ============================================
// Terminal Line Component
// ============================================

function TerminalLineComponent({ line }: { line: TerminalLine }) {
  const colorMap = {
    command: "#4a9eff",
    output: "#a0a0a0",
    error: "#ef4444",
    system: "#888888",
  };

  return (
    <div
      className="whitespace-pre-wrap mb-1"
      style={{ color: colorMap[line.type] }}
    >
      {line.content}
    </div>
  );
}
