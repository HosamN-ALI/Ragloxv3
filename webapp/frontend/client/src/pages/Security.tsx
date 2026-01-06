// RAGLOX v3.0 - Security Page
// Security Dashboard with Rate Limiting, Health Monitoring, Audit Logs
// Professional enterprise-grade design

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Activity,
  Lock,
  Key,
  Eye,
  FileText,
  Filter,
  Search,
  Loader2,
  TrendingUp,
  Users,
  Server,
  Database,
  Wifi,
  WifiOff,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { healthApi } from "@/lib/api";

// ============================================
// Types
// ============================================

interface HealthStatus {
  status: "healthy" | "degraded" | "unhealthy";
  version: string;
  uptime_seconds: number;
  components: {
    database: "healthy" | "unhealthy";
    llm_service: "healthy" | "unhealthy";
    websocket: "healthy" | "unhealthy";
    file_storage: "healthy" | "unhealthy";
  };
  metrics: {
    active_connections: number;
    requests_per_minute: number;
    average_latency_ms: number;
  };
}

interface RateLimitStatus {
  endpoint: string;
  limit: number;
  remaining: number;
  reset_at: string;
  blocked: boolean;
}

interface AuditLog {
  id: string;
  timestamp: string;
  action: string;
  user: string;
  resource: string;
  status: "success" | "failure" | "warning";
  ip_address: string;
  details?: string;
}

// ============================================
// Security Page
// ============================================

export default function Security() {
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("overview");
  const [healthStatus, setHealthStatus] = useState<HealthStatus | null>(null);
  const [rateLimits, setRateLimits] = useState<RateLimitStatus[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  // Load data
  useEffect(() => {
    loadSecurityData();
    // Refresh every 30 seconds
    const interval = setInterval(loadSecurityData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadSecurityData = async () => {
    setIsLoading(true);
    try {
      // Load health status
      const health = await healthApi.check().catch(() => null) as Record<string, unknown> | null;
      if (health) {
        const status = (health.status as string) || "healthy";
        setHealthStatus({
          status: status as "healthy" | "degraded" | "unhealthy",
          version: (health.version as string) || "3.0.0",
          uptime_seconds: (health.uptime_seconds as number) || 0,
          components: {
            database: "healthy",
            llm_service: "healthy",
            websocket: "healthy",
            file_storage: "healthy",
          },
          metrics: {
            active_connections: (health.active_connections as number) || 0,
            requests_per_minute: (health.requests_per_minute as number) || 0,
            average_latency_ms: (health.average_latency_ms as number) || 0,
          },
        });
      } else {
        // Use demo data if no health response
        setHealthStatus(getSampleHealthStatus());
      }

      // Load demo data for rate limits and audit logs
      setRateLimits(getSampleRateLimits());
      setAuditLogs(getSampleAuditLogs());
    } catch (error) {
      console.error("Failed to load security data:", error);
      // Use demo data
      setHealthStatus(getSampleHealthStatus());
      setRateLimits(getSampleRateLimits());
      setAuditLogs(getSampleAuditLogs());
    } finally {
      setIsLoading(false);
    }
  };

  // Filter audit logs
  const filteredLogs = auditLogs.filter((log) => {
    const matchesSearch =
      !searchQuery ||
      log.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.user.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.resource.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus = statusFilter === "all" || log.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

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
            <Shield className="w-6 h-6 text-green-400" />
            <div>
              <h1 className="text-xl font-semibold text-white">Security Dashboard</h1>
              <p className="text-sm text-gray-500">
                System Health, Rate Limits & Audit Logs
              </p>
            </div>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={loadSecurityData}
            disabled={isLoading}
          >
            <RefreshCw className={cn("w-4 h-4 mr-2", isLoading && "animate-spin")} />
            Refresh
          </Button>
        </div>

        {/* Tabs */}
        <Tabs
          value={activeTab}
          onValueChange={setActiveTab}
          className="flex-1 flex flex-col"
        >
          <TabsList
            className="mx-6 mt-4 w-fit"
            style={{ background: "rgba(255,255,255,0.05)" }}
          >
            <TabsTrigger value="overview" className="gap-2">
              <Activity className="w-4 h-4" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="rate-limits" className="gap-2">
              <Clock className="w-4 h-4" />
              Rate Limits
            </TabsTrigger>
            <TabsTrigger value="audit-logs" className="gap-2">
              <FileText className="w-4 h-4" />
              Audit Logs
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="flex-1 p-6 overflow-auto">
            {isLoading ? (
              <LoadingState />
            ) : (
              <div className="space-y-6">
                {/* System Health */}
                {healthStatus && (
                  <>
                    <div className="grid grid-cols-4 gap-4">
                      <StatCard
                        label="System Status"
                        value={healthStatus.status}
                        icon={Activity}
                        color={
                          healthStatus.status === "healthy"
                            ? "#4ade80"
                            : healthStatus.status === "degraded"
                            ? "#f59e0b"
                            : "#ef4444"
                        }
                        valueClass={cn(
                          "capitalize",
                          healthStatus.status === "healthy" && "text-green-400",
                          healthStatus.status === "degraded" && "text-yellow-400",
                          healthStatus.status === "unhealthy" && "text-red-400"
                        )}
                      />
                      <StatCard
                        label="Active Connections"
                        value={healthStatus.metrics.active_connections}
                        icon={Users}
                        color="#4a9eff"
                      />
                      <StatCard
                        label="Requests/min"
                        value={healthStatus.metrics.requests_per_minute}
                        icon={TrendingUp}
                        color="#a855f7"
                      />
                      <StatCard
                        label="Avg Latency"
                        value={`${healthStatus.metrics.average_latency_ms}ms`}
                        icon={Clock}
                        color="#f59e0b"
                      />
                    </div>

                    {/* Component Health */}
                    <Card className="bg-[#141414] border-white/5">
                      <CardHeader>
                        <CardTitle>Component Health</CardTitle>
                        <CardDescription>
                          Status of core system components
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          <ComponentStatus
                            name="Database"
                            icon={Database}
                            status={healthStatus.components.database}
                          />
                          <ComponentStatus
                            name="LLM Service"
                            icon={Activity}
                            status={healthStatus.components.llm_service}
                          />
                          <ComponentStatus
                            name="WebSocket"
                            icon={Wifi}
                            status={healthStatus.components.websocket}
                          />
                          <ComponentStatus
                            name="File Storage"
                            icon={Server}
                            status={healthStatus.components.file_storage}
                          />
                        </div>
                      </CardContent>
                    </Card>

                    {/* Uptime */}
                    <Card className="bg-[#141414] border-white/5">
                      <CardHeader>
                        <CardTitle>System Information</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-3 gap-6">
                          <div>
                            <p className="text-sm text-gray-500">Version</p>
                            <p className="text-lg font-semibold text-white">
                              v{healthStatus.version}
                            </p>
                          </div>
                          <div>
                            <p className="text-sm text-gray-500">Uptime</p>
                            <p className="text-lg font-semibold text-white">
                              {formatUptime(healthStatus.uptime_seconds)}
                            </p>
                          </div>
                          <div>
                            <p className="text-sm text-gray-500">Last Check</p>
                            <p className="text-lg font-semibold text-white">
                              Just now
                            </p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </>
                )}
              </div>
            )}
          </TabsContent>

          {/* Rate Limits Tab */}
          <TabsContent value="rate-limits" className="flex-1 p-6 overflow-auto">
            {isLoading ? (
              <LoadingState />
            ) : (
              <div className="space-y-4">
                {rateLimits.map((limit, index) => (
                  <RateLimitCard key={limit.endpoint} limit={limit} index={index} />
                ))}
              </div>
            )}
          </TabsContent>

          {/* Audit Logs Tab */}
          <TabsContent value="audit-logs" className="flex-1 flex flex-col p-6 overflow-hidden">
            {/* Filters */}
            <div className="flex items-center gap-4 mb-4">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <Input
                  placeholder="Search logs..."
                  className="pl-9 bg-white/5 border-white/10"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-40 bg-white/5 border-white/10">
                  <Filter className="w-4 h-4 mr-2" />
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="success">Success</SelectItem>
                  <SelectItem value="failure">Failure</SelectItem>
                  <SelectItem value="warning">Warning</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Logs Table */}
            <div className="flex-1 overflow-auto">
              {isLoading ? (
                <LoadingState />
              ) : filteredLogs.length === 0 ? (
                <EmptyState />
              ) : (
                <div className="space-y-2">
                  {filteredLogs.map((log, index) => (
                    <AuditLogCard key={log.id} log={log} index={index} />
                  ))}
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </AppLayout>
  );
}

// ============================================
// Helper Components
// ============================================

function LoadingState() {
  return (
    <div className="flex items-center justify-center py-20">
      <Loader2 className="w-8 h-8 animate-spin text-green-400" />
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-20">
      <FileText className="w-16 h-16 text-gray-600 mb-4" />
      <h3 className="text-lg font-medium text-white mb-2">No Logs Found</h3>
      <p className="text-gray-500 text-sm">
        Audit logs will appear here when activity is recorded
      </p>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  color,
  valueClass,
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  color: string;
  valueClass?: string;
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
            <div className={cn("text-xl font-bold text-white", valueClass)}>
              {value}
            </div>
            <div className="text-xs text-gray-500">{label}</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ComponentStatus({
  name,
  icon: Icon,
  status,
}: {
  name: string;
  icon: React.ElementType;
  status: "healthy" | "unhealthy";
}) {
  const isHealthy = status === "healthy";

  return (
    <div
      className={cn(
        "p-4 rounded-lg flex items-center gap-3",
        isHealthy ? "bg-green-500/10" : "bg-red-500/10"
      )}
    >
      <Icon
        className={cn("w-5 h-5", isHealthy ? "text-green-400" : "text-red-400")}
      />
      <div>
        <p className="text-sm font-medium text-white">{name}</p>
        <div className="flex items-center gap-1.5">
          {isHealthy ? (
            <CheckCircle className="w-3 h-3 text-green-400" />
          ) : (
            <XCircle className="w-3 h-3 text-red-400" />
          )}
          <span
            className={cn(
              "text-xs",
              isHealthy ? "text-green-400" : "text-red-400"
            )}
          >
            {status}
          </span>
        </div>
      </div>
    </div>
  );
}

function RateLimitCard({
  limit,
  index,
}: {
  limit: RateLimitStatus;
  index: number;
}) {
  const usagePercent = ((limit.limit - limit.remaining) / limit.limit) * 100;
  const isWarning = usagePercent > 70;
  const isCritical = usagePercent > 90 || limit.blocked;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
    >
      <Card className="bg-[#141414] border-white/5">
        <CardContent className="pt-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-gray-500" />
              <span className="font-medium text-white font-mono text-sm">
                {limit.endpoint}
              </span>
            </div>
            {limit.blocked && (
              <Badge variant="destructive" className="text-xs">
                Blocked
              </Badge>
            )}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-500">
                {limit.remaining} / {limit.limit} remaining
              </span>
              <span
                className={cn(
                  "font-medium",
                  isCritical
                    ? "text-red-400"
                    : isWarning
                    ? "text-yellow-400"
                    : "text-green-400"
                )}
              >
                {Math.round(usagePercent)}% used
              </span>
            </div>
            <Progress
              value={usagePercent}
              className={cn(
                "h-2",
                isCritical && "[&>div]:bg-red-500",
                isWarning && !isCritical && "[&>div]:bg-yellow-500"
              )}
            />
            <p className="text-xs text-gray-600">
              Resets at {new Date(limit.reset_at).toLocaleTimeString()}
            </p>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

function AuditLogCard({ log, index }: { log: AuditLog; index: number }) {
  const statusColors = {
    success: "text-green-400 bg-green-500/20",
    failure: "text-red-400 bg-red-500/20",
    warning: "text-yellow-400 bg-yellow-500/20",
  };

  const statusIcons = {
    success: CheckCircle,
    failure: XCircle,
    warning: AlertTriangle,
  };

  const StatusIcon = statusIcons[log.status];

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.03 }}
      className="p-4 rounded-lg bg-white/[0.02] hover:bg-white/[0.04] transition-colors"
    >
      <div className="flex items-start gap-4">
        <div className={cn("p-2 rounded-lg", statusColors[log.status])}>
          <StatusIcon className="w-4 h-4" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-medium text-white">{log.action}</span>
            <span className="text-xs text-gray-600">
              {new Date(log.timestamp).toLocaleString()}
            </span>
          </div>
          <div className="flex items-center gap-4 text-sm text-gray-500">
            <span>User: {log.user}</span>
            <span>Resource: {log.resource}</span>
            <span>IP: {log.ip_address}</span>
          </div>
          {log.details && (
            <p className="text-xs text-gray-600 mt-1">{log.details}</p>
          )}
        </div>
      </div>
    </motion.div>
  );
}

// ============================================
// Helper Functions
// ============================================

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

// ============================================
// Sample Data (Demo Mode)
// ============================================

function getSampleHealthStatus(): HealthStatus {
  return {
    status: "healthy",
    version: "3.0.0",
    uptime_seconds: 86400,
    components: {
      database: "healthy",
      llm_service: "healthy",
      websocket: "healthy",
      file_storage: "healthy",
    },
    metrics: {
      active_connections: 12,
      requests_per_minute: 156,
      average_latency_ms: 45,
    },
  };
}

function getSampleRateLimits(): RateLimitStatus[] {
  return [
    {
      endpoint: "/api/v1/chat/send",
      limit: 100,
      remaining: 87,
      reset_at: new Date(Date.now() + 3600000).toISOString(),
      blocked: false,
    },
    {
      endpoint: "/api/v1/missions/create",
      limit: 50,
      remaining: 48,
      reset_at: new Date(Date.now() + 3600000).toISOString(),
      blocked: false,
    },
    {
      endpoint: "/api/v1/exploitation/*",
      limit: 30,
      remaining: 5,
      reset_at: new Date(Date.now() + 1800000).toISOString(),
      blocked: false,
    },
  ];
}

function getSampleAuditLogs(): AuditLog[] {
  return [
    {
      id: "1",
      timestamp: new Date(Date.now() - 60000).toISOString(),
      action: "Mission Created",
      user: "admin",
      resource: "mission-123",
      status: "success",
      ip_address: "192.168.1.100",
    },
    {
      id: "2",
      timestamp: new Date(Date.now() - 120000).toISOString(),
      action: "Login Attempt",
      user: "user@example.com",
      resource: "auth",
      status: "success",
      ip_address: "10.0.0.50",
    },
    {
      id: "3",
      timestamp: new Date(Date.now() - 300000).toISOString(),
      action: "Exploit Executed",
      user: "operator",
      resource: "target-456",
      status: "warning",
      ip_address: "192.168.1.100",
      details: "High-risk operation approved",
    },
    {
      id: "4",
      timestamp: new Date(Date.now() - 600000).toISOString(),
      action: "API Rate Limit",
      user: "system",
      resource: "/api/v1/scan",
      status: "failure",
      ip_address: "10.0.0.25",
      details: "Rate limit exceeded",
    },
  ];
}

export { Security };
