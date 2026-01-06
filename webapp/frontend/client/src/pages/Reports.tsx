// RAGLOX v3.0 - Reports Page
// Mission Reports with Export Functionality
// Professional enterprise-grade design

import { useState, useEffect } from "react";
import { useParams } from "wouter";
import { motion } from "framer-motion";
import {
  FileText,
  Download,
  RefreshCw,
  Search,
  Filter,
  Calendar,
  Target,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Eye,
  Trash2,
  Plus,
  Loader2,
  FileJson,
  FileCode,
  File,
  ChevronRight,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
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
import { cn } from "@/lib/utils";
import { missionApi } from "@/lib/api";

// ============================================
// Types
// ============================================

interface Report {
  id: string;
  mission_id: string;
  mission_name: string;
  title: string;
  type: "executive" | "technical" | "compliance" | "custom";
  status: "draft" | "generating" | "completed" | "failed";
  created_at: string;
  completed_at?: string;
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  format: "pdf" | "html" | "json" | "markdown";
  size_bytes?: number;
  download_url?: string;
}

// ============================================
// Reports Page
// ============================================

export default function Reports() {
  const params = useParams<{ reportId?: string }>();
  const [isLoading, setIsLoading] = useState(true);
  const [reports, setReports] = useState<Report[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);

  // New report form
  const [newReport, setNewReport] = useState({
    mission_id: "",
    title: "",
    type: "technical" as Report["type"],
    format: "pdf" as Report["format"],
    include_evidence: true,
    include_recommendations: true,
  });

  // Load reports
  useEffect(() => {
    loadReports();
  }, []);

  // Select report if ID in URL
  useEffect(() => {
    if (params.reportId && reports.length > 0) {
      const report = reports.find((r) => r.id === params.reportId);
      if (report) setSelectedReport(report);
    }
  }, [params.reportId, reports]);

  const loadReports = async () => {
    setIsLoading(true);
    try {
      // For now, use sample data as backend doesn't have reports endpoint
      setReports(getSampleReports());
    } catch (error) {
      console.error("Failed to load reports:", error);
      setReports(getSampleReports());
    } finally {
      setIsLoading(false);
    }
  };

  // Filter reports
  const filteredReports = reports.filter((report) => {
    const matchesSearch =
      !searchQuery ||
      report.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      report.mission_name.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesType = typeFilter === "all" || report.type === typeFilter;
    const matchesStatus = statusFilter === "all" || report.status === statusFilter;

    return matchesSearch && matchesType && matchesStatus;
  });

  // Generate report
  const handleGenerateReport = async () => {
    if (!newReport.mission_id || !newReport.title) {
      toast.error("Please fill in all required fields");
      return;
    }

    setIsGenerating(true);
    try {
      // Simulate report generation
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const newReportData: Report = {
        id: `report-${Date.now()}`,
        mission_id: newReport.mission_id,
        mission_name: "New Mission",
        title: newReport.title,
        type: newReport.type,
        status: "completed",
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        findings: {
          critical: Math.floor(Math.random() * 3),
          high: Math.floor(Math.random() * 5),
          medium: Math.floor(Math.random() * 10),
          low: Math.floor(Math.random() * 15),
        },
        format: newReport.format,
        size_bytes: Math.floor(Math.random() * 1000000) + 100000,
      };

      setReports([newReportData, ...reports]);
      setIsCreateDialogOpen(false);
      setNewReport({
        mission_id: "",
        title: "",
        type: "technical",
        format: "pdf",
        include_evidence: true,
        include_recommendations: true,
      });
      toast.success("Report generated successfully");
    } catch (error) {
      toast.error("Failed to generate report");
    } finally {
      setIsGenerating(false);
    }
  };

  // Download report
  const handleDownload = (report: Report) => {
    if (report.download_url) {
      window.open(report.download_url, "_blank");
    } else {
      toast.info("Report download will be available soon");
    }
  };

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
            <FileText className="w-6 h-6 text-blue-400" />
            <div>
              <h1 className="text-xl font-semibold text-white">Reports</h1>
              <p className="text-sm text-gray-500">
                Mission Reports & Documentation
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={loadReports}
              disabled={isLoading}
            >
              <RefreshCw className={cn("w-4 h-4 mr-2", isLoading && "animate-spin")} />
              Refresh
            </Button>
            <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
              <DialogTrigger asChild>
                <Button size="sm">
                  <Plus className="w-4 h-4 mr-2" />
                  Generate Report
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Generate New Report</DialogTitle>
                  <DialogDescription>
                    Create a detailed report for a completed mission
                  </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label>Mission ID *</Label>
                    <Input
                      placeholder="Enter mission ID"
                      value={newReport.mission_id}
                      onChange={(e) =>
                        setNewReport({ ...newReport, mission_id: e.target.value })
                      }
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Report Title *</Label>
                    <Input
                      placeholder="e.g., Penetration Test Report - Q1 2025"
                      value={newReport.title}
                      onChange={(e) =>
                        setNewReport({ ...newReport, title: e.target.value })
                      }
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Report Type</Label>
                      <Select
                        value={newReport.type}
                        onValueChange={(v) =>
                          setNewReport({ ...newReport, type: v as Report["type"] })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="executive">Executive Summary</SelectItem>
                          <SelectItem value="technical">Technical Report</SelectItem>
                          <SelectItem value="compliance">Compliance Report</SelectItem>
                          <SelectItem value="custom">Custom</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>Format</Label>
                      <Select
                        value={newReport.format}
                        onValueChange={(v) =>
                          setNewReport({ ...newReport, format: v as Report["format"] })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="pdf">PDF</SelectItem>
                          <SelectItem value="html">HTML</SelectItem>
                          <SelectItem value="markdown">Markdown</SelectItem>
                          <SelectItem value="json">JSON</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </div>

                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => setIsCreateDialogOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button onClick={handleGenerateReport} disabled={isGenerating}>
                    {isGenerating ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Generating...
                      </>
                    ) : (
                      <>
                        <FileText className="w-4 h-4 mr-2" />
                        Generate
                      </>
                    )}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </div>
        </div>

        {/* Filters */}
        <div
          className="px-6 py-3 flex items-center gap-4"
          style={{
            background: "#0d0d0d",
            borderBottom: "1px solid rgba(255,255,255,0.04)",
          }}
        >
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <Input
              placeholder="Search reports..."
              className="pl-9 bg-white/5 border-white/10"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <Select value={typeFilter} onValueChange={setTypeFilter}>
            <SelectTrigger className="w-44 bg-white/5 border-white/10">
              <Filter className="w-4 h-4 mr-2" />
              <SelectValue placeholder="Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              <SelectItem value="executive">Executive</SelectItem>
              <SelectItem value="technical">Technical</SelectItem>
              <SelectItem value="compliance">Compliance</SelectItem>
              <SelectItem value="custom">Custom</SelectItem>
            </SelectContent>
          </Select>

          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-40 bg-white/5 border-white/10">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="completed">Completed</SelectItem>
              <SelectItem value="generating">Generating</SelectItem>
              <SelectItem value="draft">Draft</SelectItem>
              <SelectItem value="failed">Failed</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          {isLoading ? (
            <LoadingState />
          ) : filteredReports.length === 0 ? (
            <EmptyState onGenerate={() => setIsCreateDialogOpen(true)} />
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {filteredReports.map((report, index) => (
                <ReportCard
                  key={report.id}
                  report={report}
                  index={index}
                  onView={() => setSelectedReport(report)}
                  onDownload={() => handleDownload(report)}
                />
              ))}
            </div>
          )}
        </div>

        {/* Report Detail Dialog */}
        <Dialog
          open={!!selectedReport}
          onOpenChange={(open) => !open && setSelectedReport(null)}
        >
          <DialogContent className="max-w-2xl">
            {selectedReport && (
              <>
                <DialogHeader>
                  <DialogTitle className="flex items-center gap-2">
                    <FileText className="w-5 h-5 text-blue-400" />
                    {selectedReport.title}
                  </DialogTitle>
                  <DialogDescription>
                    {selectedReport.mission_name} - Generated{" "}
                    {new Date(selectedReport.created_at).toLocaleDateString()}
                  </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                  {/* Findings Summary */}
                  <div>
                    <ReportLabel className="text-gray-400">Findings Summary</ReportLabel>
                    <div className="grid grid-cols-4 gap-3 mt-2">
                      <FindingBadge
                        label="Critical"
                        count={selectedReport.findings.critical}
                        color="#ef4444"
                      />
                      <FindingBadge
                        label="High"
                        count={selectedReport.findings.high}
                        color="#f59e0b"
                      />
                      <FindingBadge
                        label="Medium"
                        count={selectedReport.findings.medium}
                        color="#eab308"
                      />
                      <FindingBadge
                        label="Low"
                        count={selectedReport.findings.low}
                        color="#4ade80"
                      />
                    </div>
                  </div>

                  {/* Metadata */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <ReportLabel className="text-gray-400">Report Type</ReportLabel>
                      <p className="text-white capitalize">{selectedReport.type}</p>
                    </div>
                    <div>
                      <ReportLabel className="text-gray-400">Format</ReportLabel>
                      <p className="text-white uppercase">{selectedReport.format}</p>
                    </div>
                    <div>
                      <ReportLabel className="text-gray-400">Status</ReportLabel>
                      <Badge
                        variant="outline"
                        className={cn(
                          "mt-1",
                          selectedReport.status === "completed" &&
                            "border-green-500/50 text-green-400",
                          selectedReport.status === "generating" &&
                            "border-blue-500/50 text-blue-400",
                          selectedReport.status === "failed" &&
                            "border-red-500/50 text-red-400"
                        )}
                      >
                        {selectedReport.status}
                      </Badge>
                    </div>
                    {selectedReport.size_bytes && (
                      <div>
                        <ReportLabel className="text-gray-400">File Size</ReportLabel>
                        <p className="text-white">
                          {(selectedReport.size_bytes / 1024 / 1024).toFixed(2)} MB
                        </p>
                      </div>
                    )}
                  </div>
                </div>

                <DialogFooter>
                  <Button variant="outline" onClick={() => setSelectedReport(null)}>
                    Close
                  </Button>
                  <Button onClick={() => handleDownload(selectedReport)}>
                    <Download className="w-4 h-4 mr-2" />
                    Download Report
                  </Button>
                </DialogFooter>
              </>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </AppLayout>
  );
}

// ============================================
// Helper Components
// ============================================

function ReportLabel({ children, className }: { children: React.ReactNode; className?: string }) {
  return <p className={cn("text-sm font-medium", className)}>{children}</p>;
}

function LoadingState() {
  return (
    <div className="flex items-center justify-center h-full">
      <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
    </div>
  );
}

function EmptyState({ onGenerate }: { onGenerate: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center h-full">
      <FileText className="w-16 h-16 text-gray-600 mb-4" />
      <h3 className="text-lg font-medium text-white mb-2">No Reports Yet</h3>
      <p className="text-gray-500 text-sm text-center max-w-md mb-6">
        Generate reports from completed missions to document findings and recommendations.
      </p>
      <Button onClick={onGenerate}>
        <Plus className="w-4 h-4 mr-2" />
        Generate Report
      </Button>
    </div>
  );
}

function FindingBadge({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color: string;
}) {
  return (
    <div
      className="p-3 rounded-lg text-center"
      style={{ background: `${color}15` }}
    >
      <div className="text-xl font-bold" style={{ color }}>
        {count}
      </div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}

interface ReportCardProps {
  report: Report;
  index: number;
  onView: () => void;
  onDownload: () => void;
}

function ReportCard({ report, index, onView, onDownload }: ReportCardProps) {
  const formatIcons = {
    pdf: File,
    html: FileCode,
    json: FileJson,
    markdown: FileText,
  };
  const FormatIcon = formatIcons[report.format] || File;

  const typeColors = {
    executive: "#4a9eff",
    technical: "#a855f7",
    compliance: "#4ade80",
    custom: "#f59e0b",
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
    >
      <Card className="bg-[#141414] border-white/5 hover:border-white/10 transition-all cursor-pointer">
        <CardHeader className="pb-2" onClick={onView}>
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center"
                style={{ background: `${typeColors[report.type]}20` }}
              >
                <FormatIcon
                  className="w-4 h-4"
                  style={{ color: typeColors[report.type] }}
                />
              </div>
              <div>
                <CardTitle className="text-sm line-clamp-1">{report.title}</CardTitle>
                <CardDescription className="text-xs">
                  {report.mission_name}
                </CardDescription>
              </div>
            </div>
            <Badge
              variant="outline"
              className={cn(
                "text-xs shrink-0",
                report.status === "completed" && "border-green-500/50 text-green-400",
                report.status === "generating" && "border-blue-500/50 text-blue-400",
                report.status === "failed" && "border-red-500/50 text-red-400"
              )}
            >
              {report.status}
            </Badge>
          </div>
        </CardHeader>
        <CardContent onClick={onView}>
          {/* Findings Mini */}
          <div className="flex items-center gap-2 mb-3">
            {report.findings.critical > 0 && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/20 text-red-400">
                {report.findings.critical} Critical
              </span>
            )}
            {report.findings.high > 0 && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400">
                {report.findings.high} High
              </span>
            )}
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1 text-xs text-gray-500">
              <Calendar className="w-3 h-3" />
              {new Date(report.created_at).toLocaleDateString()}
            </div>
            <div className="flex items-center gap-1">
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-2"
                onClick={(e) => {
                  e.stopPropagation();
                  onDownload();
                }}
              >
                <Download className="w-3 h-3" />
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-2"
                onClick={(e) => {
                  e.stopPropagation();
                  onView();
                }}
              >
                <Eye className="w-3 h-3" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ============================================
// Sample Data (Demo Mode)
// ============================================

function getSampleReports(): Report[] {
  return [
    {
      id: "report-1",
      mission_id: "mission-abc-123",
      mission_name: "Corporate Network Assessment",
      title: "Q4 2024 Penetration Test Report",
      type: "technical",
      status: "completed",
      created_at: new Date(Date.now() - 86400000).toISOString(),
      completed_at: new Date(Date.now() - 80000000).toISOString(),
      findings: { critical: 2, high: 5, medium: 12, low: 8 },
      format: "pdf",
      size_bytes: 2456789,
    },
    {
      id: "report-2",
      mission_id: "mission-def-456",
      mission_name: "Web Application Security",
      title: "Executive Summary - Web App Assessment",
      type: "executive",
      status: "completed",
      created_at: new Date(Date.now() - 172800000).toISOString(),
      completed_at: new Date(Date.now() - 170000000).toISOString(),
      findings: { critical: 1, high: 3, medium: 7, low: 4 },
      format: "pdf",
      size_bytes: 1234567,
    },
    {
      id: "report-3",
      mission_id: "mission-ghi-789",
      mission_name: "Cloud Infrastructure Review",
      title: "AWS Security Compliance Report",
      type: "compliance",
      status: "generating",
      created_at: new Date(Date.now() - 3600000).toISOString(),
      findings: { critical: 0, high: 2, medium: 5, low: 3 },
      format: "html",
    },
  ];
}

export { Reports };
