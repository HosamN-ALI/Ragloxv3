// RAGLOX v3.0 - Tools Page
// Security Tools Library with Categories and Installation
// Professional enterprise-grade design

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Wrench,
  Search,
  Filter,
  Download,
  Check,
  Terminal,
  Shield,
  Bug,
  Key,
  Network,
  Radar,
  Loader2,
  ExternalLink,
  ChevronRight,
  Info,
  Package,
  Play,
  RefreshCw,
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
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  workflowApi,
  TOOL_CATEGORIES,
  type Tool,
  type ToolInstallResult,
} from "@/lib/workflowApi";

// ============================================
// Category Icons
// ============================================

const categoryIcons: Record<string, React.ElementType> = {
  recon: Search,
  scanner: Radar,
  exploit: Bug,
  post_exploit: Terminal,
  credential: Key,
  lateral: Network,
  utility: Wrench,
};

// ============================================
// Tools Page
// ============================================

export default function Tools() {
  const [isLoading, setIsLoading] = useState(true);
  const [tools, setTools] = useState<Tool[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [platformFilter, setPlatformFilter] = useState("all");
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null);
  const [isDetailDialogOpen, setIsDetailDialogOpen] = useState(false);

  // Install state
  const [isInstalling, setIsInstalling] = useState(false);
  const [installResults, setInstallResults] = useState<Record<string, ToolInstallResult>>({});
  const [selectedForInstall, setSelectedForInstall] = useState<Set<string>>(new Set());

  // Load tools
  useEffect(() => {
    loadTools();
  }, [categoryFilter, platformFilter]);

  const loadTools = async () => {
    setIsLoading(true);
    try {
      const params: { category?: string; platform?: string } = {};
      if (categoryFilter !== "all") params.category = categoryFilter;
      if (platformFilter !== "all") params.platform = platformFilter;

      const toolsData = await workflowApi.listTools(params);
      setTools(toolsData);
    } catch (error) {
      console.error("Failed to load tools:", error);
      // Demo mode - show sample tools
      setTools(getSampleTools());
    } finally {
      setIsLoading(false);
    }
  };

  // Filter tools
  const filteredTools = tools.filter((tool) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      tool.name.toLowerCase().includes(query) ||
      tool.description.toLowerCase().includes(query) ||
      tool.category.toLowerCase().includes(query)
    );
  });

  // Group tools by category
  const groupedTools = filteredTools.reduce((acc, tool) => {
    if (!acc[tool.category]) {
      acc[tool.category] = [];
    }
    acc[tool.category].push(tool);
    return acc;
  }, {} as Record<string, Tool[]>);

  // Toggle tool selection
  const toggleToolSelection = (toolName: string) => {
    const newSelection = new Set(selectedForInstall);
    if (newSelection.has(toolName)) {
      newSelection.delete(toolName);
    } else {
      newSelection.add(toolName);
    }
    setSelectedForInstall(newSelection);
  };

  // Install selected tools
  const handleInstallSelected = async () => {
    if (selectedForInstall.size === 0) {
      toast.error("Please select tools to install");
      return;
    }

    setIsInstalling(true);
    try {
      // Note: environmentId should come from a real environment
      const results = await workflowApi.installTools(
        "default-env",
        Array.from(selectedForInstall),
        platformFilter !== "all" ? platformFilter : "linux"
      );

      setInstallResults(results);
      toast.success(`Installed ${Object.keys(results).length} tools`);
      setSelectedForInstall(new Set());
    } catch (error) {
      toast.error("Failed to install tools");
    } finally {
      setIsInstalling(false);
    }
  };

  // Open tool details
  const handleToolClick = (tool: Tool) => {
    setSelectedTool(tool);
    setIsDetailDialogOpen(true);
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
            <Wrench className="w-6 h-6 text-orange-400" />
            <div>
              <h1 className="text-xl font-semibold text-white">Tools Library</h1>
              <p className="text-sm text-gray-500">
                Security & Penetration Testing Tools
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {selectedForInstall.size > 0 && (
              <Badge variant="secondary" className="mr-2">
                {selectedForInstall.size} selected
              </Badge>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={loadTools}
              disabled={isLoading}
            >
              <RefreshCw className={cn("w-4 h-4 mr-2", isLoading && "animate-spin")} />
              Refresh
            </Button>
            <Button
              size="sm"
              onClick={handleInstallSelected}
              disabled={selectedForInstall.size === 0 || isInstalling}
            >
              {isInstalling ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Download className="w-4 h-4 mr-2" />
              )}
              Install Selected
            </Button>
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
              placeholder="Search tools..."
              className="pl-9 bg-white/5 border-white/10"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger className="w-44 bg-white/5 border-white/10">
              <Filter className="w-4 h-4 mr-2" />
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Categories</SelectItem>
              {TOOL_CATEGORIES.map((cat) => (
                <SelectItem key={cat.id} value={cat.id}>
                  {cat.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={platformFilter} onValueChange={setPlatformFilter}>
            <SelectTrigger className="w-36 bg-white/5 border-white/10">
              <SelectValue placeholder="Platform" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Platforms</SelectItem>
              <SelectItem value="linux">Linux</SelectItem>
              <SelectItem value="windows">Windows</SelectItem>
              <SelectItem value="macos">macOS</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6">
          {isLoading ? (
            <div className="flex items-center justify-center h-full">
              <Loader2 className="w-8 h-8 animate-spin text-orange-400" />
            </div>
          ) : filteredTools.length === 0 ? (
            <EmptyState searchQuery={searchQuery} />
          ) : (
            <div className="space-y-8">
              {Object.entries(groupedTools).map(([category, categoryTools]) => {
                const catInfo = TOOL_CATEGORIES.find((c) => c.id === category);
                const Icon = categoryIcons[category] || Wrench;

                return (
                  <div key={category}>
                    {/* Category Header */}
                    <div className="flex items-center gap-2 mb-4">
                      <Icon className="w-5 h-5 text-orange-400" />
                      <h2 className="text-lg font-semibold text-white">
                        {catInfo?.name || category}
                      </h2>
                      <Badge variant="secondary" className="text-xs">
                        {categoryTools.length}
                      </Badge>
                    </div>

                    {/* Tools Grid */}
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                      {categoryTools.map((tool, index) => (
                        <ToolCard
                          key={tool.name}
                          tool={tool}
                          index={index}
                          isSelected={selectedForInstall.has(tool.name)}
                          onSelect={() => toggleToolSelection(tool.name)}
                          onClick={() => handleToolClick(tool)}
                          installResult={installResults[tool.name]}
                        />
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Tool Detail Dialog */}
        <Dialog open={isDetailDialogOpen} onOpenChange={setIsDetailDialogOpen}>
          <DialogContent className="max-w-lg">
            {selectedTool && (
              <>
                <DialogHeader>
                  <DialogTitle className="flex items-center gap-2">
                    <Package className="w-5 h-5 text-orange-400" />
                    {selectedTool.name}
                  </DialogTitle>
                  <DialogDescription>{selectedTool.description}</DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                  <div>
                    <Label>Category</Label>
                    <div className="mt-1">
                      <Badge variant="secondary">{selectedTool.category}</Badge>
                    </div>
                  </div>

                  <div>
                    <Label>Platforms</Label>
                    <div className="mt-1 flex flex-wrap gap-2">
                      {selectedTool.platforms.map((platform) => (
                        <Badge key={platform} variant="outline">
                          {platform}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {selectedTool.dependencies.length > 0 && (
                    <div>
                      <Label>Dependencies</Label>
                      <div className="mt-1 flex flex-wrap gap-2">
                        {selectedTool.dependencies.map((dep) => (
                          <Badge key={dep} variant="outline" className="text-xs">
                            {dep}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => setIsDetailDialogOpen(false)}
                  >
                    Close
                  </Button>
                  <Button
                    onClick={() => {
                      toggleToolSelection(selectedTool.name);
                      setIsDetailDialogOpen(false);
                    }}
                  >
                    {selectedForInstall.has(selectedTool.name) ? (
                      <>
                        <Check className="w-4 h-4 mr-2" />
                        Selected
                      </>
                    ) : (
                      <>
                        <Download className="w-4 h-4 mr-2" />
                        Select for Install
                      </>
                    )}
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

function Label({ children }: { children: React.ReactNode }) {
  return <p className="text-sm font-medium text-gray-400">{children}</p>;
}

function EmptyState({ searchQuery }: { searchQuery: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-full">
      <Wrench className="w-16 h-16 text-gray-600 mb-4" />
      <h3 className="text-lg font-medium text-white mb-2">No Tools Found</h3>
      <p className="text-gray-500 text-sm text-center max-w-md">
        {searchQuery
          ? `No tools match "${searchQuery}". Try a different search term.`
          : "Tools will appear here when loaded from the workflow engine."}
      </p>
    </div>
  );
}

interface ToolCardProps {
  tool: Tool;
  index: number;
  isSelected: boolean;
  onSelect: () => void;
  onClick: () => void;
  installResult?: ToolInstallResult;
}

function ToolCard({
  tool,
  index,
  isSelected,
  onSelect,
  onClick,
  installResult,
}: ToolCardProps) {
  const Icon = categoryIcons[tool.category] || Wrench;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.03 }}
    >
      <Card
        className={cn(
          "bg-[#141414] border-white/5 cursor-pointer transition-all hover:border-white/10",
          isSelected && "border-orange-500/50 bg-orange-500/5"
        )}
        onClick={onClick}
      >
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-2">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center"
                style={{ background: "rgba(251, 146, 60, 0.2)" }}
              >
                <Icon className="w-4 h-4 text-orange-400" />
              </div>
              <CardTitle className="text-sm">{tool.name}</CardTitle>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onSelect();
              }}
              className={cn(
                "w-5 h-5 rounded border flex items-center justify-center transition-all",
                isSelected
                  ? "bg-orange-500 border-orange-500"
                  : "border-gray-600 hover:border-orange-500/50"
              )}
            >
              {isSelected && <Check className="w-3 h-3 text-white" />}
            </button>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-gray-500 line-clamp-2 mb-3">
            {tool.description}
          </p>
          <div className="flex items-center justify-between">
            <div className="flex gap-1">
              {tool.platforms.slice(0, 2).map((platform) => (
                <Badge key={platform} variant="outline" className="text-[10px] px-1.5">
                  {platform}
                </Badge>
              ))}
            </div>
            {installResult && (
              <Badge
                variant={installResult.status === "installed" ? "default" : "secondary"}
                className="text-[10px]"
              >
                {installResult.status}
              </Badge>
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ============================================
// Sample Tools (Demo Mode)
// ============================================

function getSampleTools(): Tool[] {
  return [
    {
      name: "nmap",
      description: "Network exploration tool and security scanner",
      category: "recon",
      platforms: ["linux", "windows", "macos"],
      dependencies: [],
    },
    {
      name: "masscan",
      description: "Fast port scanner for large networks",
      category: "recon",
      platforms: ["linux"],
      dependencies: ["libpcap"],
    },
    {
      name: "nuclei",
      description: "Fast vulnerability scanner based on templates",
      category: "scanner",
      platforms: ["linux", "windows", "macos"],
      dependencies: [],
    },
    {
      name: "nikto",
      description: "Web server vulnerability scanner",
      category: "scanner",
      platforms: ["linux", "macos"],
      dependencies: ["perl"],
    },
    {
      name: "metasploit",
      description: "Penetration testing framework",
      category: "exploit",
      platforms: ["linux", "windows", "macos"],
      dependencies: ["ruby", "postgresql"],
    },
    {
      name: "sqlmap",
      description: "Automatic SQL injection tool",
      category: "exploit",
      platforms: ["linux", "windows", "macos"],
      dependencies: ["python"],
    },
    {
      name: "mimikatz",
      description: "Windows credential extraction tool",
      category: "credential",
      platforms: ["windows"],
      dependencies: [],
    },
    {
      name: "hashcat",
      description: "Advanced password recovery",
      category: "credential",
      platforms: ["linux", "windows"],
      dependencies: [],
    },
    {
      name: "proxychains",
      description: "TCP/DNS traffic routing through proxy",
      category: "lateral",
      platforms: ["linux", "macos"],
      dependencies: [],
    },
    {
      name: "chisel",
      description: "Fast TCP/UDP tunnel over HTTP",
      category: "lateral",
      platforms: ["linux", "windows", "macos"],
      dependencies: [],
    },
  ];
}

export { Tools };
