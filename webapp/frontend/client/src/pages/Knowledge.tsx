// RAGLOX v3.0 - Knowledge Base Browser
// Full integration with backend Knowledge API

import { useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Shield, 
  Search,
  Book,
  Code,
  Server,
  Bug,
  RefreshCw,
  Loader2,
  ChevronRight,
  Terminal,
  AlertTriangle,
  Info,
  ExternalLink,
  Copy,
  Check,
  Filter,
  Layers,
  Cpu,
  FileCode
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { knowledgeApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { 
  KnowledgeStats, 
  Technique, 
  RXModule, 
  Tactic, 
  NucleiTemplate 
} from "@/types";

// Severity colors
const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/50",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/50",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/50",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/50",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/50",
};

export default function Knowledge() {
  const [, setLocation] = useLocation();
  const [stats, setStats] = useState<KnowledgeStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("techniques");
  
  // Search and filter state
  const [searchQuery, setSearchQuery] = useState("");
  const [platformFilter, setPlatformFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  
  // Data state
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [modules, setModules] = useState<RXModule[]>([]);
  const [tactics, setTactics] = useState<Tactic[]>([]);
  const [nucleiTemplates, setNucleiTemplates] = useState<NucleiTemplate[]>([]);
  
  const tacticCountCache = useRef<Record<string, number>>({});
  
  // Detail view
  const [selectedModule, setSelectedModule] = useState<RXModule | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<NucleiTemplate | null>(null);

  useEffect(() => {
    loadStats();
    loadData();
  }, []);

  const loadStats = async () => {
    try {
      const data = await knowledgeApi.stats();
      setStats(data);
    } catch (error) {
      console.error("Failed to load stats:", error);
      toast.error("Failed to load knowledge base stats");
    }
  };

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [techniquesData, tacticsData, modulesData, nucleiData] = await Promise.allSettled([
        knowledgeApi.techniques.list({ limit: 100 }),
        knowledgeApi.tactics.list(),
        knowledgeApi.modules.list({ limit: 50 }),
        knowledgeApi.nuclei.list({ limit: 50 }),
      ]);

      if (techniquesData.status === "fulfilled") {
        setTechniques(techniquesData.value.items);
      }

      if (modulesData.status === "fulfilled") {
        setModules(modulesData.value.items);
      }

      if (nucleiData.status === "fulfilled") {
        setNucleiTemplates(nucleiData.value.items);
      }

      if (tacticsData.status === "fulfilled") {
        const baseTactics = tacticsData.value;
        const enrichedTactics = await Promise.all(
          baseTactics.map(async (tactic) => {
            const existingCount = tactic.technique_count ?? 0;

            if (existingCount > 0) {
              tacticCountCache.current[tactic.id] = existingCount;
              return tactic;
            }

            const cachedCount = tacticCountCache.current[tactic.id];
            if (cachedCount !== undefined) {
              return { ...tactic, technique_count: cachedCount };
            }

            try {
              const relatedTechniques = await knowledgeApi.tactics.getTechniques(tactic.id);
              const count = relatedTechniques.length;
              tacticCountCache.current[tactic.id] = count;
              return { ...tactic, technique_count: count };
            } catch (innerError) {
              console.error(`[Knowledge] Failed to fetch techniques for tactic ${tactic.id}:`, innerError);
              return tactic;
            }
          })
        );

        setTactics(enrichedTactics);
      }
    } catch (error) {
      console.error("Failed to load data:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      loadData();
      return;
    }
    
    setIsLoading(true);
    try {
      if (activeTab === "modules") {
        const results = await knowledgeApi.modules.search(searchQuery, {
          platform: platformFilter !== "all" ? platformFilter : undefined,
          limit: 50,
        });
        setModules(results);
      } else if (activeTab === "nuclei") {
        const results = await knowledgeApi.nuclei.search(searchQuery, {
          severity: severityFilter !== "all" ? severityFilter : undefined,
          limit: 50,
        });
        setNucleiTemplates(results);
      }
    } catch (error) {
      console.error("Search failed:", error);
      toast.error("Search failed");
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

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
            <Button variant="ghost" onClick={() => setLocation("/missions")}>
              Missions
            </Button>
            <Button variant="ghost" className="text-primary" onClick={() => setLocation("/knowledge")}>
              Knowledge
            </Button>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="container py-8">
        {/* Page Header with Stats */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Book className="w-8 h-8 text-primary" />
              Knowledge Base
            </h1>
            <p className="text-muted-foreground mt-1">
              Browse techniques, modules, and vulnerability templates
            </p>
          </div>
          <Button variant="outline" onClick={loadData} className="gap-2">
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
        </div>

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <StatsCard
              icon={Layers}
              label="Techniques"
              value={stats.total_techniques}
              color="text-blue-400"
            />
            <StatsCard
              icon={Code}
              label="RX Modules"
              value={stats.total_rx_modules}
              color="text-green-400"
            />
            <StatsCard
              icon={Cpu}
              label="Tactics"
              value={stats.total_tactics}
              color="text-purple-400"
            />
            <StatsCard
              icon={Bug}
              label="Nuclei Templates"
              value={stats.total_nuclei_templates}
              color="text-red-400"
            />
          </div>
        )}

        {/* Search and Filters */}
        <div className="flex items-center gap-4 mb-6">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search techniques, modules, CVEs..."
              className="pl-9"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            />
          </div>
          
          {activeTab === "modules" && (
            <Select value={platformFilter} onValueChange={setPlatformFilter}>
              <SelectTrigger className="w-40">
                <Server className="w-4 h-4 mr-2" />
                <SelectValue placeholder="Platform" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Platforms</SelectItem>
                <SelectItem value="windows">Windows</SelectItem>
                <SelectItem value="linux">Linux</SelectItem>
                <SelectItem value="macos">macOS</SelectItem>
              </SelectContent>
            </Select>
          )}
          
          {activeTab === "nuclei" && (
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-40">
                <AlertTriangle className="w-4 h-4 mr-2" />
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="info">Info</SelectItem>
              </SelectContent>
            </Select>
          )}
          
          <Button onClick={handleSearch} className="gap-2">
            <Search className="w-4 h-4" />
            Search
          </Button>
        </div>

        {/* Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid grid-cols-4 w-full max-w-lg">
            <TabsTrigger value="techniques" className="gap-2">
              <Layers className="w-4 h-4" />
              Techniques
            </TabsTrigger>
            <TabsTrigger value="modules" className="gap-2">
              <Code className="w-4 h-4" />
              Modules
            </TabsTrigger>
            <TabsTrigger value="tactics" className="gap-2">
              <Cpu className="w-4 h-4" />
              Tactics
            </TabsTrigger>
            <TabsTrigger value="nuclei" className="gap-2">
              <Bug className="w-4 h-4" />
              Nuclei
            </TabsTrigger>
          </TabsList>

          {isLoading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
              <span className="ml-3 text-muted-foreground">Loading...</span>
            </div>
          ) : (
            <>
              {/* Techniques Tab */}
              <TabsContent value="techniques" className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                  {techniques.slice(0, 30).map((technique) => (
                    <TechniqueCard key={technique.id} technique={technique} />
                  ))}
                </div>
                {techniques.length === 0 && (
                  <EmptyState message="No techniques found" />
                )}
              </TabsContent>

              {/* Modules Tab */}
              <TabsContent value="modules" className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                  {modules.slice(0, 30).map((module) => (
                    <ModuleCard 
                      key={module.rx_module_id} 
                      module={module} 
                      onClick={() => setSelectedModule(module)}
                    />
                  ))}
                </div>
                {modules.length === 0 && (
                  <EmptyState message="No modules found" />
                )}
              </TabsContent>

              {/* Tactics Tab */}
              <TabsContent value="tactics" className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
                  {tactics.map((tactic) => (
                    <TacticCard key={tactic.id} tactic={tactic} />
                  ))}
                </div>
                {tactics.length === 0 && (
                  <EmptyState message="No tactics found" />
                )}
              </TabsContent>

              {/* Nuclei Tab */}
              <TabsContent value="nuclei" className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                  {nucleiTemplates.slice(0, 30).map((template) => (
                    <NucleiCard 
                      key={template.template_id} 
                      template={template}
                      onClick={() => setSelectedTemplate(template)}
                    />
                  ))}
                </div>
                {nucleiTemplates.length === 0 && (
                  <EmptyState message="No templates found" />
                )}
              </TabsContent>
            </>
          )}
        </Tabs>
      </main>

      {/* Module Detail Dialog */}
      <Dialog open={!!selectedModule} onOpenChange={() => setSelectedModule(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-auto">
          {selectedModule && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Code className="w-5 h-5 text-primary" />
                  {selectedModule.technique_name}
                </DialogTitle>
                <DialogDescription>
                  {selectedModule.rx_module_id} | {selectedModule.technique_id}
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Description</h4>
                  <p className="text-sm text-muted-foreground">{selectedModule.description}</p>
                </div>
                <div>
                  <h4 className="font-semibold mb-2">Execution</h4>
                  <div className="flex flex-wrap gap-2 mb-2">
                    {selectedModule.execution.platforms.map((p) => (
                      <Badge key={p} variant="outline">{p}</Badge>
                    ))}
                    <Badge variant="secondary">{selectedModule.execution.executor_type}</Badge>
                    {selectedModule.execution.elevation_required && (
                      <Badge variant="destructive">Requires Elevation</Badge>
                    )}
                  </div>
                  <div className="relative">
                    <pre className="bg-muted p-3 rounded-lg text-xs overflow-x-auto">
                      <code>{selectedModule.execution.command}</code>
                    </pre>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="absolute top-2 right-2"
                      onClick={() => copyToClipboard(selectedModule.execution.command)}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
                {selectedModule.variables.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Variables</h4>
                    <div className="space-y-2">
                      {selectedModule.variables.map((v, i) => (
                        <div key={i} className="text-sm bg-muted/50 p-2 rounded">
                          <code className="text-primary">{v.name}</code>
                          <span className="text-muted-foreground ml-2">({v.type})</span>
                          {v.default_value && (
                            <span className="ml-2">= {v.default_value}</span>
                          )}
                          <p className="text-xs text-muted-foreground mt-1">{v.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Nuclei Template Detail Dialog */}
      <Dialog open={!!selectedTemplate} onOpenChange={() => setSelectedTemplate(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-auto">
          {selectedTemplate && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Bug className="w-5 h-5 text-red-400" />
                  {selectedTemplate.name}
                </DialogTitle>
                <DialogDescription className="flex items-center gap-2">
                  {selectedTemplate.template_id}
                  <Badge className={severityColors[selectedTemplate.severity.toLowerCase()]}>
                    {selectedTemplate.severity}
                  </Badge>
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                {selectedTemplate.description && (
                  <div>
                    <h4 className="font-semibold mb-2">Description</h4>
                    <p className="text-sm text-muted-foreground">{selectedTemplate.description}</p>
                  </div>
                )}
                <div className="flex flex-wrap gap-2">
                  {selectedTemplate.tags.map((tag) => (
                    <Badge key={tag} variant="outline">{tag}</Badge>
                  ))}
                </div>
                {Array.isArray(selectedTemplate.cve_id) && selectedTemplate.cve_id.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">CVE IDs</h4>
                    <div className="flex flex-wrap gap-2">
                      {selectedTemplate.cve_id.map((cve) => (
                        <Badge key={cve} variant="destructive">{cve}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                {selectedTemplate.cvss_score && (
                  <div>
                    <h4 className="font-semibold mb-2">CVSS Score</h4>
                    <Badge variant="outline" className="text-lg">
                      {selectedTemplate.cvss_score}
                    </Badge>
                  </div>
                )}
                {selectedTemplate.reference.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">References</h4>
                    <div className="space-y-1">
                      {selectedTemplate.reference.slice(0, 5).map((ref, i) => (
                        <a
                          key={i}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-sm text-primary hover:underline"
                        >
                          <ExternalLink className="w-3 h-3" />
                          {ref}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// Helper Components

function StatsCard({ 
  icon: Icon, 
  label, 
  value, 
  color 
}: { 
  icon: typeof Layers; 
  label: string; 
  value: number; 
  color: string;
}) {
  return (
    <Card className="bg-card/50">
      <CardContent className="flex items-center gap-4 p-4">
        <div className={cn("p-3 rounded-lg bg-muted", color)}>
          <Icon className="w-5 h-5" />
        </div>
        <div>
          <div className="text-2xl font-bold">{value.toLocaleString()}</div>
          <div className="text-sm text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function TechniqueCard({ technique }: { technique: Technique }) {
  return (
    <Card className="hover:border-primary/50 transition-colors">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Badge variant="outline" className="text-xs">{technique.id}</Badge>
          <span className="truncate">{technique.name}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-1 mb-2">
          {technique.platforms.slice(0, 3).map((p) => (
            <Badge key={p} variant="secondary" className="text-xs">{p}</Badge>
          ))}
        </div>
        <div className="text-xs text-muted-foreground">
          {technique.test_count} tests available
        </div>
      </CardContent>
    </Card>
  );
}

function ModuleCard({ module, onClick }: { module: RXModule; onClick: () => void }) {
  return (
    <Card 
      className="hover:border-primary/50 transition-colors cursor-pointer"
      onClick={onClick}
    >
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Code className="w-4 h-4 text-primary shrink-0" />
          <span className="truncate">{module.technique_name}</span>
        </CardTitle>
        <CardDescription className="text-xs truncate">
          {module.rx_module_id}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-1 mb-2">
          {module.execution.platforms.slice(0, 2).map((p) => (
            <Badge key={p} variant="secondary" className="text-xs">{p}</Badge>
          ))}
          <Badge variant="outline" className="text-xs">
            {module.execution.executor_type}
          </Badge>
        </div>
        <p className="text-xs text-muted-foreground line-clamp-2">
          {module.description}
        </p>
      </CardContent>
    </Card>
  );
}

function TacticCard({ tactic }: { tactic: Tactic }) {
  return (
    <Card className="hover:border-primary/50 transition-colors">
      <CardContent className="p-4 text-center">
        <Badge variant="outline" className="mb-2">{tactic.id}</Badge>
        <h3 className="font-medium text-sm mb-1">{tactic.name}</h3>
        <p className="text-xs text-muted-foreground">
          {tactic.technique_count} techniques
        </p>
      </CardContent>
    </Card>
  );
}

function NucleiCard({ template, onClick }: { template: NucleiTemplate; onClick: () => void }) {
  return (
    <Card 
      className="hover:border-primary/50 transition-colors cursor-pointer"
      onClick={onClick}
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between">
          <CardTitle className="text-sm truncate flex-1">
            {template.name}
          </CardTitle>
          <Badge 
            variant="outline" 
            className={cn("ml-2 shrink-0", severityColors[template.severity.toLowerCase()])}
          >
            {template.severity}
          </Badge>
        </div>
        <CardDescription className="text-xs truncate">
          {template.template_id}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-1">
          {template.tags.slice(0, 3).map((tag) => (
            <Badge key={tag} variant="secondary" className="text-xs">{tag}</Badge>
          ))}
          {template.tags.length > 3 && (
            <Badge variant="outline" className="text-xs">+{template.tags.length - 3}</Badge>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <Card className="text-center py-16">
      <CardContent>
        <Info className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
        <p className="text-muted-foreground">{message}</p>
      </CardContent>
    </Card>
  );
}
