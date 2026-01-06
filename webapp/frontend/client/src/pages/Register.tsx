// RAGLOX v3.0 - Registration Page
// User registration with VM configuration selection

import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import {
  Shield,
  User,
  Mail,
  Lock,
  Building,
  Server,
  Globe,
  Cpu,
  HardDrive,
  Loader2,
  CheckCircle,
  ArrowLeft,
  Info,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { authApi } from "@/lib/api";
import { useAuth } from "@/stores/authStore";
import { toast } from "sonner";

// VM Location Options
const VM_LOCATIONS = [
  { id: "us-east", name: "US East (Virginia)", flag: "🇺🇸" },
  { id: "us-west", name: "US West (California)", flag: "🇺🇸" },
  { id: "eu-west", name: "EU West (Ireland)", flag: "🇪🇺" },
  { id: "eu-central", name: "EU Central (Frankfurt)", flag: "🇩🇪" },
  { id: "ap-southeast", name: "Asia Pacific (Singapore)", flag: "🇸🇬" },
  { id: "ap-northeast", name: "Asia Pacific (Tokyo)", flag: "🇯🇵" },
  { id: "me-south", name: "Middle East (Dubai)", flag: "🇦🇪" },
  { id: "sa-east", name: "South America (São Paulo)", flag: "🇧🇷" },
];

// VM Plan Options (fixed at 8GB-2CORE as per requirements)
const VM_PLANS = [
  {
    id: "8GB-2CORE",
    name: "Standard Security VM",
    ram: "8 GB RAM",
    cpu: "2 vCPU Cores",
    storage: "100 GB SSD",
    network: "1 Gbps",
    isDefault: true,
  },
];

// OS Options
const OS_OPTIONS = [
  { id: "ubuntu-22.04", name: "Ubuntu 22.04 LTS", description: "Recommended" },
  { id: "ubuntu-20.04", name: "Ubuntu 20.04 LTS", description: "Stable" },
  { id: "debian-12", name: "Debian 12", description: "Minimal" },
  { id: "kali-2024", name: "Kali Linux 2024", description: "Security-focused" },
];

export default function Register() {
  const [, setLocation] = useLocation();
  const { setToken, setUser, isAuthenticated, checkAuth } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [step, setStep] = useState<"account" | "vm">("account");
  const [isChecking, setIsChecking] = useState(true);

  // Account form state - ALL HOOKS MUST BE AT THE TOP
  const [formData, setFormData] = useState({
    email: "",
    password: "",
    confirmPassword: "",
    fullName: "",
    organization: "",
  });

  // VM configuration state
  const [vmConfig, setVmConfig] = useState({
    location: "us-east",
    plan: "8GB-2CORE",
    os: "ubuntu-22.04",
  });

  // Form validation
  const [errors, setErrors] = useState<Record<string, string>>({});

  // Redirect authenticated users to dashboard
  useEffect(() => {
    const verifyAuth = async () => {
      try {
        const authenticated = await checkAuth();
        if (authenticated) {
          setLocation("/dashboard");
        }
      } finally {
        setIsChecking(false);
      }
    };
    verifyAuth();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Early redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      setLocation("/dashboard");
    }
  }, [isAuthenticated, setLocation]);

  // Show loading while checking authentication
  if (isChecking) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <Shield className="w-12 h-12 text-primary animate-pulse" />
          <p className="text-muted-foreground">Checking authentication...</p>
        </div>
      </div>
    );
  }

  const validateAccountForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.email.trim()) {
      newErrors.email = "Email is required";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = "Invalid email format";
    }

    if (!formData.password) {
      newErrors.password = "Password is required";
    } else if (formData.password.length < 8) {
      newErrors.password = "Password must be at least 8 characters";
    }

    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match";
    }

    if (!formData.fullName.trim()) {
      newErrors.fullName = "Full name is required";
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleAccountSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validateAccountForm()) {
      setStep("vm");
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const response = await authApi.register({
        email: formData.email,
        password: formData.password,
        full_name: formData.fullName,
        organization: formData.organization || undefined,
        vm_config: {
          plan_id: vmConfig.plan,
          location_id: vmConfig.location,
          os_id: vmConfig.os,
        },
      });

      if (response.access_token) {
        setToken(response.access_token);
        setUser(response.user);
        toast.success("Account created successfully! Your VM is being provisioned.");
        setLocation("/dashboard");
      }
    } catch (error: any) {
      console.error("Registration error:", error);
      const message = error.message || "Registration failed. Please try again.";
      toast.error(message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-2 cursor-pointer" onClick={() => setLocation("/")}>
            <Shield className="w-8 h-8 text-primary" />
            <span className="font-bold text-xl">RAGLOX</span>
            <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded ml-2">
              v3.0
            </span>
          </div>
          <Button variant="ghost" onClick={() => setLocation("/login")}>
            Already have an account? Sign In
          </Button>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="w-full max-w-2xl">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            {/* Progress Indicator */}
            <div className="flex items-center justify-center gap-4 mb-8">
              <div className={`flex items-center gap-2 ${step === "account" ? "text-primary" : "text-muted-foreground"}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${step === "account" ? "bg-primary text-primary-foreground" : "bg-muted"}`}>
                  1
                </div>
                <span className="font-medium">Account</span>
              </div>
              <div className="w-16 h-0.5 bg-border" />
              <div className={`flex items-center gap-2 ${step === "vm" ? "text-primary" : "text-muted-foreground"}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center ${step === "vm" ? "bg-primary text-primary-foreground" : "bg-muted"}`}>
                  2
                </div>
                <span className="font-medium">VM Setup</span>
              </div>
            </div>

            <Card>
              <CardHeader className="text-center">
                <CardTitle className="text-2xl">
                  {step === "account" ? "Create Your Account" : "Configure Your Security VM"}
                </CardTitle>
                <CardDescription>
                  {step === "account"
                    ? "Enter your details to get started with RAGLOX"
                    : "Choose your VM specifications and location"}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {step === "account" ? (
                  <form onSubmit={handleAccountSubmit} className="space-y-4">
                    {/* Full Name */}
                    <div className="space-y-2">
                      <Label htmlFor="fullName">Full Name *</Label>
                      <div className="relative">
                        <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                          id="fullName"
                          placeholder="John Doe"
                          className="pl-10"
                          value={formData.fullName}
                          onChange={(e) => setFormData({ ...formData, fullName: e.target.value })}
                        />
                      </div>
                      {errors.fullName && (
                        <p className="text-sm text-destructive">{errors.fullName}</p>
                      )}
                    </div>

                    {/* Email */}
                    <div className="space-y-2">
                      <Label htmlFor="email">Email Address *</Label>
                      <div className="relative">
                        <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                          id="email"
                          type="email"
                          placeholder="john@example.com"
                          className="pl-10"
                          value={formData.email}
                          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                        />
                      </div>
                      {errors.email && (
                        <p className="text-sm text-destructive">{errors.email}</p>
                      )}
                    </div>

                    {/* Organization */}
                    <div className="space-y-2">
                      <Label htmlFor="organization">Organization (Optional)</Label>
                      <div className="relative">
                        <Building className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                          id="organization"
                          placeholder="Company Name"
                          className="pl-10"
                          value={formData.organization}
                          onChange={(e) => setFormData({ ...formData, organization: e.target.value })}
                        />
                      </div>
                    </div>

                    {/* Password */}
                    <div className="space-y-2">
                      <Label htmlFor="password">Password *</Label>
                      <div className="relative">
                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                          id="password"
                          type="password"
                          placeholder="••••••••"
                          className="pl-10"
                          value={formData.password}
                          onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                        />
                      </div>
                      {errors.password && (
                        <p className="text-sm text-destructive">{errors.password}</p>
                      )}
                    </div>

                    {/* Confirm Password */}
                    <div className="space-y-2">
                      <Label htmlFor="confirmPassword">Confirm Password *</Label>
                      <div className="relative">
                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                          id="confirmPassword"
                          type="password"
                          placeholder="••••••••"
                          className="pl-10"
                          value={formData.confirmPassword}
                          onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                        />
                      </div>
                      {errors.confirmPassword && (
                        <p className="text-sm text-destructive">{errors.confirmPassword}</p>
                      )}
                    </div>

                    <Button type="submit" className="w-full" size="lg">
                      Continue to VM Setup
                      <ArrowLeft className="w-4 h-4 ml-2 rotate-180" />
                    </Button>
                  </form>
                ) : (
                  <form onSubmit={handleRegister} className="space-y-6">
                    {/* VM Plan Info */}
                    <div className="p-4 bg-muted/50 rounded-lg border border-border">
                      <div className="flex items-start gap-3">
                        <Server className="w-5 h-5 text-primary mt-0.5" />
                        <div>
                          <h4 className="font-medium">Standard Security VM</h4>
                          <div className="grid grid-cols-2 gap-2 mt-2 text-sm text-muted-foreground">
                            <div className="flex items-center gap-1">
                              <Cpu className="w-4 h-4" />
                              <span>2 vCPU Cores</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <HardDrive className="w-4 h-4" />
                              <span>8 GB RAM</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <HardDrive className="w-4 h-4" />
                              <span>100 GB SSD</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <Globe className="w-4 h-4" />
                              <span>1 Gbps Network</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Location Selection */}
                    <div className="space-y-2">
                      <Label>VM Location *</Label>
                      <Select
                        value={vmConfig.location}
                        onValueChange={(value) => setVmConfig({ ...vmConfig, location: value })}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select location" />
                        </SelectTrigger>
                        <SelectContent>
                          {VM_LOCATIONS.map((location) => (
                            <SelectItem key={location.id} value={location.id}>
                              <div className="flex items-center gap-2">
                                <span>{location.flag}</span>
                                <span>{location.name}</span>
                              </div>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <p className="text-xs text-muted-foreground flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        Choose a location closest to your target infrastructure
                      </p>
                    </div>

                    {/* OS Selection */}
                    <div className="space-y-2">
                      <Label>Operating System *</Label>
                      <Select
                        value={vmConfig.os}
                        onValueChange={(value) => setVmConfig({ ...vmConfig, os: value })}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select OS" />
                        </SelectTrigger>
                        <SelectContent>
                          {OS_OPTIONS.map((os) => (
                            <SelectItem key={os.id} value={os.id}>
                              <div className="flex items-center gap-2">
                                <span>{os.name}</span>
                                <span className="text-xs text-muted-foreground">({os.description})</span>
                              </div>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    {/* Pre-installed Tools Notice */}
                    <div className="p-4 bg-primary/5 rounded-lg border border-primary/20">
                      <div className="flex items-start gap-3">
                        <CheckCircle className="w-5 h-5 text-primary mt-0.5" />
                        <div>
                          <h4 className="font-medium text-sm">Pre-installed Security Tools</h4>
                          <p className="text-xs text-muted-foreground mt-1">
                            Your VM will come with Nmap, Masscan, Metasploit, Nuclei, and the RAGLOX Agent pre-installed.
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Buttons */}
                    <div className="flex gap-3">
                      <Button
                        type="button"
                        variant="outline"
                        className="flex-1"
                        onClick={() => setStep("account")}
                        disabled={isLoading}
                      >
                        <ArrowLeft className="w-4 h-4 mr-2" />
                        Back
                      </Button>
                      <Button type="submit" className="flex-1" disabled={isLoading}>
                        {isLoading ? (
                          <>
                            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                            Creating Account...
                          </>
                        ) : (
                          <>
                            <CheckCircle className="w-4 h-4 mr-2" />
                            Create Account & Deploy VM
                          </>
                        )}
                      </Button>
                    </div>
                  </form>
                )}

                {/* Login Link */}
                <div className="mt-6 text-center text-sm text-muted-foreground">
                  Already have an account?{" "}
                  <Button variant="link" className="p-0 h-auto" onClick={() => setLocation("/login")}>
                    Sign In
                  </Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
