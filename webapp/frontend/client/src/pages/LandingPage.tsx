// RAGLOX v3.0 - Landing Page
// Public landing page for visitors with login/register options

import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import {
  Shield,
  Target,
  Zap,
  ArrowRight,
  Activity,
  Lock,
  Globe,
  Server,
  Users,
  CheckCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/stores/authStore";

export default function LandingPage() {
  const [, setLocation] = useLocation();
  const { isAuthenticated, checkAuth } = useAuth();
  const [isChecking, setIsChecking] = useState(true);

  // Check if user is already authenticated and redirect to dashboard
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

  // Redirect if user becomes authenticated
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
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/80 backdrop-blur-sm fixed top-0 left-0 right-0 z-50">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-primary" />
            <span className="font-bold text-xl">RAGLOX</span>
            <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded ml-2">
              v3.0
            </span>
          </div>
          <nav className="flex items-center gap-4">
            <Button variant="ghost" onClick={() => setLocation("/login")}>
              Sign In
            </Button>
            <Button variant="default" onClick={() => setLocation("/register")}>
              Get Started
            </Button>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4">
        <div className="container max-w-5xl text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="inline-flex items-center gap-2 bg-primary/10 text-primary px-4 py-2 rounded-full mb-6">
              <Zap className="w-4 h-4" />
              <span className="text-sm font-medium">Enterprise Security Platform</span>
            </div>
            <h1 className="text-5xl md:text-6xl font-bold mb-6 leading-tight">
              <span className="text-primary">AI-Powered</span> Security
              <br />
              Operations Platform
            </h1>
            <p className="text-xl text-muted-foreground mb-8 max-w-3xl mx-auto">
              RAGLOX is an autonomous penetration testing platform that combines
              AI intelligence with human oversight for enterprise-grade security operations.
              Deploy your dedicated security VM in minutes.
            </p>
            <div className="flex items-center justify-center gap-4">
              <Button size="lg" onClick={() => setLocation("/register")} className="gap-2">
                <Zap className="w-5 h-5" />
                Start Free Trial
              </Button>
              <Button size="lg" variant="outline" onClick={() => setLocation("/login")} className="gap-2">
                <ArrowRight className="w-5 h-5" />
                Sign In
              </Button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-12 px-4 border-y border-border bg-muted/30">
        <div className="container">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <StatItem value="99.9%" label="Uptime SLA" />
            <StatItem value="8GB+" label="RAM per VM" />
            <StatItem value="24/7" label="Monitoring" />
            <StatItem value="50+" label="Global Locations" />
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 px-4">
        <div className="container">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Enterprise-Grade Security Infrastructure
            </h2>
            <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
              Get your dedicated security VM with pre-configured tools and AI-powered analysis
            </p>
          </div>
          <div className="grid md:grid-cols-3 gap-6">
            <FeatureCard
              icon={Target}
              title="Autonomous Reconnaissance"
              description="AI-driven reconnaissance that discovers targets, services, and vulnerabilities automatically with zero configuration."
            />
            <FeatureCard
              icon={Shield}
              title="Human-in-the-Loop"
              description="Critical actions require human approval, ensuring safe and controlled operations with full audit trails."
            />
            <FeatureCard
              icon={Activity}
              title="Real-time Monitoring"
              description="Live updates via WebSocket, terminal output, and comprehensive event logging for full visibility."
            />
            <FeatureCard
              icon={Server}
              title="Dedicated VM"
              description="Each user gets a dedicated VM with 8GB RAM and 2 CPU cores, isolated and secure environment."
            />
            <FeatureCard
              icon={Globe}
              title="Global Locations"
              description="Choose from multiple worldwide locations for your security VM to optimize latency and compliance."
            />
            <FeatureCard
              icon={Lock}
              title="Enterprise Security"
              description="End-to-end encryption, SOC2 compliant infrastructure, and comprehensive access controls."
            />
          </div>
        </div>
      </section>

      {/* VM Specs Section */}
      <section className="py-20 px-4 bg-muted/30">
        <div className="container max-w-4xl">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Your Dedicated Security VM
            </h2>
            <p className="text-muted-foreground text-lg">
              Every account includes a fully managed security VM
            </p>
          </div>
          <Card className="bg-card border-primary/20">
            <CardContent className="p-8">
              <div className="grid md:grid-cols-2 gap-8">
                <div>
                  <h3 className="text-xl font-semibold mb-4">VM Specifications</h3>
                  <ul className="space-y-3">
                    <SpecItem text="8 GB DDR4 RAM" />
                    <SpecItem text="2 vCPU Cores" />
                    <SpecItem text="Ubuntu 22.04 LTS" />
                    <SpecItem text="100 GB SSD Storage" />
                    <SpecItem text="1 Gbps Network" />
                    <SpecItem text="IPv4 & IPv6 Support" />
                  </ul>
                </div>
                <div>
                  <h3 className="text-xl font-semibold mb-4">Pre-installed Tools</h3>
                  <ul className="space-y-3">
                    <SpecItem text="Nmap & Masscan" />
                    <SpecItem text="Metasploit Framework" />
                    <SpecItem text="Nuclei Scanner" />
                    <SpecItem text="Custom RAGLOX Agent" />
                    <SpecItem text="Python 3.12+ Environment" />
                    <SpecItem text="Docker & Kubernetes" />
                  </ul>
                </div>
              </div>
              <div className="mt-8 pt-8 border-t border-border text-center">
                <Button size="lg" onClick={() => setLocation("/register")} className="gap-2">
                  <Zap className="w-5 h-5" />
                  Get Your VM Now
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4">
        <div className="container max-w-3xl text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            Ready to Start?
          </h2>
          <p className="text-muted-foreground text-lg mb-8">
            Create your account and get your dedicated security VM deployed in minutes.
          </p>
          <div className="flex items-center justify-center gap-4">
            <Button size="lg" onClick={() => setLocation("/register")} className="gap-2">
              <Users className="w-5 h-5" />
              Create Account
            </Button>
            <Button size="lg" variant="outline" onClick={() => setLocation("/login")} className="gap-2">
              <Lock className="w-5 h-5" />
              Sign In
            </Button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-12 bg-card">
        <div className="container">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-primary" />
              <span className="font-bold">RAGLOX</span>
              <span className="text-xs text-muted-foreground">v3.0</span>
            </div>
            <p className="text-sm text-muted-foreground">
              © {new Date().getFullYear()} RAGLOX. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

// Stat Item Component
function StatItem({ value, label }: { value: string; label: string }) {
  return (
    <div className="text-center">
      <div className="text-3xl font-bold text-primary">{value}</div>
      <div className="text-sm text-muted-foreground">{label}</div>
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

// Spec Item Component
function SpecItem({ text }: { text: string }) {
  return (
    <li className="flex items-center gap-2">
      <CheckCircle className="w-5 h-5 text-primary shrink-0" />
      <span>{text}</span>
    </li>
  );
}
