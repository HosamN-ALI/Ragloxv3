// RAGLOX v3.0 - Home Page (Redirect)
// This page redirects authenticated users to Dashboard
// Unauthenticated users are shown the Landing Page via App.tsx routing

import { useEffect } from "react";
import { useLocation } from "wouter";
import { Loader2, Shield } from "lucide-react";
import { useAuth } from "@/stores/authStore";

export default function Home() {
  const [, setLocation] = useLocation();
  const { isAuthenticated, isLoading, checkAuth } = useAuth();

  useEffect(() => {
    const check = async () => {
      const isAuth = await checkAuth();
      if (isAuth) {
        setLocation("/dashboard");
      } else {
        setLocation("/");
      }
    };
    check();
  }, [checkAuth, setLocation]);

  // Show loading while checking auth
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="flex flex-col items-center gap-4">
        <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center animate-pulse">
          <Shield className="w-8 h-8 text-primary" />
        </div>
        <div className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="w-4 h-4 animate-spin" />
          <span>Loading...</span>
        </div>
      </div>
    </div>
  );
}
