// RAGLOX v3.0 - Protected Route Component
// Wraps routes that require authentication
// NO DEMO MODE - Real authentication only

import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { Loader2, Shield } from "lucide-react";
import { useAuth } from "@/stores/authStore";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRole?: "admin" | "operator" | "analyst" | "viewer";
}

export function ProtectedRoute({ children, requiredRole }: ProtectedRouteProps) {
  const [, setLocation] = useLocation();
  const { isAuthenticated, isLoading, user, checkAuth } = useAuth();
  const [isChecking, setIsChecking] = useState(true);

  useEffect(() => {
    const verify = async () => {
      // Check authentication status
      const isAuth = await checkAuth();

      if (!isAuth) {
        setLocation("/login");
      }

      setIsChecking(false);
    };

    verify();
  }, [checkAuth, setLocation]);

  // Show loading state while checking auth
  if (isChecking || isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center animate-pulse">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Verifying authentication...</span>
          </div>
        </div>
      </div>
    );
  }

  // If not authenticated, redirect to login (handled in useEffect)
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
          <span className="text-muted-foreground">Redirecting to login...</span>
        </div>
      </div>
    );
  }

  // Check role if required
  if (requiredRole && user) {
    const roleHierarchy = ["viewer", "analyst", "operator", "admin"];
    const userRoleIndex = roleHierarchy.indexOf(user.role);
    const requiredRoleIndex = roleHierarchy.indexOf(requiredRole);

    if (userRoleIndex < requiredRoleIndex) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-destructive mb-2">Access Denied</h1>
            <p className="text-muted-foreground">
              You don't have permission to access this page.
            </p>
            <p className="text-sm text-muted-foreground mt-2">
              Required role: {requiredRole} | Your role: {user.role}
            </p>
          </div>
        </div>
      );
    }
  }

  // Render protected content
  return <>{children}</>;
}

export default ProtectedRoute;
