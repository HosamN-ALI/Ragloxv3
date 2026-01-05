// RAGLOX v3.0 - Main Application
// Updated with authentication routes and protected routes

import { useEffect } from "react";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { useAuthStore } from "./stores/authStore";
import { AUTH_ENABLED, logConfig } from "./lib/config";

// Pages
import Home from "./pages/Home";
import Operations from "./pages/Operations";
import Missions from "./pages/Missions";
import Knowledge from "./pages/Knowledge";
import Login from "./pages/Login";

// Log configuration on startup (development only)
if (import.meta.env.DEV) {
  logConfig();
}

function Router() {
  return (
    <Switch>
      {/* Public Routes */}
      <Route path="/login" component={Login} />

      {/* Protected Routes */}
      <Route path="/">
        <ProtectedRoute>
          <Home />
        </ProtectedRoute>
      </Route>

      <Route path="/missions">
        <ProtectedRoute>
          <Missions />
        </ProtectedRoute>
      </Route>

      <Route path="/operations">
        <ProtectedRoute>
          <Operations />
        </ProtectedRoute>
      </Route>

      <Route path="/operations/:missionId">
        {(params) => (
          <ProtectedRoute>
            <Operations />
          </ProtectedRoute>
        )}
      </Route>

      <Route path="/knowledge">
        <ProtectedRoute>
          <Knowledge />
        </ProtectedRoute>
      </Route>

      {/* 404 */}
      <Route path="/404" component={NotFound} />
      <Route component={NotFound} />
    </Switch>
  );
}

function AppContent() {
  const checkAuth = useAuthStore((state) => state.checkAuth);

  // Check authentication on app load
  useEffect(() => {
    if (AUTH_ENABLED) {
      checkAuth();
    }
  }, [checkAuth]);

  return (
    <TooltipProvider>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: 'var(--card)',
            border: '1px solid var(--border)',
            color: 'var(--foreground)',
          },
        }}
      />
      <Router />
    </TooltipProvider>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <AppContent />
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
