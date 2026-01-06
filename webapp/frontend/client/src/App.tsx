// RAGLOX v3.0 - Main Application
// Professional enterprise layout with separated public/protected routes
// NO DEMO/MOCK DATA - Real API integration only

import { useEffect } from "react";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { useAuthStore } from "./stores/authStore";
import { logConfig } from "./lib/config";

// Public Pages
import LandingPage from "./pages/LandingPage";
import Login from "./pages/Login";
import Register from "./pages/Register";

// Protected Pages - Core Dashboard
import Dashboard from "./pages/Dashboard";
import Operations from "./pages/Operations";
import Missions from "./pages/Missions";
import Knowledge from "./pages/Knowledge";
import Infrastructure from "./pages/Infrastructure";
import Exploitation from "./pages/Exploitation";
import Workflow from "./pages/Workflow";
import Tools from "./pages/Tools";
import Security from "./pages/Security";
import Reports from "./pages/Reports";
import Settings from "./pages/Settings";

// Log configuration on startup (development only)
if (import.meta.env.DEV) {
  logConfig();
}

function Router() {
  return (
    <Switch>
      {/* Public Routes - Landing, Login, Register */}
      <Route path="/" component={LandingPage} />
      <Route path="/login" component={Login} />
      <Route path="/register" component={Register} />

      {/* Protected Routes - Dashboard (Home after login) */}
      <Route path="/dashboard">
        <ProtectedRoute>
          <Dashboard />
        </ProtectedRoute>
      </Route>

      {/* Missions */}
      <Route path="/missions">
        <ProtectedRoute>
          <Missions />
        </ProtectedRoute>
      </Route>

      {/* Operations */}
      <Route path="/operations">
        <ProtectedRoute>
          <Operations />
        </ProtectedRoute>
      </Route>

      <Route path="/operations/:missionId">
        {() => (
          <ProtectedRoute>
            <Operations />
          </ProtectedRoute>
        )}
      </Route>

      {/* Infrastructure Management */}
      <Route path="/infrastructure">
        <ProtectedRoute>
          <Infrastructure />
        </ProtectedRoute>
      </Route>

      {/* Exploitation Tools */}
      <Route path="/exploitation">
        <ProtectedRoute>
          <Exploitation />
        </ProtectedRoute>
      </Route>

      {/* Workflow Engine */}
      <Route path="/workflow">
        <ProtectedRoute>
          <Workflow />
        </ProtectedRoute>
      </Route>

      <Route path="/workflow/:missionId">
        {() => (
          <ProtectedRoute>
            <Workflow />
          </ProtectedRoute>
        )}
      </Route>

      {/* Tools Library */}
      <Route path="/tools">
        <ProtectedRoute>
          <Tools />
        </ProtectedRoute>
      </Route>

      {/* Knowledge Base */}
      <Route path="/knowledge">
        <ProtectedRoute>
          <Knowledge />
        </ProtectedRoute>
      </Route>

      {/* Security Dashboard */}
      <Route path="/security">
        <ProtectedRoute>
          <Security />
        </ProtectedRoute>
      </Route>

      {/* Reports */}
      <Route path="/reports">
        <ProtectedRoute>
          <Reports />
        </ProtectedRoute>
      </Route>

      <Route path="/reports/:reportId">
        {() => (
          <ProtectedRoute>
            <Reports />
          </ProtectedRoute>
        )}
      </Route>

      {/* Settings */}
      <Route path="/settings">
        <ProtectedRoute>
          <Settings />
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
    checkAuth();
  }, [checkAuth]);

  return (
    <TooltipProvider>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#141414',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            color: '#ffffff',
          },
          classNames: {
            success: 'border-green-500/30',
            error: 'border-red-500/30',
            warning: 'border-yellow-500/30',
            info: 'border-blue-500/30',
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
