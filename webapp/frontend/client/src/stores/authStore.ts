// RAGLOX v3.0 - Authentication Store (Zustand)
// Centralized state management for authentication
// Updated for real API integration - NO DEMO/MOCK DATA

import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { User } from "@/types";
import { authApi, setAuthToken, clearAuth, getAuthToken } from "@/lib/api";

// ============================================
// Auth State Interface
// ============================================

interface AuthState {
  // State
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  // Actions
  login: (credentials: { email: string; password: string }) => Promise<boolean>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<boolean>;
  refreshToken: () => Promise<boolean>;
  clearError: () => void;
  setUser: (user: User | null) => void;
  setToken: (token: string | null) => void;
}

// ============================================
// Initial State
// ============================================

const initialState = {
  user: null,
  token: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,
};

// ============================================
// Auth Store
// ============================================

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      ...initialState,

      // ============================================
      // Login
      // ============================================
      login: async (credentials: { email: string; password: string }): Promise<boolean> => {
        set({ isLoading: true, error: null });

        try {
          const response = await authApi.login(credentials);

          set({
            user: response.user,
            token: response.access_token,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });

          return true;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : "Login failed";
          set({
            isLoading: false,
            error: errorMessage,
            isAuthenticated: false,
            user: null,
            token: null,
          });
          return false;
        }
      },

      // ============================================
      // Logout
      // ============================================
      logout: async (): Promise<void> => {
        set({ isLoading: true });

        try {
          // Call logout API if we have a token
          if (get().token) {
            await authApi.logout();
          }
        } catch (error) {
          console.error("[Auth] Logout error:", error);
        } finally {
          // Clear local state regardless of API result
          clearAuth();
          set({
            ...initialState,
            isLoading: false,
          });
        }
      },

      // ============================================
      // Check Authentication
      // ============================================
      checkAuth: async (): Promise<boolean> => {
        // Check if we have a stored token
        const storedToken = getAuthToken();
        if (!storedToken) {
          set({ isAuthenticated: false, user: null, token: null });
          return false;
        }

        set({ isLoading: true });

        try {
          // Verify token with backend
          const user = await authApi.me();

          set({
            user,
            token: storedToken,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });

          return true;
        } catch (error) {
          console.error("[Auth] Check auth error:", error);
          clearAuth();
          set({
            ...initialState,
            isLoading: false,
          });
          return false;
        }
      },

      // ============================================
      // Refresh Token
      // ============================================
      refreshToken: async (): Promise<boolean> => {
        try {
          const response = await authApi.refresh();

          set({
            token: response.access_token,
          });

          return true;
        } catch (error) {
          console.error("[Auth] Token refresh error:", error);
          // If refresh fails, logout
          await get().logout();
          return false;
        }
      },

      // ============================================
      // Utility Actions
      // ============================================
      clearError: () => set({ error: null }),

      setUser: (user: User | null) => set({ user, isAuthenticated: !!user }),

      setToken: (token: string | null) => {
        setAuthToken(token);
        set({ token });
      },
    }),
    {
      name: "raglox-auth",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated,
      }),
      onRehydrateStorage: () => (state) => {
        // After rehydration, sync the token with the API module
        if (state?.token) {
          setAuthToken(state.token);
        }
      },
    }
  )
);

// ============================================
// Listen for unauthorized events
// ============================================

if (typeof window !== "undefined") {
  window.addEventListener("auth:unauthorized", () => {
    console.log("[Auth] Unauthorized event received - logging out");
    useAuthStore.getState().logout();
  });
}

// ============================================
// Selectors
// ============================================

export const selectUser = (state: AuthState) => state.user;
export const selectIsAuthenticated = (state: AuthState) => state.isAuthenticated;
export const selectIsLoading = (state: AuthState) => state.isLoading;
export const selectError = (state: AuthState) => state.error;

// ============================================
// Helper Hooks
// ============================================

export function useAuth() {
  const user = useAuthStore((state) => state.user);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isLoading = useAuthStore((state) => state.isLoading);
  const error = useAuthStore((state) => state.error);
  const token = useAuthStore((state) => state.token);
  const login = useAuthStore((state) => state.login);
  const logout = useAuthStore((state) => state.logout);
  const checkAuth = useAuthStore((state) => state.checkAuth);
  const refreshToken = useAuthStore((state) => state.refreshToken);
  const clearError = useAuthStore((state) => state.clearError);
  const setUser = useAuthStore((state) => state.setUser);
  const setToken = useAuthStore((state) => state.setToken);

  return {
    user,
    isAuthenticated,
    isLoading,
    error,
    token,
    login,
    logout,
    checkAuth,
    refreshToken,
    clearError,
    setUser,
    setToken,
  };
}

export default useAuthStore;
