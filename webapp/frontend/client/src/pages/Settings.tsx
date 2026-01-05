// RAGLOX v3.0 - Settings Page
// Application Settings and Configuration
// Professional enterprise-grade design

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Settings as SettingsIcon,
  User,
  Bell,
  Shield,
  Key,
  Globe,
  Moon,
  Sun,
  Monitor,
  Save,
  RefreshCw,
  Check,
  AlertTriangle,
  Database,
  Wifi,
  Server,
  Loader2,
  Eye,
  EyeOff,
  Copy,
} from "lucide-react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/authStore";
import { useTheme } from "@/contexts/ThemeContext";
import {
  API_BASE_URL,
  WS_BASE_URL,
  AUTH_ENABLED,
  WS_ENABLED,
  DEMO_MODE,
} from "@/lib/config";

// ============================================
// Settings Page
// ============================================

export default function Settings() {
  const { user, isAuthenticated } = useAuthStore();
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState("profile");
  const [isSaving, setIsSaving] = useState(false);

  // Profile settings
  const [profile, setProfile] = useState({
    username: user?.username || "",
    email: user?.email || "",
    displayName: user?.displayName || "",
  });

  // Notification settings
  const [notifications, setNotifications] = useState({
    emailAlerts: true,
    pushNotifications: true,
    approvalRequests: true,
    missionUpdates: true,
    securityAlerts: true,
    weeklyReports: false,
  });

  // API settings
  const [apiSettings, setApiSettings] = useState({
    apiKey: "",
    showApiKey: false,
    timeout: 30,
    retryAttempts: 3,
    rateLimitWarning: true,
  });

  // Appearance settings
  const [appearance, setAppearance] = useState({
    theme: theme,
    compactMode: false,
    showTooltips: true,
    animationsEnabled: true,
    sidebarCollapsed: false,
  });

  // Security settings
  const [security, setSecurity] = useState({
    twoFactorEnabled: false,
    sessionTimeout: 60,
    ipWhitelisting: false,
    auditLogging: true,
  });

  // Update profile from user
  useEffect(() => {
    if (user) {
      setProfile({
        username: user.username || "",
        email: user.email || "",
        displayName: user.displayName || user.username || "",
      });
    }
  }, [user]);

  // Save settings
  const handleSave = async () => {
    setIsSaving(true);
    try {
      // Simulate API call
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Apply theme change
      if (appearance.theme !== theme) {
        setTheme(appearance.theme);
      }

      toast.success("Settings saved successfully");
    } catch (error) {
      toast.error("Failed to save settings");
    } finally {
      setIsSaving(false);
    }
  };

  // Copy API key
  const handleCopyApiKey = () => {
    if (apiSettings.apiKey) {
      navigator.clipboard.writeText(apiSettings.apiKey);
      toast.success("API key copied to clipboard");
    }
  };

  // Generate new API key
  const handleGenerateApiKey = async () => {
    const newKey = `raglox_${generateRandomString(32)}`;
    setApiSettings({ ...apiSettings, apiKey: newKey });
    toast.success("New API key generated");
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
            <SettingsIcon className="w-6 h-6 text-gray-400" />
            <div>
              <h1 className="text-xl font-semibold text-white">Settings</h1>
              <p className="text-sm text-gray-500">
                Manage your account and application preferences
              </p>
            </div>
          </div>

          <Button onClick={handleSave} disabled={isSaving}>
            {isSaving ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <Save className="w-4 h-4 mr-2" />
                Save Changes
              </>
            )}
          </Button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto">
          <Tabs
            value={activeTab}
            onValueChange={setActiveTab}
            className="flex h-full"
            orientation="vertical"
          >
            {/* Sidebar */}
            <TabsList
              className="flex-shrink-0 w-56 h-auto flex-col items-stretch gap-1 p-4 rounded-none"
              style={{
                background: "#0d0d0d",
                borderRight: "1px solid rgba(255,255,255,0.06)",
              }}
            >
              <TabsTrigger
                value="profile"
                className="justify-start gap-2 px-3 py-2"
              >
                <User className="w-4 h-4" />
                Profile
              </TabsTrigger>
              <TabsTrigger
                value="appearance"
                className="justify-start gap-2 px-3 py-2"
              >
                <Monitor className="w-4 h-4" />
                Appearance
              </TabsTrigger>
              <TabsTrigger
                value="notifications"
                className="justify-start gap-2 px-3 py-2"
              >
                <Bell className="w-4 h-4" />
                Notifications
              </TabsTrigger>
              <TabsTrigger
                value="security"
                className="justify-start gap-2 px-3 py-2"
              >
                <Shield className="w-4 h-4" />
                Security
              </TabsTrigger>
              <TabsTrigger
                value="api"
                className="justify-start gap-2 px-3 py-2"
              >
                <Key className="w-4 h-4" />
                API & Integration
              </TabsTrigger>
              <TabsTrigger
                value="system"
                className="justify-start gap-2 px-3 py-2"
              >
                <Server className="w-4 h-4" />
                System Info
              </TabsTrigger>
            </TabsList>

            {/* Main Content */}
            <div className="flex-1 p-6 overflow-auto">
              {/* Profile Tab */}
              <TabsContent value="profile" className="mt-0 space-y-6">
                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>Profile Information</CardTitle>
                    <CardDescription>
                      Update your account profile information
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center gap-4 mb-6">
                      <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                        <span className="text-2xl font-bold text-white">
                          {profile.username?.[0]?.toUpperCase() || "U"}
                        </span>
                      </div>
                      <div>
                        <h3 className="text-lg font-semibold text-white">
                          {profile.displayName || profile.username || "User"}
                        </h3>
                        <p className="text-sm text-gray-500">{profile.email || "No email set"}</p>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Username</Label>
                        <Input
                          value={profile.username}
                          onChange={(e) =>
                            setProfile({ ...profile, username: e.target.value })
                          }
                          placeholder="Enter username"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Display Name</Label>
                        <Input
                          value={profile.displayName}
                          onChange={(e) =>
                            setProfile({ ...profile, displayName: e.target.value })
                          }
                          placeholder="Enter display name"
                        />
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label>Email Address</Label>
                      <Input
                        type="email"
                        value={profile.email}
                        onChange={(e) =>
                          setProfile({ ...profile, email: e.target.value })
                        }
                        placeholder="Enter email address"
                      />
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Appearance Tab */}
              <TabsContent value="appearance" className="mt-0 space-y-6">
                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>Theme</CardTitle>
                    <CardDescription>
                      Choose your preferred color theme
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex gap-3">
                      {[
                        { value: "dark", label: "Dark", icon: Moon },
                        { value: "light", label: "Light", icon: Sun },
                        { value: "system", label: "System", icon: Monitor },
                      ].map((option) => (
                        <button
                          key={option.value}
                          onClick={() =>
                            setAppearance({ ...appearance, theme: option.value as any })
                          }
                          className={cn(
                            "flex flex-col items-center gap-2 p-4 rounded-lg border transition-all",
                            appearance.theme === option.value
                              ? "bg-blue-500/10 border-blue-500/50"
                              : "bg-white/5 border-white/10 hover:border-white/20"
                          )}
                        >
                          <option.icon className="w-5 h-5" />
                          <span className="text-sm">{option.label}</span>
                        </button>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>Display Options</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <SettingToggle
                      label="Compact Mode"
                      description="Use smaller UI elements"
                      checked={appearance.compactMode}
                      onCheckedChange={(v) =>
                        setAppearance({ ...appearance, compactMode: v })
                      }
                    />
                    <SettingToggle
                      label="Show Tooltips"
                      description="Display helpful tooltips on hover"
                      checked={appearance.showTooltips}
                      onCheckedChange={(v) =>
                        setAppearance({ ...appearance, showTooltips: v })
                      }
                    />
                    <SettingToggle
                      label="Animations"
                      description="Enable UI animations and transitions"
                      checked={appearance.animationsEnabled}
                      onCheckedChange={(v) =>
                        setAppearance({ ...appearance, animationsEnabled: v })
                      }
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Notifications Tab */}
              <TabsContent value="notifications" className="mt-0 space-y-6">
                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>Notification Preferences</CardTitle>
                    <CardDescription>
                      Choose which notifications you want to receive
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <SettingToggle
                      label="Email Alerts"
                      description="Receive important alerts via email"
                      checked={notifications.emailAlerts}
                      onCheckedChange={(v) =>
                        setNotifications({ ...notifications, emailAlerts: v })
                      }
                    />
                    <SettingToggle
                      label="Push Notifications"
                      description="Browser push notifications for real-time updates"
                      checked={notifications.pushNotifications}
                      onCheckedChange={(v) =>
                        setNotifications({ ...notifications, pushNotifications: v })
                      }
                    />
                    <SettingToggle
                      label="Approval Requests"
                      description="Notifications for pending HITL approvals"
                      checked={notifications.approvalRequests}
                      onCheckedChange={(v) =>
                        setNotifications({ ...notifications, approvalRequests: v })
                      }
                    />
                    <SettingToggle
                      label="Mission Updates"
                      description="Updates on mission progress and completion"
                      checked={notifications.missionUpdates}
                      onCheckedChange={(v) =>
                        setNotifications({ ...notifications, missionUpdates: v })
                      }
                    />
                    <SettingToggle
                      label="Security Alerts"
                      description="Critical security notifications"
                      checked={notifications.securityAlerts}
                      onCheckedChange={(v) =>
                        setNotifications({ ...notifications, securityAlerts: v })
                      }
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Security Tab */}
              <TabsContent value="security" className="mt-0 space-y-6">
                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>Security Settings</CardTitle>
                    <CardDescription>
                      Manage your account security preferences
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <SettingToggle
                      label="Two-Factor Authentication"
                      description="Add an extra layer of security to your account"
                      checked={security.twoFactorEnabled}
                      onCheckedChange={(v) =>
                        setSecurity({ ...security, twoFactorEnabled: v })
                      }
                    />
                    <SettingToggle
                      label="Audit Logging"
                      description="Log all security-related actions"
                      checked={security.auditLogging}
                      onCheckedChange={(v) =>
                        setSecurity({ ...security, auditLogging: v })
                      }
                    />
                    <SettingToggle
                      label="IP Whitelisting"
                      description="Restrict access to specific IP addresses"
                      checked={security.ipWhitelisting}
                      onCheckedChange={(v) =>
                        setSecurity({ ...security, ipWhitelisting: v })
                      }
                    />

                    <div className="space-y-2 pt-4 border-t border-white/5">
                      <Label>Session Timeout (minutes)</Label>
                      <Select
                        value={security.sessionTimeout.toString()}
                        onValueChange={(v) =>
                          setSecurity({ ...security, sessionTimeout: parseInt(v) })
                        }
                      >
                        <SelectTrigger className="w-40">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="30">30 minutes</SelectItem>
                          <SelectItem value="60">1 hour</SelectItem>
                          <SelectItem value="120">2 hours</SelectItem>
                          <SelectItem value="480">8 hours</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* API Tab */}
              <TabsContent value="api" className="mt-0 space-y-6">
                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>API Key</CardTitle>
                    <CardDescription>
                      Manage your API key for external integrations
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label>Your API Key</Label>
                      <div className="flex gap-2">
                        <div className="relative flex-1">
                          <Input
                            type={apiSettings.showApiKey ? "text" : "password"}
                            value={apiSettings.apiKey || "No API key generated"}
                            readOnly
                            className="pr-10 font-mono text-sm"
                          />
                          <button
                            onClick={() =>
                              setApiSettings({
                                ...apiSettings,
                                showApiKey: !apiSettings.showApiKey,
                              })
                            }
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white"
                          >
                            {apiSettings.showApiKey ? (
                              <EyeOff className="w-4 h-4" />
                            ) : (
                              <Eye className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                        <Button
                          variant="outline"
                          size="icon"
                          onClick={handleCopyApiKey}
                          disabled={!apiSettings.apiKey}
                        >
                          <Copy className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>

                    <Button variant="outline" onClick={handleGenerateApiKey}>
                      <RefreshCw className="w-4 h-4 mr-2" />
                      Generate New Key
                    </Button>

                    <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/30">
                      <div className="flex items-center gap-2 text-yellow-400 text-sm">
                        <AlertTriangle className="w-4 h-4" />
                        <span>
                          Keep your API key secure. Regenerating will invalidate the old key.
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>API Settings</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Timeout (seconds)</Label>
                        <Input
                          type="number"
                          value={apiSettings.timeout}
                          onChange={(e) =>
                            setApiSettings({
                              ...apiSettings,
                              timeout: parseInt(e.target.value) || 30,
                            })
                          }
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Retry Attempts</Label>
                        <Input
                          type="number"
                          value={apiSettings.retryAttempts}
                          onChange={(e) =>
                            setApiSettings({
                              ...apiSettings,
                              retryAttempts: parseInt(e.target.value) || 3,
                            })
                          }
                        />
                      </div>
                    </div>

                    <SettingToggle
                      label="Rate Limit Warnings"
                      description="Show warnings when approaching rate limits"
                      checked={apiSettings.rateLimitWarning}
                      onCheckedChange={(v) =>
                        setApiSettings({ ...apiSettings, rateLimitWarning: v })
                      }
                    />
                  </CardContent>
                </Card>
              </TabsContent>

              {/* System Info Tab */}
              <TabsContent value="system" className="mt-0 space-y-6">
                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>System Configuration</CardTitle>
                    <CardDescription>
                      Current system configuration and status
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <InfoRow label="Version" value="RAGLOX v3.0.0" />
                      <InfoRow label="API URL" value={API_BASE_URL} />
                      <InfoRow label="WebSocket URL" value={WS_BASE_URL} />
                      <InfoRow
                        label="Authentication"
                        value={AUTH_ENABLED ? "Enabled" : "Disabled"}
                        badge={AUTH_ENABLED}
                      />
                      <InfoRow
                        label="WebSocket"
                        value={WS_ENABLED ? "Enabled" : "Disabled"}
                        badge={WS_ENABLED}
                      />
                      <InfoRow
                        label="Demo Mode"
                        value={DEMO_MODE ? "Active" : "Inactive"}
                        badge={!DEMO_MODE}
                        badgeInvert
                      />
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-[#141414] border-white/5">
                  <CardHeader>
                    <CardTitle>Session Information</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <InfoRow
                        label="Authenticated"
                        value={isAuthenticated ? "Yes" : "No"}
                        badge={isAuthenticated}
                      />
                      <InfoRow label="User" value={user?.username || "Anonymous"} />
                      <InfoRow
                        label="Browser"
                        value={navigator.userAgent.split(" ").slice(-1)[0]}
                      />
                      <InfoRow
                        label="Platform"
                        value={navigator.platform}
                      />
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </div>
          </Tabs>
        </div>
      </div>
    </AppLayout>
  );
}

// ============================================
// Helper Components
// ============================================

interface SettingToggleProps {
  label: string;
  description: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}

function SettingToggle({
  label,
  description,
  checked,
  onCheckedChange,
}: SettingToggleProps) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm font-medium text-white">{label}</p>
        <p className="text-xs text-gray-500">{description}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}

interface InfoRowProps {
  label: string;
  value: string;
  badge?: boolean;
  badgeInvert?: boolean;
}

function InfoRow({ label, value, badge, badgeInvert }: InfoRowProps) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-white/5 last:border-0">
      <span className="text-sm text-gray-500">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-sm font-mono text-white">{value}</span>
        {badge !== undefined && (
          <div
            className={cn(
              "w-2 h-2 rounded-full",
              badgeInvert
                ? badge
                  ? "bg-gray-500"
                  : "bg-green-500"
                : badge
                ? "bg-green-500"
                : "bg-gray-500"
            )}
          />
        )}
      </div>
    </div>
  );
}

// ============================================
// Utilities
// ============================================

function generateRandomString(length: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

export { Settings };
