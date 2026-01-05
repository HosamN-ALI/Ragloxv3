// RAGLOX v3.0 - Login Page
// Authentication page with username/password form

import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import { Shield, Eye, EyeOff, Loader2, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useAuth } from "@/stores/authStore";
import { AUTH_ENABLED } from "@/lib/config";

export default function Login() {
    const [, setLocation] = useLocation();
    const { login, isAuthenticated, isLoading, error, checkAuth, clearError } = useAuth();

    // Form state
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [formError, setFormError] = useState<string | null>(null);

    // Check if already authenticated
    useEffect(() => {
        const check = async () => {
            const isAuth = await checkAuth();
            if (isAuth) {
                setLocation("/");
            }
        };
        check();
    }, [checkAuth, setLocation]);

    // Redirect if authenticated
    useEffect(() => {
        if (isAuthenticated) {
            setLocation("/");
        }
    }, [isAuthenticated, setLocation]);

    // Clear errors when form changes
    useEffect(() => {
        if (formError) setFormError(null);
        if (error) clearError();
    }, [username, password]); // eslint-disable-line react-hooks/exhaustive-deps

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setFormError(null);

        // Validation
        if (!username.trim()) {
            setFormError("Username is required");
            return;
        }
        if (!password.trim()) {
            setFormError("Password is required");
            return;
        }

        // Attempt login
        const success = await login({ username: username.trim(), password });

        if (success) {
            setLocation("/");
        }
    };

    // If auth is disabled, show bypass option
    if (!AUTH_ENABLED) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background p-4">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5 }}
                >
                    <Card className="w-full max-w-md">
                        <CardHeader className="text-center">
                            <div className="flex justify-center mb-4">
                                <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                                    <Shield className="w-8 h-8 text-primary" />
                                </div>
                            </div>
                            <CardTitle className="text-2xl">RAGLOX v3.0</CardTitle>
                            <CardDescription>
                                Authentication is disabled in development mode
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <Alert className="mb-4">
                                <AlertCircle className="h-4 w-4" />
                                <AlertDescription>
                                    Auth is disabled. Click below to continue as demo user.
                                </AlertDescription>
                            </Alert>
                            <Button
                                className="w-full"
                                onClick={() => {
                                    login({ username: "demo", password: "demo" });
                                }}
                            >
                                Continue as Demo User
                            </Button>
                        </CardContent>
                    </Card>
                </motion.div>
            </div>
        );
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
                className="w-full max-w-md"
            >
                <Card>
                    <CardHeader className="text-center">
                        <div className="flex justify-center mb-4">
                            <motion.div
                                className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center"
                                whileHover={{ scale: 1.05 }}
                                whileTap={{ scale: 0.95 }}
                            >
                                <Shield className="w-8 h-8 text-primary" />
                            </motion.div>
                        </div>
                        <CardTitle className="text-2xl">Welcome to RAGLOX</CardTitle>
                        <CardDescription>
                            Sign in to access the security operations platform
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <form onSubmit={handleSubmit} className="space-y-4">
                            {/* Error Alert */}
                            {(error || formError) && (
                                <motion.div
                                    initial={{ opacity: 0, height: 0 }}
                                    animate={{ opacity: 1, height: "auto" }}
                                    exit={{ opacity: 0, height: 0 }}
                                >
                                    <Alert variant="destructive">
                                        <AlertCircle className="h-4 w-4" />
                                        <AlertDescription>{formError || error}</AlertDescription>
                                    </Alert>
                                </motion.div>
                            )}

                            {/* Username Field */}
                            <div className="space-y-2">
                                <Label htmlFor="username">Username</Label>
                                <Input
                                    id="username"
                                    type="text"
                                    placeholder="Enter your username"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    disabled={isLoading}
                                    autoComplete="username"
                                    autoFocus
                                />
                            </div>

                            {/* Password Field */}
                            <div className="space-y-2">
                                <Label htmlFor="password">Password</Label>
                                <div className="relative">
                                    <Input
                                        id="password"
                                        type={showPassword ? "text" : "password"}
                                        placeholder="Enter your password"
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        disabled={isLoading}
                                        autoComplete="current-password"
                                        className="pr-10"
                                    />
                                    <Button
                                        type="button"
                                        variant="ghost"
                                        size="sm"
                                        className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                                        onClick={() => setShowPassword(!showPassword)}
                                        disabled={isLoading}
                                    >
                                        {showPassword ? (
                                            <EyeOff className="h-4 w-4 text-muted-foreground" />
                                        ) : (
                                            <Eye className="h-4 w-4 text-muted-foreground" />
                                        )}
                                    </Button>
                                </div>
                            </div>

                            {/* Submit Button */}
                            <Button type="submit" className="w-full" disabled={isLoading}>
                                {isLoading ? (
                                    <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Signing in...
                                    </>
                                ) : (
                                    "Sign In"
                                )}
                            </Button>
                        </form>

                        {/* Footer */}
                        <div className="mt-6 text-center text-sm text-muted-foreground">
                            <p>RAGLOX v3.0 - AI-Powered Security Operations</p>
                        </div>
                    </CardContent>
                </Card>
            </motion.div>
        </div>
    );
}
