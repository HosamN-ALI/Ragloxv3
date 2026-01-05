// RAGLOX v3.0 - Artifact Cards Component (Manus Exact Style)
// Clean, minimal cards using Manus color palette

import { motion } from "framer-motion";
import { 
  Key, 
  Shield, 
  Terminal as TerminalIcon, 
  AlertTriangle,
  User,
  Server,
  Lock,
  Globe,
  Copy,
  ExternalLink,
  CheckCircle2,
  Eye,
  EyeOff
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useState } from "react";
import { toast } from "sonner";
// Using inline types for flexibility

// Credential Artifact Card
interface CredentialCardProps {
  credential: {
    id: string;
    username: string;
    password?: string;
    credential_type: string;
    service?: string;
    host?: string;
  };
  className?: string;
}

export function CredentialCard({ credential, className }: CredentialCardProps) {
  const [copied, setCopied] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success(`${label} copied`);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn("rounded-xl p-4", className)}
      style={{ background: '#1f1f1f', boxShadow: '0 4px 24px rgba(0,0,0,0.15)' }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <Lock className="w-4 h-4" style={{ color: '#888888' }} />
        <span className="text-xs font-mono" style={{ color: '#e8e8e8' }}>••••••••</span>
        <span 
          className="ml-auto px-2 py-0.5 text-xs rounded"
          style={{ background: '#2a2a2a', color: '#888888' }}
        >
          {credential.credential_type}
        </span>
      </div>

      {/* Service & Host */}
      {credential.service && (
        <div className="flex items-center gap-2 mb-3 text-xs" style={{ color: '#888888' }}>
          <Globe className="w-3.5 h-3.5" />
          <span>{credential.service}</span>
          {credential.host && (
            <>
              <span>@</span>
              <span className="font-mono">{credential.host}</span>
            </>
          )}
        </div>
      )}

      {/* Username */}
      <div className="flex items-center gap-2 py-1.5">
        <User className="w-4 h-4" style={{ color: '#888888' }} />
        <span className="font-mono text-sm flex-1" style={{ color: '#e8e8e8' }}>
          {credential.username}
        </span>
        <button
          onClick={() => handleCopy(credential.username, "Username")}
          className="p-1 rounded hover:bg-[#2a2a2a] transition-colors"
          style={{ color: '#888888' }}
        >
          <Copy className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Password */}
      <div className="flex items-center gap-2 py-1.5">
        <Key className="w-4 h-4" style={{ color: '#888888' }} />
        <span className="font-mono text-sm flex-1" style={{ color: '#e8e8e8' }}>
          {showPassword ? (credential.password || '(empty)') : '••••••••••••'}
        </span>
        <button
          onClick={() => setShowPassword(!showPassword)}
          className="p-1 rounded hover:bg-[#2a2a2a] transition-colors"
          style={{ color: '#888888' }}
        >
          {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
        </button>
        <button
          onClick={() => handleCopy(credential.password || '', "Password")}
          className="p-1 rounded hover:bg-[#2a2a2a] transition-colors"
          style={{ color: '#888888' }}
        >
          {copied ? <CheckCircle2 className="w-3.5 h-3.5" style={{ color: '#4ade80' }} /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
    </motion.div>
  );
}

// Session Artifact Card
interface SessionCardProps {
  session: {
    id: string;
    session_type: string;
    username: string;
    target_ip: string;
    port: number;
    status: string;
  };
  className?: string;
  onConnect?: (sessionId: string) => void;
}

export function SessionCard({ session, className, onConnect }: SessionCardProps) {
  const isActive = session.status === "active";

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn("rounded-xl p-4", className)}
      style={{ background: '#1f1f1f', boxShadow: '0 4px 24px rgba(0,0,0,0.15)' }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <TerminalIcon className="w-4 h-4" style={{ color: '#4ade80' }} />
        <span 
          className="px-2 py-0.5 text-xs font-medium rounded"
          style={{ background: 'rgba(74, 222, 128, 0.15)', color: '#4ade80' }}
        >
          SESSION
        </span>
        <span 
          className="px-2 py-0.5 text-xs rounded"
          style={{ background: '#2a2a2a', color: '#888888' }}
        >
          {session.session_type}
        </span>
        {isActive && (
          <div 
            className="w-2 h-2 rounded-full ml-auto"
            style={{ background: '#4a9eff' }}
          />
        )}
      </div>

      {/* User Info */}
      <div className="flex items-center gap-2 py-1.5">
        <User className="w-4 h-4" style={{ color: '#888888' }} />
        <span className="font-mono text-sm" style={{ color: '#e8e8e8' }}>
          {session.username}@{session.target_ip}
        </span>
      </div>

      {/* Connection Info */}
      <div className="flex items-center gap-2 py-1.5">
        <Server className="w-4 h-4" style={{ color: '#888888' }} />
        <span className="font-mono text-sm" style={{ color: '#e8e8e8' }}>
          {session.target_ip}:{session.port}
        </span>
      </div>

      {/* Connect Button */}
      {isActive && onConnect && (
        <button
          onClick={() => onConnect(session.id)}
          className="w-full mt-3 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors"
          style={{ background: '#2a2a2a', color: '#e8e8e8' }}
          onMouseEnter={(e) => e.currentTarget.style.background = '#3a3a3a'}
          onMouseLeave={(e) => e.currentTarget.style.background = '#2a2a2a'}
        >
          <ExternalLink className="w-3 h-3" />
          Connect
        </button>
      )}
    </motion.div>
  );
}

// Vulnerability Artifact Card
interface VulnerabilityCardProps {
  vulnerability: {
    id: string;
    name: string;
    severity: string;
    cve_id?: string;
    target_ip: string;
    port: number;
  };
  className?: string;
}

export function VulnerabilityCard({ vulnerability, className }: VulnerabilityCardProps) {
  const getSeverityStyle = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return { bg: '#ef4444', text: '#ffffff', badgeBg: 'rgba(239, 68, 68, 0.15)', badgeText: '#ef4444' };
      case 'high':
        return { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444', badgeBg: 'rgba(239, 68, 68, 0.15)', badgeText: '#ef4444' };
      case 'medium':
        return { bg: 'rgba(245, 158, 11, 0.15)', text: '#f59e0b', badgeBg: 'rgba(245, 158, 11, 0.15)', badgeText: '#f59e0b' };
      case 'low':
        return { bg: 'rgba(74, 222, 128, 0.15)', text: '#4ade80', badgeBg: 'rgba(74, 222, 128, 0.15)', badgeText: '#4ade80' };
      default:
        return { bg: '#2a2a2a', text: '#888888', badgeBg: '#2a2a2a', badgeText: '#888888' };
    }
  };

  const colors = getSeverityStyle(vulnerability.severity);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn("rounded-xl p-4", className)}
      style={{ background: '#1f1f1f', boxShadow: '0 4px 24px rgba(0,0,0,0.15)' }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <AlertTriangle className="w-4 h-4" style={{ color: '#EF4444' }} />
        <span 
          className="px-2 py-0.5 text-xs font-medium rounded"
          style={{ background: colors.badgeBg, color: colors.badgeText }}
        >
          VULNERABILITY
        </span>
        <span 
          className="px-2 py-0.5 text-xs font-bold rounded uppercase"
          style={{ background: colors.bg, color: colors.text }}
        >
          {vulnerability.severity}
        </span>
      </div>

      {/* Title */}
      <h4 className="text-base font-medium mb-2" style={{ color: '#e8e8e8' }}>
        {vulnerability.name}
      </h4>

      {/* CVE */}
      {vulnerability.cve_id && (
        <div className="flex items-center gap-2 py-1">
          <Shield className="w-4 h-4" style={{ color: '#888888' }} />
          <span className="font-mono text-sm" style={{ color: '#e8e8e8' }}>
            {vulnerability.cve_id}
          </span>
        </div>
      )}

      {/* Target */}
      <div className="flex items-center gap-2 py-1">
        <Server className="w-4 h-4" style={{ color: '#888888' }} />
        <span className="font-mono text-sm" style={{ color: '#e8e8e8' }}>
          {vulnerability.target_ip}:{vulnerability.port}
        </span>
      </div>
    </motion.div>
  );
}

// Target Artifact Card (for discovered hosts)
interface TargetCardProps {
  target: {
    id: string;
    ip: string;
    hostname?: string;
    os?: string;
    status: string;
    risk_score: number;
    open_ports: number[];
  };
  className?: string;
}

export function TargetCard({ target, className }: TargetCardProps) {
  const getRiskColor = (score: number) => {
    if (score >= 80) return '#EF4444';
    if (score >= 60) return '#F59E0B';
    if (score >= 40) return '#3B82F6';
    return '#10B981';
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn("rounded-xl p-4", className)}
      style={{ background: '#1f1f1f', boxShadow: '0 4px 24px rgba(0,0,0,0.15)' }}
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <Server className="w-4 h-4" style={{ color: '#3B82F6' }} />
        <span 
          className="px-2 py-0.5 text-xs font-medium rounded"
          style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#3B82F6' }}
        >
          TARGET
        </span>
        <span 
          className="px-2 py-0.5 text-xs rounded capitalize"
          style={{ background: '#2a2a2a', color: '#888888' }}
        >
          {target.status}
        </span>
        <span 
          className="ml-auto text-xs font-bold"
          style={{ color: getRiskColor(target.risk_score) }}
        >
          Risk: {target.risk_score}
        </span>
      </div>

      {/* IP Address */}
      <div className="flex items-center gap-2 py-1.5">
        <Globe className="w-4 h-4" style={{ color: '#888888' }} />
        <span className="font-mono text-sm" style={{ color: '#e8e8e8' }}>
          {target.ip}
        </span>
      </div>

      {/* Hostname */}
      {target.hostname && (
        <div className="flex items-center gap-2 py-1.5">
          <Server className="w-4 h-4" style={{ color: '#888888' }} />
          <span className="text-sm" style={{ color: '#e8e8e8' }}>
            {target.hostname}
          </span>
        </div>
      )}

      {/* OS */}
      {target.os && (
        <div className="flex items-center gap-2 py-1.5">
          <TerminalIcon className="w-4 h-4" style={{ color: '#888888' }} />
          <span className="text-sm" style={{ color: '#888888' }}>
            {target.os}
          </span>
        </div>
      )}

      {/* Open Ports */}
      {target.open_ports.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {target.open_ports.slice(0, 5).map(port => (
            <span 
              key={port} 
              className="text-xs px-2 py-0.5 rounded font-mono"
              style={{ background: '#2a2a2a', color: '#888888' }}
            >
              {port}
            </span>
          ))}
          {target.open_ports.length > 5 && (
            <span 
              className="text-xs px-2 py-0.5 rounded"
              style={{ background: '#2a2a2a', color: '#888888' }}
            >
              +{target.open_ports.length - 5}
            </span>
          )}
        </div>
      )}
    </motion.div>
  );
}

export default { CredentialCard, SessionCard, VulnerabilityCard, TargetCard };
