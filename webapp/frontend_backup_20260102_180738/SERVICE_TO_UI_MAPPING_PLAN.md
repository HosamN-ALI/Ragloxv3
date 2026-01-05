# RAGLOX v3.0 - Service-to-UI Mapping Plan

## Executive Summary

This document outlines the comprehensive UI architecture for RAGLOX v3.0, translating backend capabilities into a mature, professional command center interface inspired by Palantir and Metasploit Pro.

---

## 🎯 Backend Capabilities → UI Mapping

### Backend Services

| Service | Capability | UI Component | Workspace |
|---------|------------|--------------|-----------|
| ReconSpecialist | Network scanning, port discovery, service enumeration | AssetCard, ReconView | A: Scope & Recon |
| AttackSpecialist | Exploitation, credential access | MissionTimeline, OperationsView | B: Operations |
| PostExSpecialist | Credential harvesting, file extraction | CredentialVault, SessionTerminal | C: Loot & Access |
| WebSocket API | Real-time events, status updates | All workspaces (live updates) | Global |
| HITL Controller | Approval workflow, decision points | HITLApprovalModal, DecisionRoom | B: Operations |
| Mission Controller | Start/stop/pause, emergency stop | EmergencyStop, StatusIndicator | B: Operations |

---

## 🏗️ The 4 Workspaces Architecture

### Workspace A: Scope & Recon (`/recon`)

**Purpose:** Asset discovery and reconnaissance data visualization

**Components:**
```
ReconView/
├── StatsBar          # Quick metrics (targets, ports, vulns, owned)
├── Toolbar           # Search, filter, view toggle
├── AssetCardGrid     # Main asset visualization
│   └── AssetCard     # Individual target card
│       ├── OS Icon   # Platform indicator
│       ├── IP/Host   # Network identity
│       ├── Ports     # Open services badges
│       └── RiskScore # Visual risk indicator
└── DeepDiveDrawer    # Raw recon data panel
```

**Data Flow:**
```
Backend Events → eventStore → ReconView
├── new_target → targets Map → AssetCardGrid
├── new_vuln → vulnerabilities Map → VulnBadges
└── statistics → missionStats → StatsBar
```

**Grouping Options:**
- By OS Family (Linux vs Windows)
- By Criticality (Critical → Low)
- By Status (Discovered → Owned)
- By Subnet (/24 groups)

---

### Workspace B: Active Operations (`/operations`)

**Purpose:** Mission timeline, HITL decisions, system control

**Components:**
```
OperationsView/
├── QuickStats        # Phase, completed, pending, goals
├── MissionTimeline   # Structured progress view
│   ├── PhaseProgress # Visual phase indicator
│   ├── FilterControls
│   └── TimelineEventItem
│       ├── StatusIcon
│       ├── PhaseBadge
│       └── Metadata (expandable)
├── DecisionRoom      # HITL approval panel
│   └── RiskModal     # Action approval dialog
└── EmergencyStop     # Kill switch control
    ├── StatusIndicator
    ├── HoldToAbort (2-sec hold)
    └── ConfirmationModal
```

**Timeline Event Types:**
| Event Type | Icon | Color | Significance |
|------------|------|-------|--------------|
| phase_start | Zap | Cyan | Phase transition |
| target_discovered | Target | Blue | New asset found |
| vuln_found | AlertTriangle | Orange | Vulnerability detected |
| exploit_success | CheckCircle | Green | Successful exploitation |
| session_established | Terminal | Green | Shell access gained |
| credential_harvested | Key | Yellow | Creds extracted |
| approval_required | Shield | Amber | HITL decision needed |
| goal_achieved | CheckCircle | Emerald | Objective completed |

**HITL Decision Room:**
```
┌─────────────────────────────────────────────┐
│ ⚠️ DECISION REQUIRED                        │
│                                             │
│ Target: 172.28.0.100                        │
│ Action: Brute Force SSH                     │
│ Risk:   HIGH (Account Lockout)              │
│                                             │
│ AI Recommendation: "Proceed with caution.   │
│ Rate limit to 5 attempts per minute."       │
│                                             │
│ [Deny]                    [Review & Approve]│
└─────────────────────────────────────────────┘
```

---

### Workspace C: Loot & Access (`/loot`)

**Purpose:** Session management, credential vault, artifact gallery

**Components:**
```
LootView/
├── LootStats         # Sessions, creds, artifacts counts
├── TabNavigation     # Sessions | Credentials | Artifacts
├── SessionManager
│   ├── SessionCard   # Session list item
│   │   ├── TypeIcon  # Shell/SSH/Meterpreter
│   │   ├── User@Host
│   │   └── Privilege # root/user badge
│   └── SessionTerminalWindow
│       ├── TerminalHeader
│       └── xterm.js terminal
├── CredentialVault
│   ├── FilterBar
│   └── CredentialRow
│       ├── TypeIcon  # Password/Hash/Key
│       ├── Username
│       ├── PasswordDisplay (masked + reveal)
│       ├── Source    # ~/.db_creds
│       ├── Privilege # root/admin/user
│       └── ValidationStatus # ✅ Verified
└── ArtifactsGallery
    ├── FileList (grouped by target)
    └── PreviewPanel
```

**Credential Vault Columns:**
| Column | Description |
|--------|-------------|
| Type | password / ssh_key / ntlm / kerberos |
| Username | Account identifier |
| Password/Hash | Masked (••••••) + Reveal button |
| Source | File path where found |
| Privilege | root / admin / user badge |
| Status | ✅ Verified / ⏳ Testing / ❌ Invalid |

**Session Terminal Features:**
- Real-time command execution
- Copy output to clipboard
- Clear terminal
- Kill session
- Maximize/minimize window

---

### Workspace D: Intelligence Sidebar (`/intelligence`)

**Purpose:** Persistent AI co-pilot with insights and recommendations

**Components:**
```
IntelligenceSidebar/
├── Header            # AI Co-pilot branding
├── TabNavigation     # Insights | Chat
├── ContextSummary    # Current mission state
├── InsightsList
│   └── InsightCard
│       ├── TypeBadge # Finding/Recommendation/Warning
│       ├── Title
│       ├── Description
│       └── SuggestedAction
└── ChatInterface
    ├── MessageList
    │   └── ChatMessageItem
    └── InputArea
```

**Insight Types:**
| Type | Icon | Color | Purpose |
|------|------|-------|---------|
| Finding | Eye | Cyan | Discovered information |
| Recommendation | Lightbulb | Yellow | Suggested actions |
| Warning | AlertTriangle | Orange | Risk alerts |
| Opportunity | TrendingUp | Green | Attack vectors |

**Example Insights:**
```
💡 RECOMMENDATION
"I found database credentials in a flat file (~/.db_creds).
Consider pivoting to the Database service next."
→ [Pivot to Database]

⚠️ WARNING  
"Multiple failed login attempts detected. Reduce scan
intensity to avoid triggering alerts."

📈 OPPORTUNITY
"SSH with password authentication enabled on 3 targets.
High success rate for credential stuffing."
→ [Launch SSH Brute Force]
```

---

## 🚨 UX Gap Solutions

### 1. Emergency Stop (Kill Switch)

**Design:**
```
┌─────────────────────────┐
│   [🟢 System Armed]     │  ← Status when idle
│                         │
│      ┌───────┐          │
│      │  ⛔   │          │  ← Hold 2 seconds
│      │ HOLD  │          │     to activate
│      └───────┘          │
│                         │
│ Hold for 2 sec to stop  │
└─────────────────────────┘

┌─────────────────────────┐
│   [🔴 Active Attack]    │  ← Status when running
│      ▓▓▓▓▓░░░░          │     (pulsing)
│                         │
│      ┌───────┐          │
│      │  1.2s │          │  ← Countdown while
│      │   ⛔   │          │     holding
│      └───────┘          │
│                         │
│  [Pause]    [Resume]    │  ← Secondary controls
└─────────────────────────┘
```

**Implementation:**
- `HoldToAbortButton`: 2-second press with visual progress ring
- `ConfirmationModal`: 2-step confirmation for click mode
- `StatusIndicator`: Real-time system status display

### 2. Exploitability Matrix

**Design:**
```
┌────────────────────────────────────────────────────┐
│ EXPLOITABILITY MATRIX                               │
├────────────────────────────────────────────────────┤
│                                                     │
│  [SSH Weak Creds] ──────────> [Full Shell Access]  │
│         │                            │              │
│         ▼                            ▼              │
│  [Credential Reuse] ──────> [Lateral Movement]     │
│         │                            │              │
│         ▼                            ▼              │
│  [DB Access] ────────────> [Data Exfiltration]     │
│                                                     │
│  Legend: ━━━ High Probability  ─ ─ ─ Low Prob.     │
└────────────────────────────────────────────────────┘
```

### 3. Mission Setup Wizard (Empty State)

**Flow:**
```
┌─────────────────────────────────────────────────┐
│  🚀 MISSION SETUP                               │
│                                                 │
│  [1. Define Scope] → [2. Set Goals] →           │
│  [3. Select Intensity] → [4. Review & Launch]   │
│                                                 │
├─────────────────────────────────────────────────┤
│                                                 │
│  Step 1: DEFINE SCOPE                           │
│                                                 │
│  Mission Name: [Internal Network Assessment  ]  │
│                                                 │
│  Add Targets:                                   │
│  [192.168.1.0/24            ] [+ Add]           │
│                                                 │
│  Scope (2 targets):                             │
│  ┌────────────────────┐                         │
│  │ 📦 192.168.1.0/24  │ [×]                     │
│  │ 📦 10.0.0.100      │ [×]                     │
│  └────────────────────┘                         │
│                                                 │
│  [← Back]                    [Continue →]       │
└─────────────────────────────────────────────────┘
```

**Intensity Options:**
| Mode | Description | Features |
|------|-------------|----------|
| 🔵 Stealth | Low and slow | Slow scans, no aggressive exploitation |
| 🟢 Balanced | Speed/stealth tradeoff | Standard scans, targeted exploitation |
| 🟠 Aggressive | Fast and comprehensive | Parallel scanning, all exploits |

---

## 📊 React Component Structure

```
src/components/
├── assets/
│   ├── AssetCard.tsx          # Target visualization
│   └── index.ts
├── operations/
│   ├── MissionTimeline.tsx    # Structured log replacement
│   └── index.ts
├── loot/
│   ├── CredentialVault.tsx    # Secure credential table
│   ├── SessionTerminal.tsx    # xterm.js wrapper
│   └── index.ts
├── control/
│   ├── EmergencyStop.tsx      # Kill switch with hold-to-abort
│   └── index.ts
├── wizard/
│   ├── MissionSetupWizard.tsx # Empty state wizard
│   └── index.ts
├── workspaces/
│   ├── ReconView.tsx          # Workspace A
│   ├── OperationsView.tsx     # Workspace B
│   ├── LootView.tsx           # Workspace C
│   └── index.ts
└── intelligence/
    ├── IntelligenceSidebar.tsx # Workspace D (AI Co-pilot)
    └── index.ts
```

---

## 📦 Zustand Store Updates

### MissionStore (New)

```typescript
interface MissionStoreState {
  // Core Mission State
  missionId: string | null
  missionName: string
  missionPhase: MissionPhase
  systemStatus: SystemStatus
  
  // Mission Configuration
  scope: string[]
  goals: string[]
  intensity: 'stealth' | 'balanced' | 'aggressive'
  
  // Timeline (Structured Log)
  timeline: TimelineEvent[]
  
  // Loot & Access
  credentials: Map<string, EnhancedCredential>
  artifacts: Map<string, Artifact>
  activeSessions: Map<string, Session>
  
  // HITL State
  currentApproval: ApprovalRequest | null
  approvalHistory: ApprovalDecision[]
  
  // Emergency Control
  emergencyStopActive: boolean
  emergencyStopReason: string | null
}

// Actions
interface MissionStoreActions {
  initMission(config: MissionConfig): void
  startMission(missionId: string): void
  advancePhase(newPhase: MissionPhase): void
  pauseMission(): void
  resumeMission(): void
  abortMission(reason: string): void
  
  addTimelineEvent(event: TimelineEvent): void
  addCredential(cred: EnhancedCredential): void
  addArtifact(artifact: Artifact): void
  addActiveSession(session: Session): void
  
  setCurrentApproval(approval: ApprovalRequest): void
  recordApprovalDecision(actionId: string, decision: 'approved' | 'rejected'): void
  
  activateEmergencyStop(reason: string): void
  resetEmergencyStop(): void
}
```

### Enhanced Types

```typescript
// Timeline Event
interface TimelineEvent {
  id: string
  timestamp: string
  type: TimelineEventType
  phase: MissionPhase
  title: string
  description: string
  metadata?: {
    target_id?: string
    vuln_id?: string
    session_id?: string
    cred_id?: string
    action_id?: string
    risk_level?: string
  }
  status: 'completed' | 'in_progress' | 'pending' | 'failed' | 'awaiting'
}

// Enhanced Credential
interface EnhancedCredential extends Credential {
  password?: string
  password_hash?: string
  validation_status: 'verified' | 'unverified' | 'invalid' | 'testing'
  last_tested?: string
  source_file?: string
  impact_assessment?: string
}

// Artifact
interface Artifact {
  id: string
  target_id: string
  file_path: string
  file_name: string
  file_type: 'credentials' | 'config' | 'database' | 'key' | 'document' | 'other'
  content_preview?: string
  size_bytes: number
  extracted_at: string
}
```

---

## 🎨 Design System

### Color Palette

| Purpose | Color | Hex | Usage |
|---------|-------|-----|-------|
| Primary | Royal Blue | `#3b82f6` | Actions, active states |
| Success | Green | `#4ade80` | Completed, verified |
| Warning | Amber | `#f59e0b` | HITL, attention needed |
| Danger | Red | `#ef4444` | Critical, emergency |
| Info | Cyan | `#22d3ee` | Findings, recon |

### Status Indicators

```
🟢 System Armed    - Green, no pulse
🔴 Active Attack   - Red, pulsing
🟠 Awaiting Input  - Amber, pulsing
🟡 Paused          - Yellow, no pulse
⛔ Emergency Stop  - Red, fast pulse
```

### Typography

- **Headings:** Inter, Semi-bold
- **Body:** Inter, Regular
- **Monospace:** JetBrains Mono (IPs, commands, code)
- **Labels:** Inter, 10px, UPPERCASE, tracking-wider

---

## 📱 Responsive Breakpoints

| Breakpoint | Width | Layout Changes |
|------------|-------|----------------|
| Mobile | <768px | Stacked workspaces, drawer navigation |
| Tablet | 768-1024px | 2-column grid, collapsible sidebar |
| Desktop | 1024-1440px | 3-column grid, full sidebar |
| Wide | >1440px | 4-column grid, AI sidebar always visible |

---

## 🔄 WebSocket Event → UI Mapping

| Event | Handler | UI Update |
|-------|---------|-----------|
| `new_target` | `addTarget()` | AssetCardGrid refreshes |
| `new_vuln` | `addVulnerability()` | VulnBadges update |
| `new_session` | `addActiveSession()` | SessionManager updates |
| `new_cred` | `addCredential()` | CredentialVault updates |
| `approval_request` | `setCurrentApproval()` | DecisionRoom shows modal |
| `goal_achieved` | `addTimelineEvent()` | Timeline + celebration |
| `status_change` | `updateMissionStatus()` | StatusIndicator updates |
| `statistics` | `updateMissionStats()` | All stat components |

---

## 📋 Implementation Checklist

### Phase 1: Core Components ✅
- [x] MissionStore (Zustand)
- [x] AssetCard + AssetCardGrid
- [x] MissionTimeline
- [x] CredentialVault
- [x] SessionTerminal
- [x] EmergencyStop

### Phase 2: Workspaces ✅
- [x] ReconView
- [x] OperationsView
- [x] LootView
- [x] IntelligenceSidebar

### Phase 3: UX Enhancements ✅
- [x] MissionSetupWizard
- [x] StatusIndicator
- [x] Updated Sidebar navigation
- [ ] ExploitabilityMatrix (optional)

### Phase 4: Integration
- [ ] Connect to WebSocket events
- [ ] Test HITL approval flow
- [ ] Validate emergency stop
- [ ] End-to-end testing

---

## 🚀 Next Steps

1. **Wire up WebSocket events** to MissionStore and EventStore
2. **Test the HITL workflow** with real backend
3. **Add routing** for workspace navigation
4. **Performance optimization** for large target lists
5. **Accessibility audit** (WCAG 2.1 AA)

---

*Document Version: 1.0.0*
*Last Updated: 2026-01-02*
*Author: RAGLOX Development Team*
