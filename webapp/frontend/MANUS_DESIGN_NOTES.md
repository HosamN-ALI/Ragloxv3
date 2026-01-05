# Manus Design Analysis - Detailed Notes

## Color Palette (Extracted from Screenshots)

### Backgrounds
- **Main Background**: #1a1a1a (very dark gray, almost black)
- **Sidebar Background**: #141414 (darker than main)
- **Chat Panel Background**: #1e1e1e (slightly lighter)
- **Terminal Panel Background**: #1a1a1a with subtle border
- **Card Background**: #2a2a2a (code blocks, results)
- **Input Box Background**: #2a2a2a

### Text Colors
- **Primary Text**: #e5e5e5 (off-white)
- **Secondary Text**: #a3a3a3 (gray)
- **Muted Text**: #737373 (darker gray)
- **Terminal Prompt**: #22c55e (green for ubuntu@sandbox)
- **Terminal Command**: #ffffff (white)

### Accent Colors
- **Blue Badge (Max)**: #3b82f6 background, white text
- **Green Checkmark**: #22c55e
- **Progress Bar**: #3b82f6 (blue gradient)
- **Live Indicator**: #22c55e (green dot)

## Layout Structure

### Three-Column Layout (when terminal open)
1. **Left Sidebar** (~280px): Projects, tasks list
2. **Center Chat** (flexible): Messages, events
3. **Right Terminal** (~500px): Floating panel

### Two-Column Layout (terminal closed)
1. **Left Sidebar** (~280px)
2. **Center Chat** (full remaining width)

## Component Styles

### Sidebar
- Dark background (#141414)
- "manus" logo with brain icon at top
- Navigation items: New task, Search, Library
- "Projects" section with + button
- Project items with folder icon
- "All tasks" section with filter icon
- Task items with icons (document, brain, etc.)
- "Share Manus with a friend" CTA at bottom
- Bottom icons: settings, help, notifications

### Chat Panel Header
- "Manus 1.6 Max" with dropdown arrow
- Right side: Collaborate, Share, Copy, More icons

### Message Structure
- **Agent Header**: Brain icon + "manus" + Blue "Max" badge + timestamp
- **Message Content**: Regular text, bullet points
- **Knowledge Recalled Badge**: 
  - Brain icon (🧠)
  - "Knowledge recalled(3)" text
  - Dropdown arrow (expandable)
  - Subtle background pill shape
- **Executing Command Badge**:
  - Terminal icon
  - "Executing command" text
  - Command in monospace: `df -h`
  - Gray background pill

### Result Card (Plain Text)
- "Plain Text" header with copy icon
- Monospace content
- Dark background (#2a2a2a)
- Subtle border radius

### Terminal Panel ("Manus's Computer")
- **Header**: 
  - Terminal icon
  - "Manus's Computer" title
  - "Manus is using Terminal" + "Executing command df -h"
  - Window controls (minimize, maximize, close)
- **Branch indicator**: "main" in top right
- **Terminal content**:
  - Green prompt: ubuntu@sandbox:~ $
  - White command text
  - Output in standard terminal colors
- **Progress bar at bottom**:
  - Play/pause controls
  - Slider with blue progress
  - "live" indicator with green dot
- **Current task indicator**:
  - Checkmark icon
  - "Deliver final summary to user"
  - "7/7" progress

### Input Box
- Rounded corners (full pill shape)
- Placeholder: "Send message to Manus"
- Left icons: +, emoji, GitHub
- Right icons: microphone, send button
- Send button: circular, blue when active

## Typography

### Font Family
- Sans-serif (likely Inter or similar)
- Monospace for code/terminal

### Font Sizes
- Header: 16px
- Body: 14px
- Small/Caption: 12px
- Code: 13px monospace

### Font Weights
- Regular: 400
- Medium: 500
- Semibold: 600

## Spacing

### Padding
- Card padding: 16px
- Section padding: 12px
- Badge padding: 6px 12px

### Margins
- Between messages: 16px
- Between sections: 24px

## Animations

### Transitions
- Smooth expand/collapse for Knowledge recalled
- Fade in for new messages
- Slide for terminal panel

## RAGLOX Adaptations

### Terminology Mapping
- "manus" → "RAGLOX Agent"
- "Max" badge → "v3.0" or mission status
- "Manus's Computer" → "Target Terminal" or "Session: root@172.28.0.100"
- "Knowledge recalled" → "Knowledge recalled" (keep same)
- "Executing command" → "Executing command" (keep same)

### Additional Components for RAGLOX
- **Vulnerability Cards**: Red accent
- **Credential Cards**: Green accent
- **Session Cards**: Blue accent
- **Approval Cards**: Orange/Red warning style
- **Plan Bar**: Mission progress (4/7 tasks)

### Security-Specific Styling
- Risk score indicators
- Port status badges
- CVE references
- MITRE ATT&CK technique tags
