#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Offensive Security Prompts
# Optimized prompts for Red Team operations
# ═══════════════════════════════════════════════════════════════════════════════

"""
RAGLOX Offensive Security Prompts

This module contains optimized prompts for different phases of offensive operations:
1. Reconnaissance Prompts
2. Exploitation Decision Prompts  
3. Privilege Escalation Prompts
4. Lateral Movement Prompts
5. Defense Evasion Prompts
6. Failure Analysis Prompts (Reflexion)

Each prompt is designed to:
- Provide clear context for the LLM
- Request structured JSON responses
- Include MITRE ATT&CK references
- Guide decision-making with specific criteria
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Any, Optional


class PromptType(Enum):
    """Types of prompts"""
    RECON_PLANNING = "recon_planning"
    EXPLOIT_SELECTION = "exploit_selection"
    PRIVESC_PLANNING = "privesc_planning"
    LATERAL_PLANNING = "lateral_planning"
    EVASION_PLANNING = "evasion_planning"
    FAILURE_ANALYSIS = "failure_analysis"
    ATTACK_CHAIN_PLANNING = "attack_chain_planning"
    CREDENTIAL_STRATEGY = "credential_strategy"


@dataclass
class PromptTemplate:
    """Template for a prompt"""
    name: str
    type: PromptType
    template: str
    expected_response_format: str
    mitre_techniques: List[str]
    version: str = "1.0"


# ═══════════════════════════════════════════════════════════════════════════════
# System Prompts
# ═══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT_RED_TEAM = """You are an expert Red Team operator and penetration testing specialist.

Your role is to analyze security scenarios and provide tactical recommendations based on:
- MITRE ATT&CK framework tactics, techniques, and procedures (TTPs)
- Real-world offensive security experience
- Current threat actor methodologies (APT29, APT41, FIN7, etc.)
- Defense evasion and operational security best practices

Guidelines:
1. Always prioritize stealth and operational security
2. Recommend techniques based on target environment specifics
3. Consider detection risks and defensive measures
4. Suggest multiple approaches when possible
5. Reference MITRE ATT&CK technique IDs where applicable

You MUST respond with valid JSON matching the requested format."""


SYSTEM_PROMPT_ANALYSIS = """You are an expert security analyst specializing in failure analysis and adaptive attack strategies.

Your role is to:
1. Analyze failed attack attempts to understand root causes
2. Recommend appropriate next actions (retry, modify, skip, escalate)
3. Identify defense mechanisms and suggest evasion techniques
4. Learn from failures to improve future attempts

Decision Criteria:
- RETRY: Transient failures (network timeout, resource busy)
- MODIFY_APPROACH: Defense detected, need different technique
- SKIP: Target patched or fundamentally not vulnerable
- ESCALATE: Need human guidance for complex decisions
- PIVOT: Try completely different attack vector

Always provide structured reasoning with confidence levels."""


# ═══════════════════════════════════════════════════════════════════════════════
# Reconnaissance Prompts
# ═══════════════════════════════════════════════════════════════════════════════

RECON_PLANNING_PROMPT = PromptTemplate(
    name="Reconnaissance Planning",
    type=PromptType.RECON_PLANNING,
    mitre_techniques=["T1595", "T1592", "T1590", "T1591", "T1589"],
    template="""## Reconnaissance Planning Request

### Target Information:
- Target Network: {target_network}
- Known Hosts: {known_hosts}
- Mission Goals: {mission_goals}
- Current Phase: {current_phase}
- Time Constraints: {time_constraints}

### Available Reconnaissance Modules:
{available_modules}

### Previous Recon Results:
{previous_results}

### Request:
Plan the next reconnaissance steps. Consider:
1. What information gaps exist?
2. Which techniques minimize detection risk?
3. What high-value targets should be prioritized?
4. Are there any external intelligence sources to query?

Respond with JSON only:

```json
{{
    "recommended_actions": [
        {{
            "action_type": "network_scan|port_scan|service_enum|vuln_scan|osint",
            "target": "target identifier or range",
            "module": "module to use",
            "priority": 1-10,
            "detection_risk": "low|medium|high",
            "reasoning": "why this action"
        }}
    ],
    "information_gaps": ["list of unknown info"],
    "high_value_targets": ["list of priority targets"],
    "estimated_time_minutes": 30,
    "next_phase_ready": true|false,
    "mitre_techniques": ["T1595", "T1592"]
}}
```""",
    expected_response_format="JSON with recommended_actions array"
)


NUCLEI_TEMPLATE_SELECTION_PROMPT = PromptTemplate(
    name="Nuclei Template Selection",
    type=PromptType.RECON_PLANNING,
    mitre_techniques=["T1595.002", "T1190"],
    template="""## Nuclei Template Selection Request

### Target Web Service:
- URL: {target_url}
- Port: {port}
- Detected Technologies: {technologies}
- Server Headers: {server_headers}
- Detected CMS: {cms}

### Available Nuclei Templates by Category:
{available_templates}

### Previous Scan Results:
{previous_results}

### Request:
Select appropriate Nuclei templates for this target. Consider:
1. Technology stack detected
2. Severity priorities (critical/high first, then info for recon)
3. Templates that match the specific CMS or framework
4. Avoid noisy templates if stealth is required

Respond with JSON only:

```json
{{
    "selected_templates": [
        {{
            "template_id": "template-name",
            "severity": "critical|high|medium|low|info",
            "reason": "why selected",
            "detection_risk": "low|medium|high"
        }}
    ],
    "scan_order": ["template-id-1", "template-id-2"],
    "skip_templates": ["templates to avoid and why"],
    "estimated_findings": "low|medium|high",
    "stealth_mode": true|false
}}
```""",
    expected_response_format="JSON with selected_templates array"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Exploitation Prompts
# ═══════════════════════════════════════════════════════════════════════════════

EXPLOIT_SELECTION_PROMPT = PromptTemplate(
    name="Exploit Selection",
    type=PromptType.EXPLOIT_SELECTION,
    mitre_techniques=["T1190", "T1203", "T1210"],
    template="""## Exploit Selection Request

### Target Information:
- IP: {target_ip}
- Hostname: {hostname}
- OS: {target_os}
- Open Ports: {open_ports}
- Detected Services: {services}

### Discovered Vulnerabilities:
{vulnerabilities}

### Available Exploit Modules:
{available_modules}

### Mission Context:
- Goals: {mission_goals}
- Current Access Level: {current_access}
- Stealth Requirement: {stealth_level}
- Known Defenses: {known_defenses}

### Request:
Select the best exploit approach. Consider:
1. Exploit reliability and success rate
2. Post-exploitation access level gained
3. Detection risk and available defenses
4. Alternative approaches if primary fails

Respond with JSON only:

```json
{{
    "primary_exploit": {{
        "vuln_id": "vulnerability to exploit",
        "module": "rx-module-id",
        "technique_id": "TXXXX",
        "success_probability": 0.0-1.0,
        "expected_access": "user|admin|system|root",
        "detection_risk": "low|medium|high",
        "reasoning": "why this exploit"
    }},
    "fallback_exploits": [
        {{
            "vuln_id": "alternative vuln",
            "module": "rx-module-id",
            "reason": "use if primary fails because..."
        }}
    ],
    "required_conditions": ["list of prerequisites"],
    "evasion_recommendations": ["technique 1", "technique 2"],
    "post_exploit_actions": ["cred harvest", "privesc", "persistence"]
}}
```""",
    expected_response_format="JSON with primary_exploit and fallback_exploits"
)


CREDENTIAL_EXPLOIT_PROMPT = PromptTemplate(
    name="Credential-Based Exploitation",
    type=PromptType.EXPLOIT_SELECTION,
    mitre_techniques=["T1078", "T1110", "T1021"],
    template="""## Credential-Based Exploitation Request

### Target Information:
- IP: {target_ip}
- Hostname: {hostname}
- OS: {target_os}
- Available Services: {services}

### Available Credentials:
{credentials}

### Credential Sources:
- Intel (Leaked): {intel_creds_count} credentials
- Harvested: {harvested_creds_count} credentials
- Default/Guessed: {guessed_creds_count} credentials

### Request:
Plan credential-based attack. Prioritize:
1. Intel credentials (leaked data) - highest reliability
2. Harvested credentials from compromised systems
3. Default credentials - last resort
4. Brute force - avoid unless necessary

Respond with JSON only:

```json
{{
    "recommended_credential": {{
        "cred_id": "credential to use",
        "source": "intel|harvested|default|bruteforce",
        "reliability_score": 0.0-1.0,
        "target_service": "ssh|smb|rdp|winrm|wmi",
        "reasoning": "why this credential"
    }},
    "attack_sequence": [
        {{
            "step": 1,
            "action": "authenticate|verify|lateral",
            "service": "target service",
            "credential": "cred reference"
        }}
    ],
    "fallback_credentials": ["ordered list of alternatives"],
    "avoid_credentials": ["creds to skip and why"],
    "bruteforce_recommended": false,
    "spray_attack_viable": true|false
}}
```""",
    expected_response_format="JSON with recommended_credential and attack_sequence"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Privilege Escalation Prompts
# ═══════════════════════════════════════════════════════════════════════════════

PRIVESC_PLANNING_PROMPT = PromptTemplate(
    name="Privilege Escalation Planning",
    type=PromptType.PRIVESC_PLANNING,
    mitre_techniques=["T1068", "T1548", "T1134", "T1574"],
    template="""## Privilege Escalation Planning Request

### Current Access:
- Target: {target_ip} ({hostname})
- OS: {target_os}
- Current User: {current_user}
- Current Privilege: {current_privilege}
- Session Type: {session_type}

### System Information:
- Kernel Version: {kernel_version}
- Installed Software: {installed_software}
- Running Services: {running_services}
- Scheduled Tasks: {scheduled_tasks}
- SUID/SGID Binaries: {suid_binaries}

### Available PrivEsc Modules:
{available_modules}

### Known Defenses:
- AV/EDR: {av_edr}
- AppLocker/WDAC: {app_control}
- UAC Level: {uac_level}

### Request:
Plan privilege escalation. Consider:
1. Kernel exploits (risky but effective)
2. Service misconfigurations
3. Token manipulation
4. Scheduled task hijacking
5. DLL hijacking opportunities

Respond with JSON only:

```json
{{
    "recommended_technique": {{
        "name": "technique name",
        "technique_id": "T1068|T1548|T1134|T1574",
        "module": "rx-module-id",
        "target_privilege": "admin|system|root",
        "success_probability": 0.0-1.0,
        "detection_risk": "low|medium|high",
        "requires_interaction": false,
        "reasoning": "why this technique"
    }},
    "alternative_techniques": [
        {{
            "name": "alternative",
            "technique_id": "TXXXX",
            "reason": "use if primary fails"
        }}
    ],
    "prerequisites": ["list of requirements"],
    "evasion_needed": true|false,
    "evasion_techniques": ["amsi bypass", "etw patching"],
    "estimated_time_seconds": 60
}}
```""",
    expected_response_format="JSON with recommended_technique and alternatives"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Lateral Movement Prompts
# ═══════════════════════════════════════════════════════════════════════════════

LATERAL_MOVEMENT_PROMPT = PromptTemplate(
    name="Lateral Movement Planning",
    type=PromptType.LATERAL_PLANNING,
    mitre_techniques=["T1021", "T1047", "T1028", "T1076"],
    template="""## Lateral Movement Planning Request

### Current Position:
- Compromised Host: {current_host}
- Current Privilege: {current_privilege}
- Domain Membership: {domain_info}

### Available Credentials:
{available_credentials}

### Target Hosts:
{target_hosts}

### Network Topology:
- Subnets: {subnets}
- Trust Relationships: {trusts}
- Firewall Rules (if known): {firewall_rules}

### Available Lateral Movement Modules:
{available_modules}

### Request:
Plan lateral movement. Consider:
1. Pass-the-Hash vs Pass-the-Ticket
2. WMI/WinRM for remote execution
3. SMB admin shares
4. RDP for interactive access
5. Detection risks per technique

Respond with JSON only:

```json
{{
    "primary_path": {{
        "source_host": "current position",
        "target_host": "next target",
        "technique": "pth|ptt|wmi|winrm|smb|rdp|ssh",
        "technique_id": "T1021.xxx",
        "credential_to_use": "cred reference",
        "success_probability": 0.0-1.0,
        "detection_risk": "low|medium|high",
        "reasoning": "why this path"
    }},
    "alternative_paths": [
        {{
            "target_host": "alternative target",
            "technique": "technique",
            "reason": "backup path"
        }}
    ],
    "attack_chain": [
        {{
            "step": 1,
            "action": "lateral action",
            "target": "target host",
            "post_action": "what to do after"
        }}
    ],
    "high_value_targets": ["priority hosts for lateral"],
    "avoid_hosts": ["hosts to skip and why"]
}}
```""",
    expected_response_format="JSON with primary_path and attack_chain"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Defense Evasion Prompts
# ═══════════════════════════════════════════════════════════════════════════════

EVASION_PLANNING_PROMPT = PromptTemplate(
    name="Defense Evasion Planning",
    type=PromptType.EVASION_PLANNING,
    mitre_techniques=["T1027", "T1036", "T1055", "T1562", "T1070"],
    template="""## Defense Evasion Planning Request

### Current Situation:
- Target: {target_ip} ({hostname})
- OS: {target_os}
- Access Level: {access_level}
- Detected Operation: {detected_operation}

### Detected Defenses:
- AV Product: {av_product}
- EDR Product: {edr_product}
- AMSI Enabled: {amsi_enabled}
- ETW Logging: {etw_enabled}
- Sysmon Present: {sysmon_present}

### Detection Details:
- Error Type: {error_type}
- Error Message: {error_message}
- Blocked Component: {blocked_component}

### Original Attack:
- Module Used: {original_module}
- Technique: {original_technique}
- Payload Type: {payload_type}

### Available Evasion Modules:
{evasion_modules}

### Request:
Plan evasion strategy. Consider:
1. AMSI bypass techniques
2. ETW patching
3. Payload obfuscation
4. Living-off-the-land binaries (LOLBins)
5. Memory-only execution
6. Timestomping and log clearing

Respond with JSON only:

```json
{{
    "evasion_strategy": {{
        "primary_technique": "amsi_bypass|etw_patch|obfuscation|lolbin|memory_only",
        "technique_id": "T1027|T1562|T1070",
        "module": "rx-evasion-module",
        "description": "what this does",
        "success_probability": 0.0-1.0,
        "reasoning": "why this approach"
    }},
    "preparation_steps": [
        {{
            "step": 1,
            "action": "preparation action",
            "purpose": "why needed"
        }}
    ],
    "modified_attack": {{
        "original_module": "what was blocked",
        "new_module": "evasion-enabled version",
        "modifications": ["list of changes"],
        "lolbin_alternative": "native binary if applicable"
    }},
    "cleanup_required": true|false,
    "cleanup_actions": ["log clearing", "artifact removal"],
    "detection_reduction_estimate": "significant|moderate|minimal"
}}
```""",
    expected_response_format="JSON with evasion_strategy and modified_attack"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Failure Analysis Prompts (Reflexion)
# ═══════════════════════════════════════════════════════════════════════════════

FAILURE_ANALYSIS_PROMPT = PromptTemplate(
    name="Failure Analysis (Reflexion)",
    type=PromptType.FAILURE_ANALYSIS,
    mitre_techniques=["T1059"],
    template="""## Attack Failure Analysis Request

### Failed Task Details:
- Task ID: {task_id}
- Task Type: {task_type}
- Target: {target_ip} ({hostname})
- Target OS: {target_os}

### Execution Context:
- Module Used: {module_used}
- Technique ID: {technique_id}
- Command Executed: {command}
- Exit Code: {exit_code}
- Duration: {duration_ms}ms

### Error Information:
- Error Type: {error_type}
- Error Message: {error_message}
- STDERR: {stderr}
- STDOUT: {stdout}
- Detected Defenses: {detected_defenses}

### Retry History:
- Retry Count: {retry_count}
- Max Retries: {max_retries}
- Previous Attempts: {previous_attempts}

### Available Alternatives:
{alternative_modules}

### Mission Context:
- Goals: {mission_goals}
- Time Remaining: {time_remaining}
- Other Active Tasks: {active_tasks}

### Request:
Analyze this failure and recommend next action. Consider:
1. Is this a transient error that might succeed on retry?
2. Is the target defended and needs evasion?
3. Is the target patched and not vulnerable?
4. Should we try a different technique?
5. Should we escalate for human review?

Respond with JSON only:

```json
{{
    "analysis": {{
        "category": "network|defense|authentication|vulnerability|technical|unknown",
        "root_cause": "specific cause identified",
        "confidence": "high|medium|low",
        "detected_defenses": ["list of defenses detected"],
        "target_state": "vulnerable|patched|unknown"
    }},
    "recommended_action": {{
        "decision": "retry|modify_approach|skip|escalate|pivot",
        "reasoning": "detailed explanation",
        "delay_seconds": 0,
        "alternative_module": {{
            "rx_module_id": "new module if modify_approach",
            "reason": "why this module",
            "evasion_techniques": ["techniques to apply"]
        }},
        "modified_parameters": {{
            "use_evasion": true|false,
            "encode_payload": true|false,
            "use_lolbin": true|false
        }},
        "escalation_reason": "reason if escalate",
        "human_guidance_needed": "what input needed"
    }},
    "lessons_learned": ["insight 1", "insight 2"],
    "additional_recommendations": ["rec 1", "rec 2"],
    "should_update_knowledge": true|false,
    "knowledge_update": "what to remember for future"
}}
```""",
    expected_response_format="JSON with analysis and recommended_action"
)


REFLEXION_LEARNING_PROMPT = PromptTemplate(
    name="Reflexion Learning",
    type=PromptType.FAILURE_ANALYSIS,
    mitre_techniques=["T1059"],
    template="""## Reflexion Learning Request

### Session Summary:
- Mission ID: {mission_id}
- Duration: {duration_minutes} minutes
- Targets Engaged: {targets_count}

### Attack Statistics:
- Total Attempts: {total_attempts}
- Successful: {successful}
- Failed: {failed}
- Success Rate: {success_rate}%

### Failure Categories:
{failure_breakdown}

### Most Common Failures:
{common_failures}

### Successful Techniques:
{successful_techniques}

### Request:
Analyze the session and extract learnings. Consider:
1. What patterns led to failures?
2. What techniques were most effective?
3. What defenses were encountered?
4. How can future missions be improved?

Respond with JSON only:

```json
{{
    "session_analysis": {{
        "overall_effectiveness": "high|medium|low",
        "primary_blockers": ["main obstacles"],
        "effective_techniques": ["what worked"],
        "ineffective_techniques": ["what didn't work"]
    }},
    "defensive_insights": {{
        "common_defenses": ["defense 1", "defense 2"],
        "evasion_success_rate": 0.0-1.0,
        "defense_bypass_recommendations": ["recommendation 1"]
    }},
    "operational_learnings": [
        {{
            "learning": "specific insight",
            "applies_to": "scenario type",
            "confidence": "high|medium|low"
        }}
    ],
    "knowledge_base_updates": [
        {{
            "type": "module_reliability|defense_pattern|technique_effectiveness",
            "key": "identifier",
            "value": "updated value",
            "reason": "why update"
        }}
    ],
    "recommendations_for_next_mission": ["rec 1", "rec 2"],
    "priority_improvements": ["improvement 1", "improvement 2"]
}}
```""",
    expected_response_format="JSON with session_analysis and operational_learnings"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Chain Planning Prompts
# ═══════════════════════════════════════════════════════════════════════════════

ATTACK_CHAIN_PROMPT = PromptTemplate(
    name="Attack Chain Planning",
    type=PromptType.ATTACK_CHAIN_PLANNING,
    mitre_techniques=["T1059", "T1078", "T1003", "T1021"],
    template="""## Attack Chain Planning Request

### Mission Objectives:
{mission_objectives}

### Current State:
- Compromised Hosts: {compromised_hosts}
- Available Credentials: {available_credentials}
- Discovered Vulnerabilities: {discovered_vulns}
- Current Privilege Level: {current_privilege}

### Target Environment:
- Domain: {domain_info}
- High-Value Targets: {high_value_targets}
- Network Topology: {network_topology}

### Constraints:
- Time Limit: {time_limit}
- Stealth Requirement: {stealth_requirement}
- Rules of Engagement: {roe}

### Request:
Plan the complete attack chain to achieve mission objectives. Consider:
1. Optimal path to each objective
2. Resource requirements (creds, sessions)
3. Risk at each stage
4. Rollback plans if detected

Respond with JSON only:

```json
{{
    "attack_chain": [
        {{
            "phase": "initial_access|execution|persistence|privesc|defense_evasion|credential_access|discovery|lateral_movement|collection|exfiltration",
            "step": 1,
            "action": "specific action",
            "target": "target host/system",
            "technique_id": "TXXXX",
            "module": "rx-module",
            "prerequisites": ["what must be true"],
            "expected_outcome": "what we gain",
            "risk_level": "low|medium|high",
            "detection_indicators": ["what might trigger alert"]
        }}
    ],
    "critical_path": ["step_ids for must-succeed path"],
    "parallel_opportunities": ["steps that can run concurrently"],
    "rollback_plan": {{
        "trigger_conditions": ["when to rollback"],
        "actions": ["cleanup actions"]
    }},
    "estimated_duration_minutes": 60,
    "success_probability": 0.0-1.0,
    "key_decision_points": [
        {{
            "at_step": 3,
            "decision": "what decision",
            "options": ["option 1", "option 2"]
        }}
    ]
}}
```""",
    expected_response_format="JSON with attack_chain array"
)


# ═══════════════════════════════════════════════════════════════════════════════
# Prompt Manager
# ═══════════════════════════════════════════════════════════════════════════════

class PromptManager:
    """Manager for offensive security prompts"""
    
    def __init__(self):
        self.prompts: Dict[str, PromptTemplate] = {}
        self._load_default_prompts()
    
    def _load_default_prompts(self):
        """Load all default prompts"""
        default_prompts = [
            RECON_PLANNING_PROMPT,
            NUCLEI_TEMPLATE_SELECTION_PROMPT,
            EXPLOIT_SELECTION_PROMPT,
            CREDENTIAL_EXPLOIT_PROMPT,
            PRIVESC_PLANNING_PROMPT,
            LATERAL_MOVEMENT_PROMPT,
            EVASION_PLANNING_PROMPT,
            FAILURE_ANALYSIS_PROMPT,
            REFLEXION_LEARNING_PROMPT,
            ATTACK_CHAIN_PROMPT,
        ]
        
        for prompt in default_prompts:
            self.prompts[prompt.name] = prompt
    
    def get_prompt(self, name: str) -> Optional[PromptTemplate]:
        """Get a prompt template by name"""
        return self.prompts.get(name)
    
    def get_prompts_by_type(self, prompt_type: PromptType) -> List[PromptTemplate]:
        """Get all prompts of a specific type"""
        return [p for p in self.prompts.values() if p.type == prompt_type]
    
    def render_prompt(
        self, 
        name: str, 
        variables: Dict[str, Any],
        include_system_prompt: bool = True
    ) -> Tuple[str, str]:
        """
        Render a prompt with variables
        
        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        template = self.prompts.get(name)
        if not template:
            raise ValueError(f"Unknown prompt: {name}")
        
        # Determine system prompt based on type
        if template.type == PromptType.FAILURE_ANALYSIS:
            system_prompt = SYSTEM_PROMPT_ANALYSIS
        else:
            system_prompt = SYSTEM_PROMPT_RED_TEAM
        
        # Fill in template variables
        user_prompt = template.template
        for key, value in variables.items():
            placeholder = "{" + key + "}"
            if isinstance(value, list):
                value = "\n".join(f"- {v}" for v in value)
            elif isinstance(value, dict):
                value = "\n".join(f"- {k}: {v}" for k, v in value.items())
            user_prompt = user_prompt.replace(placeholder, str(value))
        
        return (system_prompt if include_system_prompt else "", user_prompt)
    
    def get_expected_format(self, name: str) -> str:
        """Get expected response format for a prompt"""
        template = self.prompts.get(name)
        return template.expected_response_format if template else "JSON"
    
    def list_prompts(self) -> List[Dict[str, str]]:
        """List all available prompts"""
        return [
            {
                "name": p.name,
                "type": p.type.value,
                "mitre": ", ".join(p.mitre_techniques[:3]),
                "version": p.version
            }
            for p in self.prompts.values()
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# Prompt Quality Testing
# ═══════════════════════════════════════════════════════════════════════════════

class PromptQualityTester:
    """Test prompt quality and effectiveness"""
    
    def __init__(self, prompt_manager: PromptManager):
        self.manager = prompt_manager
        self.test_results: List[Dict] = []
    
    def test_prompt_structure(self, name: str) -> Dict[str, Any]:
        """Test if prompt has proper structure"""
        template = self.manager.get_prompt(name)
        if not template:
            return {"valid": False, "error": "Prompt not found"}
        
        checks = {
            "has_request_section": "### Request:" in template.template,
            "has_json_example": "```json" in template.template,
            "has_context_section": "### " in template.template,
            "has_mitre_refs": len(template.mitre_techniques) > 0,
            "variables_present": "{" in template.template and "}" in template.template,
        }
        
        return {
            "valid": all(checks.values()),
            "checks": checks,
            "mitre_techniques": template.mitre_techniques,
            "type": template.type.value
        }
    
    def test_all_prompts(self) -> Dict[str, Any]:
        """Test all prompts for structural validity"""
        results = {}
        for name in self.manager.prompts.keys():
            results[name] = self.test_prompt_structure(name)
        
        valid_count = sum(1 for r in results.values() if r.get("valid"))
        return {
            "total": len(results),
            "valid": valid_count,
            "invalid": len(results) - valid_count,
            "details": results
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Module Export
# ═══════════════════════════════════════════════════════════════════════════════

# Singleton instance
_prompt_manager: Optional[PromptManager] = None


def get_prompt_manager() -> PromptManager:
    """Get the global prompt manager instance"""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    return _prompt_manager


def render_offensive_prompt(
    prompt_name: str,
    variables: Dict[str, Any],
    include_system: bool = True
) -> Tuple[str, str]:
    """Convenience function to render a prompt"""
    return get_prompt_manager().render_prompt(prompt_name, variables, include_system)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI for Testing
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    
    manager = get_prompt_manager()
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        tester = PromptQualityTester(manager)
        results = tester.test_all_prompts()
        
        print(f"\nPrompt Quality Test Results")
        print(f"{'=' * 50}")
        print(f"Total Prompts: {results['total']}")
        print(f"Valid: {results['valid']}")
        print(f"Invalid: {results['invalid']}")
        print()
        
        for name, result in results['details'].items():
            status = "✅" if result.get('valid') else "❌"
            print(f"{status} {name}")
            if not result.get('valid'):
                failed_checks = [k for k, v in result.get('checks', {}).items() if not v]
                print(f"   Failed: {', '.join(failed_checks)}")
    
    elif len(sys.argv) > 1 and sys.argv[1] == "list":
        print("\nAvailable Offensive Prompts")
        print(f"{'=' * 50}")
        for prompt_info in manager.list_prompts():
            print(f"- {prompt_info['name']}")
            print(f"  Type: {prompt_info['type']}")
            print(f"  MITRE: {prompt_info['mitre']}")
            print()
    
    else:
        print("Usage:")
        print("  python offensive_prompts.py list   - List all prompts")
        print("  python offensive_prompts.py test   - Test prompt quality")
