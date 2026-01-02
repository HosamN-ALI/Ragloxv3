# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - LLM Prompts
# System prompts and prompt templates for Reflexion Pattern
# ═══════════════════════════════════════════════════════════════

from typing import Any, Dict, List, Optional
import json

from .models import (
    AnalysisRequest,
    AvailableModule,
    TaskContext,
    ExecutionContext,
    ErrorDetails,
)


# ═══════════════════════════════════════════════════════════════
# System Prompts
# ═══════════════════════════════════════════════════════════════

REFLEXION_SYSTEM_PROMPT = """You are an expert Red Team analyst and security researcher working within the RAGLOX automated penetration testing system. Your role is to analyze failed attack attempts and provide intelligent recommendations.

## Your Responsibilities:
1. Analyze why an attack/reconnaissance attempt failed
2. Identify the root cause (network issues, defenses, misconfigurations, etc.)
3. Recommend the best course of action (retry, modify approach, skip, pivot, escalate)
4. Select appropriate alternative techniques/modules when needed
5. Learn from failures to improve future attempts

## Key Principles:
- Be precise and actionable in recommendations
- Prioritize stealth and evasion when defenses are detected
- Consider the target's security posture holistically
- Avoid repeated failures with the same approach
- Escalate to human operators when truly stuck

## Defense Detection Guidelines:
- "antivirus": Traditional signature-based AV
- "edr": Endpoint Detection and Response (CrowdStrike, Carbon Black, etc.)
- "firewall": Network/host firewall blocking
- "ids_ips": Intrusion Detection/Prevention Systems
- "sandbox": Sandbox/detonation environment detected
- "waf": Web Application Firewall
- "amsi": Windows AMSI (Antimalware Scan Interface)
- "applocker": Windows AppLocker restrictions
- "credential_guard": Windows Credential Guard

## Output Format:
You MUST respond with valid JSON only. No explanations or text outside the JSON structure.
The JSON must strictly follow the schema provided in the user message."""


FAILURE_ANALYSIS_PROMPT = """Analyze the following failed task and provide recommendations.

## Task Context:
{task_context}

## Execution Details:
{execution_context}

## Error Information:
{error_details}

## Retry History:
- Previous attempts: {retry_count}/{max_retries}
{previous_analysis}

## Available Alternative Modules:
{available_modules}

## Mission Goals:
{mission_goals}

## Required JSON Response Schema:
```json
{{
    "analysis": {{
        "category": "network|defense|authentication|vulnerability|technical|unknown",
        "root_cause": "Brief description of the root cause",
        "contributing_factors": ["factor1", "factor2"],
        "detected_defenses": ["antivirus", "edr", "firewall", etc.],
        "confidence": "high|medium|low"
    }},
    "recommended_action": {{
        "decision": "retry|modify_approach|skip|escalate|pivot",
        "reasoning": "Detailed reasoning for this decision",
        "delay_seconds": 0,
        "alternative_module": {{
            "rx_module_id": "module-id if modify_approach",
            "reason": "why this module",
            "expected_success_rate": 0.0-1.0,
            "required_parameters": {{}},
            "evasion_techniques": []
        }},
        "modified_parameters": {{}},
        "new_attack_vector": "if pivot",
        "new_technique_id": "if pivot",
        "escalation_reason": "if escalate",
        "human_guidance_needed": []
    }},
    "additional_recommendations": [],
    "lessons_learned": [],
    "should_update_knowledge": false,
    "knowledge_update": null
}}
```

Respond ONLY with valid JSON matching this schema."""


MODULE_SELECTION_PROMPT = """Select the best module for the given task from the available options.

## Task:
- Type: {task_type}
- Target: {target_ip} ({target_os})
- Technique: {technique_id}
- Goal: {goal}

## Detected Defenses:
{detected_defenses}

## Available Modules:
{modules_list}

## Selection Criteria:
1. Likelihood of success against detected defenses
2. Stealth and evasion capabilities
3. Reliability and stability
4. Historical success rate

## Required JSON Response Schema:
```json
{{
    "selected_module": "rx-module-id",
    "rankings": [
        {{
            "rx_module_id": "module-id",
            "rank": 1,
            "score": 0-100,
            "reasoning": "why this ranking",
            "pros": ["advantage1", "advantage2"],
            "cons": ["disadvantage1"]
        }}
    ],
    "selection_reasoning": "Overall reasoning for selection",
    "confidence": "high|medium|low",
    "recommended_parameters": {{}},
    "warnings": []
}}
```

Respond ONLY with valid JSON matching this schema."""


# ═══════════════════════════════════════════════════════════════
# Prompt Builders
# ═══════════════════════════════════════════════════════════════

def build_analysis_prompt(request: AnalysisRequest) -> str:
    """
    Build the failure analysis prompt from request data.
    
    Args:
        request: Analysis request with all context
        
    Returns:
        Formatted prompt string
    """
    # Format task context
    task_context = f"""- Task ID: {request.task.task_id}
- Task Type: {request.task.task_type}
- Target IP: {request.task.target_ip or 'Unknown'}
- Target Hostname: {request.task.target_hostname or 'Unknown'}
- Target OS: {request.task.target_os or 'Unknown'}
- Platform: {request.task.target_platform or 'Unknown'}"""

    # Format execution context
    execution_context = f"""- Module Used: {request.execution.module_used or 'None'}
- Technique ID: {request.execution.technique_id or 'Unknown'}
- Command: {_truncate(request.execution.command_executed, 200) if request.execution.command_executed else 'N/A'}
- Exit Code: {request.execution.exit_code if request.execution.exit_code is not None else 'N/A'}
- Duration: {request.execution.duration_ms}ms"""

    # Format error details
    error_details = f"""- Error Type: {request.error.error_type}
- Error Message: {request.error.error_message}
- Detected Defenses: {', '.join(request.error.detected_defenses) if request.error.detected_defenses else 'None detected'}
- Stderr: {_truncate(request.error.stderr, 300) if request.error.stderr else 'N/A'}
- Stdout: {_truncate(request.error.stdout, 300) if request.error.stdout else 'N/A'}"""

    # Format previous analysis
    previous_analysis = ""
    if request.previous_analysis:
        previous_analysis = f"- Previous Analysis: {request.previous_analysis}"

    # Format available modules
    if request.available_modules:
        modules_list = []
        for mod in request.available_modules[:10]:  # Limit to 10 modules
            mod_str = f"  - {mod.rx_module_id}: {mod.name}"
            if mod.description:
                mod_str += f" - {_truncate(mod.description, 100)}"
            if mod.supports_evasion:
                mod_str += " [EVASION SUPPORT]"
            modules_list.append(mod_str)
        available_modules = "\n".join(modules_list)
    else:
        available_modules = "No alternative modules available"

    # Format mission goals
    if request.mission_goals:
        mission_goals = "\n".join(f"- {goal}" for goal in request.mission_goals)
    else:
        mission_goals = "No specific goals defined"

    return FAILURE_ANALYSIS_PROMPT.format(
        task_context=task_context,
        execution_context=execution_context,
        error_details=error_details,
        retry_count=request.retry_count,
        max_retries=request.max_retries,
        previous_analysis=previous_analysis,
        available_modules=available_modules,
        mission_goals=mission_goals
    )


def build_module_selection_prompt(
    task_type: str,
    target_ip: Optional[str],
    target_os: Optional[str],
    technique_id: Optional[str],
    goal: str,
    detected_defenses: List[str],
    modules: List[AvailableModule]
) -> str:
    """
    Build the module selection prompt.
    
    Args:
        task_type: Type of task
        target_ip: Target IP address
        target_os: Target operating system
        technique_id: MITRE technique ID
        goal: Goal of the task
        detected_defenses: List of detected defenses
        modules: List of available modules
        
    Returns:
        Formatted prompt string
    """
    # Format defenses
    if detected_defenses:
        defenses_str = "\n".join(f"- {d}" for d in detected_defenses)
    else:
        defenses_str = "None detected"

    # Format modules
    modules_list = []
    for mod in modules:
        mod_info = {
            "id": mod.rx_module_id,
            "name": mod.name,
            "description": mod.description,
            "technique": mod.technique_id,
            "evasion": mod.supports_evasion,
            "success_rate": mod.success_rate
        }
        modules_list.append(json.dumps(mod_info, indent=2))
    
    modules_str = "\n".join(modules_list)

    return MODULE_SELECTION_PROMPT.format(
        task_type=task_type,
        target_ip=target_ip or "Unknown",
        target_os=target_os or "Unknown",
        technique_id=technique_id or "Unknown",
        goal=goal,
        detected_defenses=defenses_str,
        modules_list=modules_str
    )


# ═══════════════════════════════════════════════════════════════
# Specialized Prompts
# ═══════════════════════════════════════════════════════════════

EVASION_ANALYSIS_PROMPT = """Analyze the detected defenses and recommend evasion strategies.

## Detected Defenses:
{defenses}

## Current Module:
{current_module}

## Target Environment:
{target_info}

## Required Response:
Provide a JSON response with:
1. evasion_techniques: List of techniques to try
2. module_modifications: Parameters to modify
3. alternative_approach: Different attack vector if needed
4. risk_assessment: Risk level of each technique

Respond with valid JSON only."""


CREDENTIAL_SELECTION_PROMPT = """Select the best credential to use for authentication.

## Available Credentials:
{credentials}

## Target System:
{target_info}

## Previous Attempts:
{previous_attempts}

## Required Response:
Provide a JSON response with:
1. selected_credential_id: ID of chosen credential
2. reasoning: Why this credential
3. authentication_method: How to use it (pass-the-hash, password, etc.)
4. fallback_credentials: Ordered list of fallbacks

Respond with valid JSON only."""


PIVOT_RECOMMENDATION_PROMPT = """Recommend a new attack vector after multiple failures.

## Failed Approaches:
{failed_approaches}

## Target Information:
{target_info}

## Available Resources:
- Credentials: {credentials_count}
- Sessions: {sessions_count}
- Discovered Vulns: {vulns_count}

## Required Response:
Provide a JSON response with:
1. recommended_pivot: New attack vector
2. technique_id: MITRE technique for new approach
3. required_resources: What's needed
4. success_likelihood: Estimated chance (0-1)
5. reasoning: Why this pivot makes sense

Respond with valid JSON only."""


# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

def _truncate(text: Optional[str], max_length: int) -> str:
    """Truncate text to maximum length."""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def format_json_for_prompt(data: Dict[str, Any]) -> str:
    """Format a dictionary as pretty JSON for prompts."""
    return json.dumps(data, indent=2, default=str)


def extract_json_from_response(response: str) -> Dict[str, Any]:
    """
    Extract JSON from LLM response, handling markdown code blocks.
    
    Args:
        response: Raw LLM response
        
    Returns:
        Parsed JSON dictionary
        
    Raises:
        ValueError: If no valid JSON found
    """
    import re
    
    # Try direct JSON parse first
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass
    
    # Try to extract from markdown code blocks
    patterns = [
        r'```json\s*([\s\S]*?)\s*```',  # ```json ... ```
        r'```\s*([\s\S]*?)\s*```',       # ``` ... ```
        r'\{[\s\S]*\}',                   # Raw JSON object
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, response)
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue
    
    raise ValueError(f"Could not extract valid JSON from response: {response[:200]}...")


def build_error_context_summary(error_type: str, error_message: str, stderr: Optional[str]) -> str:
    """Build a concise error summary for prompts."""
    summary = f"Error Type: {error_type}\n"
    summary += f"Message: {error_message}\n"
    
    if stderr:
        # Extract key error indicators
        key_phrases = [
            "permission denied",
            "access denied",
            "connection refused",
            "timeout",
            "not found",
            "authentication failed",
            "blocked",
            "detected",
        ]
        
        stderr_lower = stderr.lower()
        detected = [p for p in key_phrases if p in stderr_lower]
        
        if detected:
            summary += f"Key indicators: {', '.join(detected)}\n"
    
    return summary
