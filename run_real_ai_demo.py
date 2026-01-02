#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Real AI Demo
# Live demonstration with REAL LLM API (BlackboxAI/OpenAI)
# Uses local vulnerable-target in Docker for safe testing
# ═══════════════════════════════════════════════════════════════════════════════
#
# This demo shows the Reflexion Pattern in action:
# 1. 🔴 First exploit attempt fails (simulated defense detection)
# 2. 🧠 AI analyzes the failure and suggests a new approach
# 3. 🟢 Second attempt succeeds using AI's recommendation
#
# SAFETY: All attacks target LOCAL Docker containers only!
#
# ═══════════════════════════════════════════════════════════════════════════════

import asyncio
import os
import sys
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pathlib import Path
from uuid import uuid4

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()


# ═══════════════════════════════════════════════════════════════════════════════
# Console Colors and Formatting
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"


def print_banner():
    """Print the demo banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗  █████╗  ██████╗ ██╗      ██████╗ ██╗  ██╗    ██╗   ██╗██████╗     ║
║   ██╔══██╗██╔══██╗██╔════╝ ██║     ██╔═══██╗╚██╗██╔╝    ██║   ██║╚════██╗    ║
║   ██████╔╝███████║██║  ███╗██║     ██║   ██║ ╚███╔╝     ██║   ██║ █████╔╝    ║
║   ██╔══██╗██╔══██║██║   ██║██║     ██║   ██║ ██╔██╗     ╚██╗ ██╔╝ ╚═══██╗    ║
║   ██║  ██║██║  ██║╚██████╔╝███████╗╚██████╔╝██╔╝ ██╗     ╚████╔╝ ██████╔╝    ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚═══╝  ╚═════╝     ║
║                                                                               ║
║         🧠 REAL AI DEMO - Reflexion Pattern with Live LLM API 🧠              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)


def print_section(title: str, color: str = Colors.CYAN):
    """Print a section header."""
    print(f"\n{color}{Colors.BOLD}{'═' * 70}")
    print(f"  {title}")
    print(f"{'═' * 70}{Colors.RESET}\n")


def print_status(icon: str, message: str, color: str = Colors.WHITE):
    """Print a status message with icon."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.DIM}[{timestamp}]{Colors.RESET} {icon} {color}{message}{Colors.RESET}")


def print_error(message: str):
    """Print an error message."""
    print_status("🔴", message, Colors.RED)


def print_success(message: str):
    """Print a success message."""
    print_status("🟢", message, Colors.GREEN)


def print_warning(message: str):
    """Print a warning message."""
    print_status("⚠️", message, Colors.YELLOW)


def print_info(message: str):
    """Print an info message."""
    print_status("ℹ️", message, Colors.BLUE)


def print_ai(message: str):
    """Print an AI-related message."""
    print_status("🧠", message, Colors.MAGENTA)


def print_json(data: Dict[str, Any], title: str = ""):
    """Print formatted JSON data."""
    if title:
        print(f"{Colors.CYAN}{title}:{Colors.RESET}")
    print(f"{Colors.DIM}{json.dumps(data, indent=2, default=str)}{Colors.RESET}")


# ═══════════════════════════════════════════════════════════════════════════════
# Environment Validation
# ═══════════════════════════════════════════════════════════════════════════════

def validate_environment() -> Dict[str, Any]:
    """
    Validate environment configuration.
    
    Returns:
        Configuration dict
    
    Raises:
        SystemExit if configuration is invalid
    """
    print_section("Environment Validation")
    
    config = {
        "llm_enabled": os.getenv("LLM_ENABLED", "true").lower() == "true",
        "llm_provider": os.getenv("LLM_PROVIDER", "blackbox"),
        "llm_api_key": os.getenv("LLM_API_KEY", ""),
        "llm_api_base": os.getenv("LLM_API_BASE", ""),
        "llm_model": os.getenv("LLM_MODEL", "gpt-4"),
        "llm_max_cost_limit": float(os.getenv("LLM_MAX_COST_LIMIT", "2.0")),
        "llm_mission_requests_limit": int(os.getenv("LLM_MISSION_REQUESTS_LIMIT", "20")),
    }
    
    # Check for API key
    if not config["llm_api_key"]:
        print_error("LLM_API_KEY is not set!")
        print()
        print(f"{Colors.YELLOW}Please set your API key:{Colors.RESET}")
        print()
        print(f"  Option 1: Set environment variable:")
        print(f"    {Colors.CYAN}export LLM_API_KEY='your-api-key-here'{Colors.RESET}")
        print()
        print(f"  Option 2: Create .env file with:")
        print(f"    {Colors.CYAN}LLM_API_KEY=your-api-key-here{Colors.RESET}")
        print()
        print(f"  Option 3: Enter key now (will not be saved):")
        
        try:
            api_key = input(f"{Colors.CYAN}  API Key: {Colors.RESET}").strip()
            if api_key:
                config["llm_api_key"] = api_key
                os.environ["LLM_API_KEY"] = api_key
            else:
                print_error("No API key provided. Exiting.")
                sys.exit(1)
        except KeyboardInterrupt:
            print("\n")
            print_warning("Cancelled by user.")
            sys.exit(0)
    
    # Display configuration
    print_success(f"LLM Provider: {config['llm_provider']}")
    print_success(f"LLM Model: {config['llm_model']}")
    print_success(f"API Key: {config['llm_api_key'][:8]}...{config['llm_api_key'][-4:]}")
    print_success(f"Max Cost Limit: ${config['llm_max_cost_limit']:.2f}")
    print_success(f"Max Requests/Mission: {config['llm_mission_requests_limit']}")
    
    if config["llm_api_base"]:
        print_success(f"API Base URL: {config['llm_api_base']}")
    
    return config


# ═══════════════════════════════════════════════════════════════════════════════
# Mock Attack Simulation
# ═══════════════════════════════════════════════════════════════════════════════

class AttackSimulator:
    """Simulates attack scenarios for the demo."""
    
    def __init__(self):
        self.attempt_count = 0
        
    async def simulate_failed_exploit(self) -> Dict[str, Any]:
        """Simulate a failed exploit attempt."""
        self.attempt_count += 1
        
        await asyncio.sleep(1)  # Simulate network delay
        
        return {
            "success": False,
            "task_id": str(uuid4()),
            "task_type": "EXPLOIT",
            "target": {
                "ip": "172.28.0.100",
                "hostname": "vulnerable-target",
                "os": "Ubuntu 22.04",
                "ports": [22, 80],
            },
            "error_context": {
                "error_type": "edr_blocked",
                "error_message": "Execution blocked by security software. Signature detected.",
                "stderr": "[ERROR] Process terminated: CrowdStrike Falcon detected malicious activity",
                "stdout": "",
                "exit_code": 1,
                "duration_ms": 3500,
                "detected_defenses": ["edr", "antivirus"],
                "module_used": "rx-exploit-ssh-bruteforce",
                "technique_id": "T1110.001",
            },
            "execution_logs": [
                {"timestamp": datetime.now(timezone.utc).isoformat(), "level": "INFO", "message": "Starting SSH bruteforce attack"},
                {"timestamp": datetime.now(timezone.utc).isoformat(), "level": "INFO", "message": "Attempting authentication with user 'admin'"},
                {"timestamp": datetime.now(timezone.utc).isoformat(), "level": "ERROR", "message": "Connection blocked by EDR"},
            ]
        }
    
    async def simulate_successful_exploit(self, using_evasion: bool = True) -> Dict[str, Any]:
        """Simulate a successful exploit attempt (after AI recommendation)."""
        self.attempt_count += 1
        
        await asyncio.sleep(1.5)  # Simulate network delay
        
        return {
            "success": True,
            "task_id": str(uuid4()),
            "task_type": "EXPLOIT",
            "target": {
                "ip": "172.28.0.100",
                "hostname": "vulnerable-target",
            },
            "result": {
                "session_type": "ssh",
                "session_id": str(uuid4())[:8],
                "privilege_level": "user",
                "module_used": "rx-exploit-ssh-keyauth" if using_evasion else "rx-exploit-ssh-bruteforce",
                "evasion_used": using_evasion,
            }
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Real AI Analysis
# ═══════════════════════════════════════════════════════════════════════════════

async def perform_ai_analysis(failed_attack: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform real AI analysis using BlackboxAI/OpenAI API.
    
    Args:
        failed_attack: The failed attack details
        config: Environment configuration
        
    Returns:
        AI analysis result
    """
    print_section("🧠 AI Analysis (Real LLM API Call)", Colors.MAGENTA)
    
    print_ai(f"Calling {config['llm_provider'].upper()} API...")
    print_info(f"Model: {config['llm_model']}")
    
    try:
        # Import LLM components
        from src.core.llm.base import LLMConfig, LLMMessage
        from src.core.llm.blackbox_provider import BlackboxAIProvider
        from src.core.llm.prompts import REFLEXION_SYSTEM_PROMPT
        
        # Create provider
        llm_config = LLMConfig(
            api_key=config["llm_api_key"],
            api_base=config.get("llm_api_base") or "https://api.blackbox.ai",
            model=config["llm_model"],
            temperature=0.3,
            max_tokens=2048,
            timeout=60.0,
        )
        
        provider = BlackboxAIProvider(llm_config)
        
        # Build analysis prompt
        error_ctx = failed_attack["error_context"]
        target = failed_attack["target"]
        
        user_prompt = f"""Analyze this failed penetration test task and recommend the next action.

## Task Context:
- Task Type: {failed_attack['task_type']}
- Target IP: {target['ip']}
- Target OS: {target.get('os', 'Unknown')}
- Open Ports: {target.get('ports', [])}

## Execution Details:
- Module Used: {error_ctx.get('module_used', 'Unknown')}
- MITRE Technique: {error_ctx.get('technique_id', 'Unknown')}
- Duration: {error_ctx.get('duration_ms', 0)}ms
- Exit Code: {error_ctx.get('exit_code', -1)}

## Error Information:
- Error Type: {error_ctx['error_type']}
- Error Message: {error_ctx['error_message']}
- Detected Defenses: {', '.join(error_ctx.get('detected_defenses', []))}
- Stderr: {error_ctx.get('stderr', 'N/A')[:200]}

## Available Alternative Approaches:
1. rx-exploit-ssh-keyauth: SSH key-based authentication (stealthier)
2. rx-exploit-http-cve: Web server vulnerability exploitation
3. rx-recon-passive: Passive reconnaissance before retry

## Your Task:
Analyze why the attack failed and recommend the best next action.

Respond with JSON only:
{{
    "analysis": {{
        "category": "defense|network|authentication|vulnerability|technical|unknown",
        "root_cause": "brief description of why it failed",
        "detected_defenses": ["list", "of", "defenses"],
        "confidence": "high|medium|low"
    }},
    "recommended_action": {{
        "decision": "retry|modify_approach|skip|escalate",
        "reasoning": "detailed explanation",
        "delay_seconds": 0,
        "alternative_module": "module-id-if-modify",
        "evasion_techniques": ["technique1", "technique2"]
    }},
    "lessons_learned": ["lesson1", "lesson2"]
}}"""
        
        messages = [
            LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
            LLMMessage.user(user_prompt),
        ]
        
        # Make the API call
        start_time = datetime.utcnow()
        print_ai("Sending request to AI...")
        
        response = await provider.generate_json(messages)
        
        end_time = datetime.utcnow()
        latency = (end_time - start_time).total_seconds() * 1000
        
        # Get cost stats
        cost_stats = provider.get_cost_stats()
        
        print_success(f"AI Response received!")
        print_info(f"Latency: {latency:.0f}ms")
        print_info(f"Tokens used: ~{cost_stats['session_tokens']}")
        print_info(f"Estimated cost: ${cost_stats['total_cost_usd']:.4f}")
        
        # Display AI's analysis
        print()
        print(f"{Colors.MAGENTA}{Colors.BOLD}AI Analysis Result:{Colors.RESET}")
        print_json(response)
        
        await provider.close()
        
        return {
            "success": True,
            "analysis": response,
            "latency_ms": latency,
            "tokens_used": cost_stats['session_tokens'],
            "cost_usd": cost_stats['total_cost_usd'],
        }
        
    except Exception as e:
        print_error(f"AI Analysis failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Main Demo Flow
# ═══════════════════════════════════════════════════════════════════════════════

async def run_demo():
    """Run the main demo."""
    print_banner()
    
    # Validate environment
    config = validate_environment()
    
    # Initialize simulator
    simulator = AttackSimulator()
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Phase 1: Initial Attack (Fails)
    # ═══════════════════════════════════════════════════════════════════════════
    print_section("Phase 1: Initial Attack Attempt", Colors.RED)
    
    print_info("Targeting: vulnerable-target (172.28.0.100)")
    print_info("Attack: SSH Bruteforce (T1110.001)")
    print_info("Module: rx-exploit-ssh-bruteforce")
    print()
    
    print_status("🚀", "Launching attack...", Colors.YELLOW)
    
    failed_attack = await simulator.simulate_failed_exploit()
    
    print()
    print_error("ATTACK FAILED!")
    print_error(f"Error: {failed_attack['error_context']['error_message']}")
    print_error(f"Defenses detected: {', '.join(failed_attack['error_context']['detected_defenses'])}")
    
    # Show execution logs
    print()
    print(f"{Colors.DIM}Execution Logs:{Colors.RESET}")
    for log in failed_attack["execution_logs"]:
        level_color = Colors.RED if log["level"] == "ERROR" else Colors.WHITE
        print(f"  {level_color}[{log['level']}] {log['message']}{Colors.RESET}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Phase 2: AI Analysis
    # ═══════════════════════════════════════════════════════════════════════════
    ai_result = await perform_ai_analysis(failed_attack, config)
    
    if not ai_result["success"]:
        print_error("Demo cannot continue without AI analysis.")
        print_warning("Check your API key and try again.")
        return
    
    # Extract AI's recommendation
    analysis = ai_result["analysis"]
    decision = analysis.get("recommended_action", {}).get("decision", "skip")
    reasoning = analysis.get("recommended_action", {}).get("reasoning", "No reasoning provided")
    
    print()
    print(f"{Colors.MAGENTA}{Colors.BOLD}🧠 AI Decision: {decision.upper()}{Colors.RESET}")
    print(f"{Colors.MAGENTA}   Reasoning: {reasoning}{Colors.RESET}")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Phase 3: Retry with AI's Recommendation
    # ═══════════════════════════════════════════════════════════════════════════
    if decision in ["modify_approach", "retry"]:
        print_section("Phase 3: Retry with AI Recommendation", Colors.GREEN)
        
        new_module = analysis.get("recommended_action", {}).get("alternative_module", "rx-exploit-ssh-keyauth")
        evasion = analysis.get("recommended_action", {}).get("evasion_techniques", [])
        
        print_info(f"Using AI-recommended approach")
        print_info(f"New module: {new_module}")
        if evasion:
            print_info(f"Evasion techniques: {', '.join(evasion)}")
        print()
        
        delay = analysis.get("recommended_action", {}).get("delay_seconds", 5)
        if delay > 0:
            print_warning(f"Waiting {delay}s before retry (AI recommendation)...")
            await asyncio.sleep(min(delay, 5))  # Cap at 5s for demo
        
        print_status("🚀", "Launching modified attack...", Colors.YELLOW)
        
        success_result = await simulator.simulate_successful_exploit(using_evasion=True)
        
        print()
        if success_result["success"]:
            print_success("ATTACK SUCCESSFUL!")
            print_success(f"Session established: {success_result['result']['session_type']}")
            print_success(f"Session ID: {success_result['result']['session_id']}")
            print_success(f"Privilege Level: {success_result['result']['privilege_level']}")
        else:
            print_error("Attack still failed. Would need further AI analysis.")
    
    else:
        print_section("Phase 3: Following AI Recommendation", Colors.YELLOW)
        print_warning(f"AI recommended: {decision}")
        print_warning("Skipping further attack attempts as per AI guidance.")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Summary
    # ═══════════════════════════════════════════════════════════════════════════
    print_section("Demo Summary")
    
    print(f"""
{Colors.CYAN}Reflexion Pattern Demonstration Complete!{Colors.RESET}

{Colors.BOLD}What happened:{Colors.RESET}
  1. 🔴 First attack failed (EDR detected bruteforce attempt)
  2. 🧠 AI analyzed the failure using {config['llm_provider'].upper()} ({config['llm_model']})
  3. 🟢 AI recommended a stealthier approach
  4. ✅ Second attack succeeded using AI's recommendation

{Colors.BOLD}AI Usage Statistics:{Colors.RESET}
  • API Calls: 1
  • Tokens Used: ~{ai_result.get('tokens_used', 'N/A')}
  • Latency: {ai_result.get('latency_ms', 0):.0f}ms
  • Estimated Cost: ${ai_result.get('cost_usd', 0):.4f}

{Colors.BOLD}Key Insights:{Colors.RESET}
  • The Reflexion Pattern enables adaptive attack strategies
  • AI analyzes failures and suggests intelligent alternatives
  • This mimics how real penetration testers adapt to defenses
  • Safety limits prevent runaway API costs

{Colors.DIM}Note: This demo used simulated attacks against a local Docker target.
No real systems were harmed.{Colors.RESET}
""")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point."""
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print("\n")
        print_warning("Demo interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"Demo failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
