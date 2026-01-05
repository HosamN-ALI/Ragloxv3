## RAGLOX v3.0 – Intelligence & Reasoning Audit

**Scope:** Analysis of `AnalysisSpecialist`, `ReconSpecialist`, and `AttackSpecialist` to evaluate reasoning depth, autonomy, and professional red-team readiness.  
**Rating:** **Medium intelligence** – richer than scripted automation, but missing persistent memory, cross-specialist feedback, and stealth/pivot orchestration to qualify as advanced.

### 1) Reasoning Depth
- **Predominantly scripted decision ladders:** `AnalysisSpecialist` maps error strings to categories and static retry recipes (`ERROR_CATEGORIES` / `RETRY_STRATEGIES`, lines 78-155) and branches on fixed rules (`_make_decision`, 797-996). LLM is only consulted for narrow triggers (defense count > 1 or >3 alternatives, `_needs_llm_analysis`, 998-1008), so most flows stay rule-bound.
- **Limited reflection loop:** Failures are analyzed once and appended to an in-memory list (`_analysis_history`, 183-199) but not persisted or reused to avoid repeating the same module/technique later in the mission.
- **Shallow exploit selection:** `AttackSpecialist` picks a single module via `get_module_for_vuln` if present (lookup at line 242 within the 239-246 block) and never ranks exploits by mission goal or blast radius; failed exploits return `error_context` but no adaptive re-planning is triggered on the attack side.
- **Targeting strategy lacks depth:** No preference for high-impact RCE paths vs. low-value vulns, and no chaining of recon→exploit choices based on mission goals.

### 2) Strategic Autonomy
- **Hard-coded vs. LLM:** Decision gates heavily favor hard-coded rules; LLM is an optional add-on rather than the default planner. No cost/latency-aware planner chooses between scripted vs. LLM paths.
- **Missing pivot automation:** `AttackSpecialist` creates follow-up tasks (priv esc / cred harvest) but never re-injects harvested creds into other workspaces/targets (no credential pivot orchestration in the module).
- **Single-shot context:** Analysis decisions are not pushed back into new task creation for Recon/Attack; there is no per-mission shared state of “what failed and why” to influence subsequent tasks.

### 3) Professional Red Team Readiness
- **Stealth vs. Noise:** `ReconSpecialist` drives fixed common port lists and template selection without throttling, jitter, or detection-aware template choices (lines 87-156, 169-185). Within this module there is no explicit WAF/EDR detection or scan downshift logic, so defaults resemble noisy enumeration rather than operator-grade stealth.
- **Operational logic transparency:** Some reasoning strings are returned from `AnalysisSpecialist`, but they are not persisted to the blackboard for operator review, and Attack/Recon do not emit structured justifications when launching scans/exploits.

### 4) Gap Identification (weak/Surface intelligence)
- **Short-term memory hole:** `_analysis_history` is in-memory only and never consulted by `_make_decision`; it is used only for stats/recent history helpers, so failed modules/defenses are not cached per target/mission to prevent repetition.
- **No defense-aware re-tasking:** Detected defenses in `error_context` are not propagated to Recon/Attack to choose evasion-friendly templates or alternate vectors.
- **No credential/asset pivoting:** Although `CRED_HARVEST` tasks exist, harvested credentials are not programmatically reinjected into other tasks or workspaces for automated pivoting.
- **Goal-agnostic prioritization:** Specialists lack a mission-goal scorer (e.g., favor RCE on crown-jewel assets over peripheral services).

### Recommendations to elevate from automation → thought partner
1. **Persist short-term reflection memory:** Write failed module/defense fingerprints to the blackboard per target/mission and consult it before scheduling retries or new tasks (skip or swap modules that already failed under the same defense signature).
2. **Wire reflection into task generation:** Feed `AnalysisSpecialist` decisions back into `AttackSpecialist`/`ReconSpecialist` task builders (e.g., auto-create evasion-mode tasks when category == defense, or nuclei-guided recon when vulnerability is patched).
3. **Stealth profiles:** Add operator-selectable profiles (aggressive/stealth) controlling port lists, rate limits, nuclei template families, and jitter. Default to stealth when defenses are detected.
4. **Credential pivot engine:** When `CRED_HARVEST` succeeds, automatically schedule credential-based exploitation across known targets/workspaces with precedence over brute-force paths.
5. **Goal-aware exploit ranking:** Introduce a mission-goal scorer that prefers RCE/priv-esc on high-value assets and deprioritizes noisy scans on low-value ones; let LLM arbitrate when multiple viable chains exist.
