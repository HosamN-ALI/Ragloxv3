#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Offensive Penetration Testing Tests Runner
# ═══════════════════════════════════════════════════════════════════════════════
# This script runs all offensive penetration testing integration tests and
# generates comprehensive reports.
#
# Usage:
#   ./run_offensive_tests.sh           # Run all tests
#   ./run_offensive_tests.sh --quick   # Run quick validation only
#   ./run_offensive_tests.sh --report  # Run with HTML report generation
#
# Author: RAGLOX Integration Team
# Date: 2026-01-04
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORTS_DIR="$PROJECT_ROOT/reports"

# Ensure we're in the project root
cd "$PROJECT_ROOT"

# Print banner
echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "  RAGLOX v3.0 - Offensive Penetration Testing Integration Tests"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "${NC}"
echo "Project Root: $PROJECT_ROOT"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Parse arguments
QUICK_MODE=false
GENERATE_REPORT=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --report)
            GENERATE_REPORT=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo -e "${YELLOW}Unknown option: $1${NC}"
            shift
            ;;
    esac
done

# Create reports directory if needed
if [ "$GENERATE_REPORT" = true ]; then
    mkdir -p "$REPORTS_DIR"
fi

# Function to print section headers
print_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to run tests and capture results
run_tests() {
    local test_file=$1
    local test_name=$2
    local extra_args=$3
    
    echo -e "${YELLOW}Running: $test_name${NC}"
    echo ""
    
    if [ "$GENERATE_REPORT" = true ]; then
        pytest "$test_file" \
            -v \
            --tb=short \
            --html="$REPORTS_DIR/${test_name}_report.html" \
            --self-contained-html \
            $extra_args
    else
        pytest "$test_file" \
            -v \
            --tb=short \
            $extra_args
    fi
    
    local result=$?
    if [ $result -eq 0 ]; then
        echo -e "\n${GREEN}✓ $test_name: PASSED${NC}\n"
    else
        echo -e "\n${RED}✗ $test_name: FAILED${NC}\n"
    fi
    return $result
}

# Track overall status
OVERALL_STATUS=0

# ═══════════════════════════════════════════════════════════════════════════════
# Pre-flight Checks
# ═══════════════════════════════════════════════════════════════════════════════

print_section "Pre-flight Checks"

echo -e "${YELLOW}Checking Python environment...${NC}"
python3 --version

echo -e "${YELLOW}Checking pytest installation...${NC}"
pytest --version

echo -e "${YELLOW}Checking knowledge base data files...${NC}"
for file in data/raglox_executable_modules.json data/raglox_threat_library.json data/raglox_indexes_v2.json data/raglox_nuclei_templates.json; do
    if [ -f "$file" ]; then
        echo -e "  ${GREEN}✓${NC} $file"
    else
        echo -e "  ${RED}✗${NC} $file (missing)"
        OVERALL_STATUS=1
    fi
done

if [ $OVERALL_STATUS -ne 0 ]; then
    echo -e "\n${RED}Pre-flight checks failed. Please ensure all data files are present.${NC}"
    exit 1
fi

echo -e "\n${GREEN}All pre-flight checks passed.${NC}\n"

# ═══════════════════════════════════════════════════════════════════════════════
# Quick Validation (if requested)
# ═══════════════════════════════════════════════════════════════════════════════

if [ "$QUICK_MODE" = true ]; then
    print_section "Quick Validation Mode"
    
    echo "Running quick validation tests only..."
    
    python3 << 'EOF'
import sys
sys.path.insert(0, '.')
from src.core.knowledge import get_knowledge

print("Loading Knowledge Base...")
kb = get_knowledge()

# Quick checks
checks = [
    ("Tactics loaded", len(kb.list_tactics()) == 14),
    ("Techniques available", len(kb._techniques) > 300),
    ("RX Modules loaded", len(kb._rx_modules) > 1700),
    ("Nuclei templates loaded", len(kb._nuclei_templates) > 10000),
]

print("\nQuick Validation Results:")
print("-" * 50)

all_passed = True
for name, passed in checks:
    status = "✓ PASSED" if passed else "✗ FAILED"
    print(f"  {status}: {name}")
    if not passed:
        all_passed = False

print("-" * 50)
if all_passed:
    print("\n✓ All quick validations passed!")
    sys.exit(0)
else:
    print("\n✗ Some validations failed!")
    sys.exit(1)
EOF
    
    exit $?
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Full Test Suite
# ═══════════════════════════════════════════════════════════════════════════════

print_section "Running Full Offensive Integration Tests"

# Run the main test suite
# Run all test suites
run_tests "webapp/tests/offensive_integration_tests.py" "offensive_integration" "" || OVERALL_STATUS=1
run_tests "webapp/tests/redteam_scenarios_tests.py" "redteam_scenarios" "" || OVERALL_STATUS=1
run_tests "webapp/tests/advanced_attack_scenarios_tests.py" "advanced_attacks" "" || OVERALL_STATUS=1

# ═══════════════════════════════════════════════════════════════════════════════
# Test Summary
# ═══════════════════════════════════════════════════════════════════════════════

print_section "Test Summary"

# Generate summary report
python3 << 'EOF'
import sys
sys.path.insert(0, '.')
from src.core.knowledge import get_knowledge

kb = get_knowledge()
tactics = kb.list_tactics()

print("RAGLOX v3.0 Offensive Knowledge Base Summary")
print("=" * 60)
print("")

# Tactics summary
print("MITRE ATT&CK Tactics Coverage:")
print("-" * 60)
total_techniques = 0
for tactic in sorted(tactics, key=lambda x: x['technique_count'], reverse=True):
    tech_count = tactic['technique_count']
    total_techniques += tech_count
    bar = "█" * min(tech_count, 50) + "░" * max(0, 50 - tech_count)
    print(f"  {tactic['id']}: {tactic['name'][:25]:<25} | {tech_count:>3} | {bar[:25]}")

print("-" * 60)
print(f"Total Technique Mappings: {total_techniques}")
print("")

# Platform coverage
stats = kb.get_statistics()
print("Platform Coverage:")
print("-" * 60)
for platform, count in sorted(stats.get('modules_per_platform', {}).items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"  {platform:<20}: {count:>5} modules")

print("")
print("Executor Coverage:")
print("-" * 60)
for executor, count in sorted(stats.get('modules_per_executor', {}).items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"  {executor:<20}: {count:>5} modules")

print("")
print("Nuclei Templates by Severity:")
print("-" * 60)
for severity in ['critical', 'high', 'medium', 'low', 'info']:
    count = len(kb._nuclei_by_severity.get(severity, []))
    print(f"  {severity:<20}: {count:>5} templates")

print("")
print("=" * 60)
print(f"Total RX Modules:       {stats['total_rx_modules']:>10}")
print(f"Total Techniques:       {stats['total_techniques']:>10}")
print(f"Total Tactics:          {stats['total_tactics']:>10}")
print(f"Total Nuclei Templates: {stats['total_nuclei_templates']:>10}")
print("=" * 60)
EOF

# Final status
print_section "Final Status"

if [ $OVERALL_STATUS -eq 0 ]; then
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✓ ALL TESTS PASSED SUCCESSFULLY${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
else
    echo -e "${RED}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ✗ SOME TESTS FAILED${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════════════${NC}"
fi

if [ "$GENERATE_REPORT" = true ]; then
    echo ""
    echo -e "${BLUE}Reports generated in: $REPORTS_DIR${NC}"
    ls -la "$REPORTS_DIR"/*.html 2>/dev/null || echo "No HTML reports found"
fi

echo ""
echo "Test run completed at: $(date '+%Y-%m-%d %H:%M:%S')"
exit $OVERALL_STATUS
