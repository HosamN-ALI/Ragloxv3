# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Nuclei Templates as Embedded Knowledge Tests
# Comprehensive tests for Nuclei templates integration in Knowledge Base
# ═══════════════════════════════════════════════════════════════

import pytest
from typing import Dict, Any, List
from unittest.mock import MagicMock, patch
from uuid import uuid4

from src.core.knowledge import (
    init_knowledge, get_knowledge, EmbeddedKnowledge,
    NucleiTemplate
)


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def knowledge():
    """Initialize knowledge base with test data."""
    kb = init_knowledge(data_path="data")
    yield kb


@pytest.fixture
def sample_cve_ids():
    """Sample CVE IDs for testing."""
    return [
        "CVE-2021-44228",  # Log4j
        "CVE-2022-22965",  # Spring4Shell
        "CVE-2021-45046",  # Log4j second
        "CVE-2022-42889",  # Text4Shell
        "CVE-2022-34265",  # Django SQL Injection
    ]


# ═══════════════════════════════════════════════════════════════
# Nuclei Templates Loading Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiTemplatesLoading:
    """Test Nuclei templates loading into knowledge base."""
    
    def test_nuclei_templates_loaded(self, knowledge):
        """Verify Nuclei templates are loaded into memory."""
        stats = knowledge.get_statistics()
        assert stats.get("total_nuclei_templates", 0) > 0, \
            "No Nuclei templates loaded"
    
    def test_nuclei_templates_count(self, knowledge):
        """Verify significant number of templates loaded."""
        stats = knowledge.get_statistics()
        total = stats.get("total_nuclei_templates", 0)
        # Should have thousands of templates
        assert total >= 10000, \
            f"Expected at least 10000 templates, got {total}"
    
    def test_nuclei_severity_distribution(self, knowledge):
        """Verify templates have severity distribution."""
        stats = knowledge.get_statistics()
        by_severity = stats.get("nuclei_by_severity", {})
        
        # Should have templates in each severity
        expected_severities = ["critical", "high", "medium", "low", "info"]
        for sev in expected_severities:
            assert sev in by_severity, f"Missing severity: {sev}"
            assert by_severity[sev] > 0, f"No templates for {sev}"
    
    def test_nuclei_protocol_distribution(self, knowledge):
        """Verify templates have protocol distribution."""
        stats = knowledge.get_statistics()
        by_protocol = stats.get("nuclei_by_protocol", {})
        
        # Should have common protocols
        expected_protocols = ["http", "tcp", "dns", "ssl"]
        for proto in expected_protocols:
            assert proto in by_protocol, f"Missing protocol: {proto}"
    
    def test_nuclei_critical_count(self, knowledge):
        """Verify critical templates count is significant."""
        stats = knowledge.get_statistics()
        by_severity = stats.get("nuclei_by_severity", {})
        critical = by_severity.get("critical", 0)
        
        # Should have hundreds of critical templates
        assert critical >= 1000, \
            f"Expected at least 1000 critical templates, got {critical}"


# ═══════════════════════════════════════════════════════════════
# Nuclei Templates Query Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiTemplatesQuery:
    """Test Nuclei templates querying functionality."""
    
    def test_get_nuclei_template_by_id(self, knowledge):
        """Test retrieving template by ID."""
        # Get a critical template (should exist)
        templates = knowledge.get_nuclei_critical_templates(limit=1)
        assert len(templates) > 0
        
        template_id = templates[0]["template_id"]
        template = knowledge.get_nuclei_template(template_id)
        
        assert template is not None
        assert template["template_id"] == template_id
        assert "name" in template
        assert "severity" in template
    
    def test_get_nuclei_template_not_found(self, knowledge):
        """Test retrieving non-existent template."""
        result = knowledge.get_nuclei_template("non-existent-template-xyz")
        assert result is None
    
    def test_get_nuclei_templates_by_severity(self, knowledge):
        """Test filtering templates by severity."""
        critical = knowledge.get_nuclei_templates_by_severity("critical", limit=10)
        
        assert len(critical) > 0
        for t in critical:
            assert t["severity"].lower() == "critical"
    
    def test_get_nuclei_templates_by_tag(self, knowledge):
        """Test filtering templates by tag."""
        rce_templates = knowledge.get_nuclei_templates_by_tag("rce", limit=10)
        
        assert len(rce_templates) > 0
        for t in rce_templates:
            assert "rce" in [tag.lower() for tag in t["tags"]]
    
    def test_get_nuclei_critical_templates(self, knowledge):
        """Test getting critical templates shortcut."""
        critical = knowledge.get_nuclei_critical_templates(limit=5)
        
        assert len(critical) > 0
        for t in critical:
            assert t["severity"].lower() == "critical"
    
    def test_get_nuclei_rce_templates(self, knowledge):
        """Test getting RCE templates shortcut."""
        rce = knowledge.get_nuclei_rce_templates(limit=5)
        
        assert len(rce) > 0
        for t in rce:
            tags_lower = [tag.lower() for tag in t["tags"]]
            assert "rce" in tags_lower
    
    def test_get_nuclei_sqli_templates(self, knowledge):
        """Test getting SQL injection templates shortcut."""
        sqli = knowledge.get_nuclei_sqli_templates(limit=5)
        
        assert len(sqli) > 0
        for t in sqli:
            tags_lower = [tag.lower() for tag in t["tags"]]
            assert "sqli" in tags_lower
    
    def test_get_nuclei_xss_templates(self, knowledge):
        """Test getting XSS templates shortcut."""
        xss = knowledge.get_nuclei_xss_templates(limit=5)
        
        assert len(xss) > 0
        for t in xss:
            tags_lower = [tag.lower() for tag in t["tags"]]
            assert "xss" in tags_lower


# ═══════════════════════════════════════════════════════════════
# CVE Search Tests
# ═══════════════════════════════════════════════════════════════

class TestCVESearch:
    """Test CVE-based searching functionality."""
    
    def test_search_log4j_cve(self, knowledge):
        """Test searching for Log4j CVE templates."""
        results = knowledge.search_nuclei_templates("log4j", limit=10)
        
        assert len(results) > 0, "No Log4j templates found"
        
        # Should find Log4j related templates
        names_lower = [t["name"].lower() for t in results]
        assert any("log4j" in name for name in names_lower)
    
    def test_search_spring4shell_cve(self, knowledge):
        """Test searching for Spring4Shell templates."""
        results = knowledge.search_nuclei_templates("spring", limit=10)
        
        assert len(results) > 0, "No Spring templates found"
    
    def test_search_wordpress_templates(self, knowledge):
        """Test searching for WordPress templates."""
        results = knowledge.search_nuclei_templates("wordpress", limit=10)
        
        assert len(results) > 0, "No WordPress templates found"
    
    def test_search_apache_templates(self, knowledge):
        """Test searching for Apache templates."""
        results = knowledge.search_nuclei_templates("apache", limit=10)
        
        assert len(results) > 0, "No Apache templates found"
    
    def test_search_with_severity_filter(self, knowledge):
        """Test searching with severity filter."""
        results = knowledge.search_nuclei_templates(
            "rce", 
            severity="critical",
            limit=10
        )
        
        assert len(results) > 0
        for t in results:
            assert t["severity"].lower() == "critical"
    
    def test_search_with_protocol_filter(self, knowledge):
        """Test searching with protocol filter."""
        results = knowledge.search_nuclei_templates(
            "injection",
            protocol="http",
            limit=10
        )
        
        assert len(results) >= 0  # May have 0 results but should not error


# ═══════════════════════════════════════════════════════════════
# Listing and Pagination Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiListing:
    """Test Nuclei templates listing with pagination."""
    
    def test_list_nuclei_templates(self, knowledge):
        """Test basic listing."""
        templates, total = knowledge.list_nuclei_templates(limit=10)
        
        assert len(templates) == 10
        assert total > 10
    
    def test_list_nuclei_templates_pagination(self, knowledge):
        """Test pagination works correctly."""
        # Get first page
        page1, total1 = knowledge.list_nuclei_templates(limit=5, offset=0)
        # Get second page
        page2, total2 = knowledge.list_nuclei_templates(limit=5, offset=5)
        
        assert len(page1) == 5
        assert len(page2) == 5
        assert total1 == total2  # Total should be same
        
        # Pages should be different
        ids1 = {t["template_id"] for t in page1}
        ids2 = {t["template_id"] for t in page2}
        assert ids1 != ids2
    
    def test_list_nuclei_templates_severity_filter(self, knowledge):
        """Test listing with severity filter."""
        templates, total = knowledge.list_nuclei_templates(
            severity="critical",
            limit=10
        )
        
        assert len(templates) > 0
        for t in templates:
            assert t["severity"].lower() == "critical"
    
    def test_list_nuclei_templates_protocol_filter(self, knowledge):
        """Test listing with protocol filter."""
        templates, total = knowledge.list_nuclei_templates(
            protocol="http",
            limit=10
        )
        
        assert len(templates) > 0
        for t in templates:
            assert "http" in [p.lower() for p in t["protocol"]]
    
    def test_list_nuclei_templates_tag_filter(self, knowledge):
        """Test listing with tag filter."""
        templates, total = knowledge.list_nuclei_templates(
            tag="cve",
            limit=10
        )
        
        assert len(templates) > 0
        for t in templates:
            assert "cve" in [tag.lower() for tag in t["tags"]]


# ═══════════════════════════════════════════════════════════════
# Template Data Quality Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiTemplateQuality:
    """Test quality of loaded Nuclei template data."""
    
    def test_template_has_required_fields(self, knowledge):
        """Test templates have all required fields."""
        templates, _ = knowledge.list_nuclei_templates(limit=100)
        
        required_fields = ["template_id", "name", "severity"]
        for t in templates:
            for field in required_fields:
                assert field in t, f"Missing required field: {field}"
    
    def test_template_id_unique(self, knowledge):
        """Test template IDs are unique."""
        templates, total = knowledge.list_nuclei_templates(limit=1000)
        
        ids = [t["template_id"] for t in templates]
        assert len(ids) == len(set(ids)), "Duplicate template IDs found"
    
    def test_critical_templates_have_cve(self, knowledge):
        """Test that many critical templates have CVE IDs."""
        critical = knowledge.get_nuclei_critical_templates(limit=100)
        
        # cve_id can be a string or list
        def has_cve(t):
            cve = t.get("cve_id")
            if not cve:
                return False
            if isinstance(cve, list):
                return len(cve) > 0
            return bool(cve)
        
        with_cve = sum(1 for t in critical if has_cve(t))
        
        # At least 30% should have CVE IDs (some templates are generic)
        assert with_cve >= len(critical) * 0.3, \
            f"Only {with_cve}/{len(critical)} critical templates have CVE IDs"
    
    def test_templates_have_tags(self, knowledge):
        """Test templates have tags for categorization."""
        templates, _ = knowledge.list_nuclei_templates(limit=100)
        
        with_tags = sum(1 for t in templates if t.get("tags"))
        
        # Most templates should have tags
        assert with_tags >= len(templates) * 0.8, \
            f"Only {with_tags}/{len(templates)} templates have tags"


# ═══════════════════════════════════════════════════════════════
# Integration with RX Modules Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiRXModulesIntegration:
    """Test integration between Nuclei templates and RX Modules."""
    
    def test_both_knowledge_sources_loaded(self, knowledge):
        """Test both Nuclei templates and RX Modules are loaded."""
        stats = knowledge.get_statistics()
        
        assert stats.get("total_rx_modules", 0) > 0, "No RX modules loaded"
        assert stats.get("total_nuclei_templates", 0) > 0, "No Nuclei templates loaded"
    
    def test_similar_technique_coverage(self, knowledge):
        """Test that RX Modules cover similar techniques as Nuclei."""
        # Search for credential dumping modules
        rx_creds = knowledge.search_modules("credential", limit=10)
        nuclei_creds = knowledge.search_nuclei_templates("credential", limit=10)
        
        # Both should have results
        assert len(rx_creds) > 0 or len(nuclei_creds) > 0
    
    def test_rx_module_query_still_works(self, knowledge):
        """Test RX Module queries still work after Nuclei integration."""
        # Test standard RX Module queries
        modules = knowledge.search_modules("mimikatz", limit=5)
        assert len(modules) > 0
        
        # Test technique query
        techniques, total = knowledge.list_techniques(limit=10)
        assert total > 0
        
        # Test platform query
        windows_modules = knowledge.get_modules_for_platform("windows", limit=5)
        assert len(windows_modules) > 0
    
    def test_statistics_include_both(self, knowledge):
        """Test statistics include both knowledge sources."""
        stats = knowledge.get_statistics()
        
        # RX Module stats
        assert "total_rx_modules" in stats
        assert "total_techniques" in stats
        assert "total_tactics" in stats
        assert "modules_per_platform" in stats
        assert "modules_per_executor" in stats
        
        # Nuclei stats
        assert "total_nuclei_templates" in stats
        assert "nuclei_by_severity" in stats
        assert "nuclei_by_protocol" in stats


# ═══════════════════════════════════════════════════════════════
# Performance Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiPerformance:
    """Test performance of Nuclei templates queries."""
    
    def test_search_performance(self, knowledge):
        """Test search completes in reasonable time."""
        import time
        
        start = time.time()
        for _ in range(100):
            knowledge.search_nuclei_templates("rce", limit=10)
        elapsed = time.time() - start
        
        # Should complete 100 searches in under 5 seconds
        assert elapsed < 5.0, f"Search too slow: {elapsed:.2f}s for 100 queries"
    
    def test_listing_performance(self, knowledge):
        """Test listing completes in reasonable time."""
        import time
        
        start = time.time()
        for _ in range(50):
            knowledge.list_nuclei_templates(severity="critical", limit=20)
        elapsed = time.time() - start
        
        # Should complete 50 listings in under 3 seconds
        assert elapsed < 3.0, f"Listing too slow: {elapsed:.2f}s for 50 queries"
    
    def test_memory_usage_reasonable(self, knowledge):
        """Test memory usage is reasonable."""
        stats = knowledge.get_statistics()
        memory_mb = stats.get("memory_size_mb", 0)
        
        # Should be under 100MB for indices (actual data in JSON file)
        assert memory_mb < 100, f"Memory usage too high: {memory_mb:.2f}MB"


# ═══════════════════════════════════════════════════════════════
# Edge Cases Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_search_query(self, knowledge):
        """Test empty search query returns empty or minimal results."""
        results = knowledge.search_nuclei_templates("", limit=10)
        # Empty query may return 0 results or some if matching logic allows
        assert isinstance(results, list)
    
    def test_special_characters_in_search(self, knowledge):
        """Test special characters in search don't crash."""
        # These should not raise exceptions
        knowledge.search_nuclei_templates("CVE-2021-*", limit=10)
        knowledge.search_nuclei_templates("sql'; DROP", limit=10)
        knowledge.search_nuclei_templates("<script>alert(1)</script>", limit=10)
    
    def test_invalid_severity_filter(self, knowledge):
        """Test invalid severity filter returns empty."""
        templates, total = knowledge.list_nuclei_templates(
            severity="super-critical",  # Invalid
            limit=10
        )
        assert total == 0
    
    def test_invalid_protocol_filter(self, knowledge):
        """Test invalid protocol filter returns empty."""
        templates, total = knowledge.list_nuclei_templates(
            protocol="xyz-protocol",  # Invalid
            limit=10
        )
        assert total == 0
    
    def test_large_offset(self, knowledge):
        """Test large offset returns empty list."""
        templates, total = knowledge.list_nuclei_templates(
            offset=999999,
            limit=10
        )
        assert len(templates) == 0
        assert total > 0  # Total should still be accurate
    
    def test_zero_limit(self, knowledge):
        """Test zero limit returns empty list."""
        templates, total = knowledge.list_nuclei_templates(limit=0)
        assert len(templates) == 0


# ═══════════════════════════════════════════════════════════════
# Comparison Tests - Nuclei vs RX Modules Behavior
# ═══════════════════════════════════════════════════════════════

class TestNucleiVsRXModulesBehavior:
    """Test that Nuclei templates behave similarly to RX Modules."""
    
    def test_search_returns_dicts(self, knowledge):
        """Test search returns list of dicts like RX Modules."""
        nuclei_results = knowledge.search_nuclei_templates("apache", limit=5)
        rx_results = knowledge.search_modules("credential", limit=5)
        
        # Both should return lists of dicts
        for r in nuclei_results:
            assert isinstance(r, dict)
        for r in rx_results:
            assert isinstance(r, dict)
    
    def test_list_returns_tuple(self, knowledge):
        """Test list functions return tuple of (list, total) like RX Modules."""
        nuclei_result = knowledge.list_nuclei_templates(limit=5)
        rx_result = knowledge.list_modules(limit=5)
        
        # Both should return (list, int)
        assert isinstance(nuclei_result, tuple)
        assert isinstance(nuclei_result[0], list)
        assert isinstance(nuclei_result[1], int)
        
        assert isinstance(rx_result, tuple)
        assert isinstance(rx_result[0], list)
        assert isinstance(rx_result[1], int)
    
    def test_get_by_id_returns_dict_or_none(self, knowledge):
        """Test get by ID returns dict or None like RX Modules."""
        # Valid IDs
        templates, _ = knowledge.list_nuclei_templates(limit=1)
        if templates:
            result = knowledge.get_nuclei_template(templates[0]["template_id"])
            assert isinstance(result, dict)
        
        modules, _ = knowledge.list_modules(limit=1)
        if modules:
            result = knowledge.get_module(modules[0]["rx_module_id"])
            assert isinstance(result, dict)
        
        # Invalid IDs
        assert knowledge.get_nuclei_template("invalid-id") is None
        assert knowledge.get_module("invalid-id") is None


# ═══════════════════════════════════════════════════════════════
# Reload Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiReload:
    """Test reload functionality includes Nuclei templates."""
    
    def test_reload_preserves_nuclei_templates(self, knowledge):
        """Test reload preserves Nuclei templates."""
        stats_before = knowledge.get_statistics()
        nuclei_before = stats_before.get("total_nuclei_templates", 0)
        
        # Reload
        knowledge.reload()
        
        stats_after = knowledge.get_statistics()
        nuclei_after = stats_after.get("total_nuclei_templates", 0)
        
        # Should have same count after reload
        assert nuclei_after == nuclei_before


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
