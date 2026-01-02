# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Knowledge Module Tests
# Tests for Embedded Knowledge Base
# ═══════════════════════════════════════════════════════════════

import pytest
from pathlib import Path
from typing import Dict, Any

from src.core.knowledge import (
    EmbeddedKnowledge,
    init_knowledge,
    get_knowledge,
    RXModule,
    Technique,
    Tactic,
    KnowledgeStats,
    ExecutionInfo,
    Variable,
    Prerequisite,
)


# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def knowledge_base():
    """Create and load knowledge base for tests."""
    # Reset singleton before testing
    EmbeddedKnowledge.reset()
    get_knowledge.cache_clear()
    
    # Initialize with test data path
    data_path = Path(__file__).parent.parent / "data"
    knowledge = init_knowledge(data_path=str(data_path))
    
    yield knowledge
    
    # Cleanup
    EmbeddedKnowledge.reset()
    get_knowledge.cache_clear()


@pytest.fixture
def fresh_knowledge():
    """Create a fresh knowledge instance for isolated tests."""
    EmbeddedKnowledge.reset()
    get_knowledge.cache_clear()
    
    data_path = Path(__file__).parent.parent / "data"
    knowledge = EmbeddedKnowledge(data_path=str(data_path))
    
    yield knowledge
    
    EmbeddedKnowledge.reset()
    get_knowledge.cache_clear()


# ═══════════════════════════════════════════════════════════════
# Singleton Tests
# ═══════════════════════════════════════════════════════════════

class TestSingletonPattern:
    """Test Singleton pattern implementation."""
    
    def test_singleton_returns_same_instance(self):
        """Singleton should return the same instance."""
        EmbeddedKnowledge.reset()
        
        knowledge1 = EmbeddedKnowledge()
        knowledge2 = EmbeddedKnowledge()
        
        assert knowledge1 is knowledge2
        
        EmbeddedKnowledge.reset()
    
    def test_reset_creates_new_instance(self):
        """Reset should allow creating a new instance."""
        EmbeddedKnowledge.reset()
        knowledge1 = EmbeddedKnowledge()
        
        EmbeddedKnowledge.reset()
        knowledge2 = EmbeddedKnowledge()
        
        # After reset, they should be different objects
        # But since singleton pattern, next call returns same
        assert knowledge1 is not knowledge2
        
        EmbeddedKnowledge.reset()


# ═══════════════════════════════════════════════════════════════
# Data Loading Tests
# ═══════════════════════════════════════════════════════════════

class TestDataLoading:
    """Test knowledge base data loading."""
    
    def test_load_returns_true(self, knowledge_base):
        """Load should return True on success."""
        assert knowledge_base.is_loaded() is True
    
    def test_modules_loaded(self, knowledge_base):
        """RX Modules should be loaded."""
        stats = knowledge_base.get_statistics()
        assert stats['total_rx_modules'] > 0
        assert stats['total_rx_modules'] == 1761
    
    def test_techniques_loaded(self, knowledge_base):
        """Techniques should be loaded."""
        stats = knowledge_base.get_statistics()
        assert stats['total_techniques'] > 0
        assert stats['total_techniques'] == 327
    
    def test_tactics_loaded(self, knowledge_base):
        """Tactics should be loaded."""
        stats = knowledge_base.get_statistics()
        assert stats['total_tactics'] > 0
        assert stats['total_tactics'] == 14
    
    def test_platforms_loaded(self, knowledge_base):
        """Platforms should be indexed."""
        stats = knowledge_base.get_statistics()
        assert len(stats['platforms']) > 0
        assert 'windows' in stats['platforms']
        assert 'linux' in stats['platforms']
    
    def test_load_with_invalid_path(self, fresh_knowledge):
        """Load with invalid path should fail gracefully."""
        fresh_knowledge.data_path = Path("/nonexistent/path")
        result = fresh_knowledge.load()
        
        # Should return False but not crash
        assert result is False


# ═══════════════════════════════════════════════════════════════
# Statistics Tests
# ═══════════════════════════════════════════════════════════════

class TestStatistics:
    """Test knowledge base statistics."""
    
    def test_get_statistics(self, knowledge_base):
        """Get statistics should return complete info."""
        stats = knowledge_base.get_statistics()
        
        assert 'total_techniques' in stats
        assert 'total_tactics' in stats
        assert 'total_rx_modules' in stats
        assert 'platforms' in stats
        assert 'modules_per_platform' in stats
        assert 'modules_per_executor' in stats
        assert 'loaded' in stats
    
    def test_modules_per_platform(self, knowledge_base):
        """Modules per platform should have windows as highest."""
        stats = knowledge_base.get_statistics()
        
        assert 'windows' in stats['modules_per_platform']
        assert stats['modules_per_platform']['windows'] > 100
    
    def test_modules_per_executor(self, knowledge_base):
        """Modules per executor should include powershell."""
        stats = knowledge_base.get_statistics()
        
        assert 'powershell' in stats['modules_per_executor']


# ═══════════════════════════════════════════════════════════════
# Technique Query Tests
# ═══════════════════════════════════════════════════════════════

class TestTechniqueQueries:
    """Test technique query methods."""
    
    def test_get_technique_by_id(self, knowledge_base):
        """Get technique by ID should work."""
        technique = knowledge_base.get_technique('T1003')
        
        assert technique is not None
        assert technique['id'] == 'T1003'
        assert technique['name'] == 'OS Credential Dumping'
    
    def test_get_technique_not_found(self, knowledge_base):
        """Get non-existent technique should return None."""
        technique = knowledge_base.get_technique('T9999')
        assert technique is None
    
    def test_get_technique_with_subtechnique(self, knowledge_base):
        """Get sub-technique should work."""
        technique = knowledge_base.get_technique('T1003.001')
        
        # If sub-technique exists
        if technique:
            assert 'T1003' in technique['id']
    
    def test_list_techniques(self, knowledge_base):
        """List techniques should return paginated results."""
        techniques, total = knowledge_base.list_techniques(limit=10, offset=0)
        
        assert len(techniques) <= 10
        assert total > 0
    
    def test_list_techniques_with_platform(self, knowledge_base):
        """List techniques filtered by platform."""
        techniques, total = knowledge_base.list_techniques(platform='windows', limit=50)
        
        assert len(techniques) > 0
        for tech in techniques:
            assert 'windows' in [p.lower() for p in tech['platforms']]


# ═══════════════════════════════════════════════════════════════
# Module Query Tests
# ═══════════════════════════════════════════════════════════════

class TestModuleQueries:
    """Test RX module query methods."""
    
    def test_get_module_by_id(self, knowledge_base):
        """Get module by ID should work."""
        # First get a valid module ID
        modules, _ = knowledge_base.list_modules(limit=1)
        if modules:
            module_id = modules[0]['rx_module_id']
            module = knowledge_base.get_module(module_id)
            
            assert module is not None
            assert module['rx_module_id'] == module_id
    
    def test_get_module_not_found(self, knowledge_base):
        """Get non-existent module should return None."""
        module = knowledge_base.get_module('rx-invalid-999')
        assert module is None
    
    def test_get_modules_for_technique(self, knowledge_base):
        """Get modules for technique should work."""
        modules = knowledge_base.get_modules_for_technique('T1003')
        
        assert len(modules) > 0
        for module in modules:
            assert module['technique_id'] == 'T1003'
    
    def test_get_modules_for_technique_with_platform(self, knowledge_base):
        """Get modules filtered by platform."""
        modules = knowledge_base.get_modules_for_technique('T1003', platform='windows')
        
        for module in modules:
            assert 'windows' in [p.lower() for p in module['execution']['platforms']]
    
    def test_list_modules_pagination(self, knowledge_base):
        """List modules with pagination."""
        page1, total = knowledge_base.list_modules(limit=10, offset=0)
        page2, _ = knowledge_base.list_modules(limit=10, offset=10)
        
        assert len(page1) <= 10
        assert len(page2) <= 10
        assert total > 20
        
        # Pages should be different
        if page1 and page2:
            assert page1[0]['rx_module_id'] != page2[0]['rx_module_id']
    
    def test_list_modules_by_platform(self, knowledge_base):
        """List modules filtered by platform."""
        modules, total = knowledge_base.list_modules(platform='linux', limit=50)
        
        assert len(modules) > 0
        for module in modules:
            assert 'linux' in [p.lower() for p in module['execution']['platforms']]
    
    def test_list_modules_by_executor(self, knowledge_base):
        """List modules filtered by executor type."""
        modules, total = knowledge_base.list_modules(executor_type='powershell', limit=50)
        
        assert len(modules) > 0
        for module in modules:
            assert module['execution']['executor_type'] == 'powershell'


# ═══════════════════════════════════════════════════════════════
# Tactic Query Tests
# ═══════════════════════════════════════════════════════════════

class TestTacticQueries:
    """Test tactic query methods."""
    
    def test_list_tactics(self, knowledge_base):
        """List tactics should return all tactics."""
        tactics = knowledge_base.list_tactics()
        
        assert len(tactics) > 0
        assert len(tactics) == 14  # 14 tactics in ATT&CK
    
    def test_tactic_has_required_fields(self, knowledge_base):
        """Each tactic should have required fields."""
        tactics = knowledge_base.list_tactics()
        
        for tactic in tactics:
            assert 'id' in tactic
            assert 'name' in tactic
            assert 'technique_count' in tactic
    
    def test_get_techniques_for_tactic(self, knowledge_base):
        """Get techniques for a tactic."""
        # Try with a known tactic
        techniques = knowledge_base.get_techniques_for_tactic('TA0001')
        
        # Some tactics might have no techniques mapped
        # Just verify it doesn't error


# ═══════════════════════════════════════════════════════════════
# Platform Query Tests
# ═══════════════════════════════════════════════════════════════

class TestPlatformQueries:
    """Test platform query methods."""
    
    def test_get_modules_for_platform(self, knowledge_base):
        """Get modules for platform should work."""
        modules = knowledge_base.get_modules_for_platform('windows', limit=20)
        
        assert len(modules) > 0
        assert len(modules) <= 20
    
    def test_get_modules_for_invalid_platform(self, knowledge_base):
        """Get modules for invalid platform should return empty."""
        modules = knowledge_base.get_modules_for_platform('invalid_platform')
        assert len(modules) == 0


# ═══════════════════════════════════════════════════════════════
# Search Tests
# ═══════════════════════════════════════════════════════════════

class TestSearchFunctionality:
    """Test search functionality."""
    
    def test_search_by_keyword(self, knowledge_base):
        """Search by keyword should find results."""
        results = knowledge_base.search_modules('credential')
        
        assert len(results) > 0
    
    def test_search_by_technique_id(self, knowledge_base):
        """Search by technique ID should work."""
        results = knowledge_base.search_modules('T1003')
        
        assert len(results) > 0
    
    def test_search_with_platform_filter(self, knowledge_base):
        """Search with platform filter."""
        results = knowledge_base.search_modules('dump', platform='windows')
        
        for result in results:
            assert 'windows' in [p.lower() for p in result['execution']['platforms']]
    
    def test_search_with_limit(self, knowledge_base):
        """Search should respect limit."""
        results = knowledge_base.search_modules('credential', limit=5)
        
        assert len(results) <= 5
    
    def test_search_no_results(self, knowledge_base):
        """Search with no matching results."""
        results = knowledge_base.search_modules('xyznonexistent123')
        
        assert len(results) == 0


# ═══════════════════════════════════════════════════════════════
# Task-Oriented Query Tests
# ═══════════════════════════════════════════════════════════════

class TestTaskOrientedQueries:
    """Test task-oriented query methods for specialists."""
    
    def test_get_module_for_task(self, knowledge_base):
        """Get best module for a task."""
        module = knowledge_base.get_module_for_task(
            technique='T1003',
            platform='windows'
        )
        
        assert module is not None
        assert module['technique_id'] == 'T1003'
    
    def test_get_module_for_task_no_match(self, knowledge_base):
        """Get module for task with no match."""
        module = knowledge_base.get_module_for_task(
            technique='T9999',
            platform='invalid'
        )
        
        assert module is None
    
    def test_get_exploit_modules(self, knowledge_base):
        """Get exploit modules should return results."""
        modules = knowledge_base.get_exploit_modules(platform='windows')
        
        # Should return some exploit-related modules
        assert isinstance(modules, list)
    
    def test_get_recon_modules(self, knowledge_base):
        """Get recon modules should return results."""
        modules = knowledge_base.get_recon_modules(platform='windows')
        
        assert len(modules) > 0
    
    def test_get_credential_modules(self, knowledge_base):
        """Get credential modules should return results."""
        modules = knowledge_base.get_credential_modules(platform='windows')
        
        assert len(modules) > 0
        # Should include T1003 related modules
        technique_ids = [m['technique_id'] for m in modules]
        assert any('T1003' in tid for tid in technique_ids)
    
    def test_get_privesc_modules(self, knowledge_base):
        """Get privesc modules should return results."""
        modules = knowledge_base.get_privesc_modules(platform='windows')
        
        assert isinstance(modules, list)


# ═══════════════════════════════════════════════════════════════
# Data Class Tests
# ═══════════════════════════════════════════════════════════════

class TestDataClasses:
    """Test data class functionality."""
    
    def test_rx_module_id_generation(self):
        """RX Module ID should be auto-generated."""
        execution = ExecutionInfo(
            platforms=['windows'],
            executor_type='powershell',
            command='test'
        )
        
        module = RXModule(
            index=1,
            technique_id='T1003',
            technique_name='Test',
            description='Test',
            execution=execution
        )
        
        assert module.rx_module_id == 'rx-t1003-001'
    
    def test_execution_info_defaults(self):
        """ExecutionInfo should have proper defaults."""
        execution = ExecutionInfo(
            platforms=['windows'],
            executor_type='powershell',
            command='test'
        )
        
        assert execution.elevation_required is False
        assert execution.cleanup_command is None
    
    def test_variable_creation(self):
        """Variable data class should work."""
        var = Variable(
            name='test_var',
            description='A test variable',
            type='string',
            default_value='default'
        )
        
        assert var.name == 'test_var'
        assert var.default_value == 'default'
    
    def test_prerequisite_creation(self):
        """Prerequisite data class should work."""
        prereq = Prerequisite(
            description='Test prerequisite',
            check_command='test -f /tmp/test',
            install_command='touch /tmp/test'
        )
        
        assert prereq.description == 'Test prerequisite'


# ═══════════════════════════════════════════════════════════════
# Reload Tests
# ═══════════════════════════════════════════════════════════════

class TestReloadFunctionality:
    """Test reload functionality."""
    
    def test_reload_knowledge_base(self, knowledge_base):
        """Reload should refresh all data."""
        # Get stats before reload
        stats_before = knowledge_base.get_statistics()
        
        # Reload
        result = knowledge_base.reload()
        
        # Get stats after
        stats_after = knowledge_base.get_statistics()
        
        assert result is True
        assert stats_before['total_rx_modules'] == stats_after['total_rx_modules']


# ═══════════════════════════════════════════════════════════════
# Edge Cases
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_empty_search_query(self, knowledge_base):
        """Search with very short query should still work."""
        results = knowledge_base.search_modules('a', limit=5)
        # Should not error
        assert isinstance(results, list)
    
    def test_special_characters_in_search(self, knowledge_base):
        """Search with special characters should not error."""
        results = knowledge_base.search_modules('test$%^&*()', limit=5)
        assert isinstance(results, list)
    
    def test_unicode_in_search(self, knowledge_base):
        """Search with unicode should not error."""
        results = knowledge_base.search_modules('', limit=5)
        assert isinstance(results, list)
    
    def test_large_offset(self, knowledge_base):
        """Large offset should return empty list."""
        modules, total = knowledge_base.list_modules(offset=100000, limit=10)
        assert len(modules) == 0
    
    def test_zero_limit(self, knowledge_base):
        """Zero limit should return empty list."""
        modules, total = knowledge_base.list_modules(limit=0)
        assert len(modules) == 0


# ═══════════════════════════════════════════════════════════════
# Concurrency Tests
# ═══════════════════════════════════════════════════════════════

class TestConcurrency:
    """Test thread-safety of singleton."""
    
    def test_concurrent_access(self, knowledge_base):
        """Multiple concurrent accesses should work."""
        import concurrent.futures
        
        def query_knowledge():
            return knowledge_base.get_technique('T1003')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(query_knowledge) for _ in range(10)]
            results = [f.result() for f in futures]
        
        # All results should be identical
        assert all(r == results[0] for r in results)
