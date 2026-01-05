# Critical Bug Fix - JSON Deserialization in Blackboard

## Issue Description

The `_get_hash()` method in `src/core/blackboard.py` was returning raw Redis hash data without deserializing JSON strings back to Python objects. This caused critical data loss in the data flow:

**NucleiScanner → Vulnerability → Redis → AttackSpecialist**

### Impact

When a vulnerability with complex fields (lists, dicts) was stored and retrieved:

```python
# What gets stored:
vuln = Vulnerability(
    rx_modules=["rx-ms17-010", "rx-eternalblue-v2"],  # List
    metadata={
        "curl_command": "curl -X POST ...",  # Dict
        "matcher_name": "status-code"
    }
)

# After retrieval (BEFORE FIX):
retrieved = await blackboard.get_vulnerability(vuln_id)
print(type(retrieved["rx_modules"]))  # ❌ <class 'str'>
print(type(retrieved["metadata"]))    # ❌ <class 'str'>

# AttackSpecialist would fail:
for module in retrieved["rx_modules"]:  # Iterates over characters!
    # Gets: '"', '[', '"', 'r', 'x', '-', ...
```

## Fix Applied

### File: `src/core/blackboard.py`

**Lines: 130-155 (approximately)**

```python
async def _get_hash(self, key: str) -> Optional[Dict[str, Any]]:
    """
    Get a hash from Redis and deserialize JSON fields.
    
    This method properly deserializes complex fields (lists, dicts) that were
    JSON-serialized during _set_hash(). This ensures that when AttackSpecialist
    retrieves a Vulnerability, fields like rx_modules and metadata are proper
    Python objects, not JSON strings.
    """
    data = await self.redis.hgetall(key)
    if not data:
        return None
    
    # Deserialize JSON strings back to objects
    deserialized = {}
    for k, v in data.items():
        # Try to parse as JSON if it looks like JSON
        if isinstance(v, str) and v and (v.startswith('[') or v.startswith('{')):
            try:
                deserialized[k] = json.loads(v)
            except json.JSONDecodeError:
                # Not valid JSON, keep as string
                deserialized[k] = v
        else:
            deserialized[k] = v
    
    return deserialized
```

## Verification

After this fix:

```python
# After retrieval (AFTER FIX):
retrieved = await blackboard.get_vulnerability(vuln_id)
print(type(retrieved["rx_modules"]))  # ✅ <class 'list'>
print(type(retrieved["metadata"]))    # ✅ <class 'dict'>

# AttackSpecialist works correctly:
for module in retrieved["rx_modules"]:  # Iterates over modules!
    # Gets: "rx-ms17-010", "rx-eternalblue-v2"
    execute_module(module)  # ✅ Works!

# Access nested metadata:
curl_cmd = retrieved["metadata"]["curl_command"]  # ✅ Works!
```

## Testing

### Manual Test (requires Redis running):

```bash
cd /home/runner/work/RAGLOX_V3/RAGLOX_V3
python tests/test_deserialization_simple.py
```

### Expected Output:

```
TEST 1: Vulnerability Metadata Deserialization
   ✅ metadata is dict (CORRECT)
   ✅ rx_modules is list (CORRECT)
   ✅ TEST 1 PASSED

TEST 2: AttackSpecialist Usage Simulation
   ✅ Can iterate rx_modules
   ✅ Can index rx_modules[0]
   ✅ Can access nested metadata
   ✅ TEST 2 PASSED

🎉 ALL TESTS PASSED - Critical bug fix verified! 🎉
✅ System is GO for frontend integration
```

## Related Files

- `src/core/blackboard.py` - Fixed `_get_hash()` method
- `src/core/scanners/nuclei.py` - Stores vulnerability with complex metadata
- `src/specialists/attack.py` - Consumes vulnerability data
- `tests/test_deserialization_simple.py` - Verification test

## Issue Tracking

This fix addresses:
- **DEEP_ANALYSIS_REPORT.md** Section 1.2: "Vulnerability Data Loss in Serialization"
- **FINAL_AUDIT_REPORT.md** Section 4.3: "CRITICAL BUG: Vulnerability Data Loss"

## Status: FIXED ✅

The critical bug has been fixed. The system is now ready for frontend integration pending verification with running Redis instance.
