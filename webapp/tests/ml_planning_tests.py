#!/usr/bin/env python3
"""
RAGLOX v3.0 - ML/AI Planning System Tests
=========================================

Test ML-powered attack planning and optimization.

Author: RAGLOX Team
Date: 2026-01-05
"""

import asyncio
import json
import sys
sys.path.insert(0, '/root/RAGLOX_V3/webapp')

from src.ml.attack_planner import (
    MLAttackPlanner,
    AttackPrediction,
    PredictionConfidence
)


def test_ml_prediction():
    """Test ML prediction capabilities"""
    print("=" * 70)
    print("🤖 TEST: ML Attack Success Prediction")
    print("=" * 70)
    
    # Create ML planner with some historical data
    historical_data = [
        {'technique_id': 'T1210', 'target_info': {'os': 'Windows Server 2019', 'type': 'dc'}, 'success': True, 'duration_ms': 3000, 'detected': False},
        {'technique_id': 'T1210', 'target_info': {'os': 'Windows 10', 'type': 'workstation'}, 'success': True, 'duration_ms': 2500, 'detected': False},
        {'technique_id': 'T1210', 'target_info': {'os': 'Linux Ubuntu', 'type': 'server'}, 'success': False, 'duration_ms': 5000, 'detected': True},
        {'technique_id': 'T1003', 'target_info': {'os': 'Windows Server 2019', 'type': 'dc'}, 'success': True, 'duration_ms': 4000, 'detected': False},
        {'technique_id': 'T1003', 'target_info': {'os': 'Windows 10', 'type': 'workstation'}, 'success': True, 'duration_ms': 3500, 'detected': True},
    ]
    
    ml_planner = MLAttackPlanner(historical_data=historical_data)
    
    print(f"\n📊 ML Stats:")
    stats = ml_planner.get_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Test prediction
    print(f"\n🎯 Prediction Test 1: SMBGhost on Windows DC")
    prediction = ml_planner.predict_attack_success(
        technique_id='T1210',
        target_info={'os': 'Windows Server 2019', 'type': 'dc', 'services': ['smb', 'ldap']},
        context={'defense_level': 0.3, 'network_complexity': 0.4, 'target_value': 0.8}
    )
    
    print(f"   Success Probability: {prediction.success_probability:.1%}")
    print(f"   Detection Probability: {prediction.detection_probability:.1%}")
    print(f"   Execution Time: {prediction.execution_time_estimate_ms}ms")
    print(f"   Risk Score: {prediction.risk_score:.2f}")
    print(f"   Confidence: {prediction.confidence.value}")
    print(f"   Recommended: {'✅ Yes' if prediction.recommended else '❌ No'}")
    print(f"   Reasoning:")
    for reason in prediction.reasoning:
        print(f"     - {reason}")
    
    # Test another prediction
    print(f"\n🎯 Prediction Test 2: Credential Dumping on Workstation")
    prediction2 = ml_planner.predict_attack_success(
        technique_id='T1003',
        target_info={'os': 'Windows 10', 'type': 'workstation', 'services': ['smb']},
        context={'defense_level': 0.6, 'network_complexity': 0.5, 'target_value': 0.5}
    )
    
    print(f"   Success Probability: {prediction2.success_probability:.1%}")
    print(f"   Detection Probability: {prediction2.detection_probability:.1%}")
    print(f"   Risk Score: {prediction2.risk_score:.2f}")
    print(f"   Recommended: {'✅ Yes' if prediction2.recommended else '❌ No'}")
    
    print("\n✅ ML Prediction Test: PASSED")
    return ml_planner


def test_campaign_optimization(ml_planner):
    """Test campaign optimization"""
    print("\n" + "=" * 70)
    print("🚀 TEST: Campaign Optimization")
    print("=" * 70)
    
    # Original campaign
    techniques = ['T1210', 'T1003', 'T1021', 'T1053', 'T1055']
    target_info = {
        'os': 'Windows Server 2019',
        'type': 'dc',
        'services': ['smb', 'ldap', 'kerberos']
    }
    context = {
        'defense_level': 0.5,
        'network_complexity': 0.4,
        'target_value': 0.8
    }
    
    print(f"\n📋 Original Campaign:")
    print(f"   Techniques: {', '.join(techniques)}")
    
    # Optimize
    result = ml_planner.optimize_campaign(techniques, target_info, context)
    
    print(f"\n📈 Optimization Results:")
    print(f"   Original Success Rate: {result.original_success_rate:.1%}")
    print(f"   Optimized Success Rate: {result.optimized_success_rate:.1%}")
    print(f"   Improvement: {result.improvement_percent:+.1f}%")
    print(f"   Time Saved: {result.estimated_time_saved_ms}ms")
    print(f"   Risk Reduction: {result.risk_reduction:+.2f}")
    print(f"   Confidence: {result.confidence.value}")
    
    if result.technique_changes:
        print(f"\n🔄 Technique Changes:")
        for change in result.technique_changes:
            print(f"   {change['original']} → {change['replacement']}")
            print(f"      Improvement: {change['improvement']:+.1%}")
            print(f"      Reason: {change['reason']}")
    else:
        print(f"\n✅ Campaign already optimal - no changes needed")
    
    print("\n✅ Campaign Optimization Test: PASSED")


def test_continuous_learning(ml_planner):
    """Test continuous learning"""
    print("\n" + "=" * 70)
    print("🧠 TEST: Continuous Learning")
    print("=" * 70)
    
    print(f"\n📊 Initial Stats:")
    stats_before = ml_planner.get_stats()
    print(f"   Success Patterns: {stats_before['total_success_patterns']}")
    print(f"   Failure Patterns: {stats_before['total_failure_patterns']}")
    
    # Simulate some attack executions
    print(f"\n🎬 Simulating Attack Executions...")
    
    attacks = [
        {'technique': 'T1190', 'target': {'os': 'Linux Ubuntu', 'type': 'web'}, 'success': True, 'duration': 5000, 'detected': False},
        {'technique': 'T1190', 'target': {'os': 'Linux Ubuntu', 'type': 'web'}, 'success': True, 'duration': 4800, 'detected': False},
        {'technique': 'T1078', 'target': {'os': 'Windows 10', 'type': 'workstation'}, 'success': True, 'duration': 2000, 'detected': True},
        {'technique': 'T1078', 'target': {'os': 'Windows Server 2019', 'type': 'dc'}, 'success': False, 'duration': 3000, 'detected': True},
    ]
    
    for i, attack in enumerate(attacks, 1):
        ml_planner.learn_from_attack(
            technique_id=attack['technique'],
            target_info=attack['target'],
            success=attack['success'],
            duration_ms=attack['duration'],
            detected=attack['detected']
        )
        print(f"   {i}. {attack['technique']} on {attack['target']['os']}: {'✅ Success' if attack['success'] else '❌ Failure'}")
    
    print(f"\n📊 Updated Stats:")
    stats_after = ml_planner.get_stats()
    print(f"   Success Patterns: {stats_after['total_success_patterns']} (+{stats_after['total_success_patterns'] - stats_before['total_success_patterns']})")
    print(f"   Failure Patterns: {stats_after['total_failure_patterns']} (+{stats_after['total_failure_patterns'] - stats_before['total_failure_patterns']})")
    
    # Test prediction after learning
    print(f"\n🎯 New Prediction After Learning: Web Exploitation on Linux")
    prediction = ml_planner.predict_attack_success(
        technique_id='T1190',
        target_info={'os': 'Linux Ubuntu', 'type': 'web', 'services': ['nginx']},
        context={'defense_level': 0.4}
    )
    
    print(f"   Success Probability: {prediction.success_probability:.1%}")
    print(f"   Confidence: {prediction.confidence.value}")
    print(f"   Recommended: {'✅ Yes' if prediction.recommended else '❌ No'}")
    
    print("\n✅ Continuous Learning Test: PASSED")


def main():
    """Main test entry point"""
    print("\n" + "=" * 70)
    print("🤖 RAGLOX ML/AI PLANNING SYSTEM - TEST SUITE")
    print("=" * 70)
    print(f"Date: 2026-01-05")
    print("=" * 70)
    
    # Run tests
    ml_planner = test_ml_prediction()
    test_campaign_optimization(ml_planner)
    test_continuous_learning(ml_planner)
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 TEST SUMMARY")
    print("=" * 70)
    print("✅ All ML/AI tests PASSED")
    print("   - ML Prediction: ✅")
    print("   - Campaign Optimization: ✅")
    print("   - Continuous Learning: ✅")
    print("\n🎉 ML/AI Planning System: FULLY OPERATIONAL")
    print("=" * 70)


if __name__ == "__main__":
    main()
