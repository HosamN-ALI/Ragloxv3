"""
RAGLOX v3.0 - ML/AI Attack Planning System
==========================================

Machine Learning and AI-powered attack planning and success prediction.

Features:
- Attack success rate prediction
- Optimal technique selection
- Pattern-based strategy recommendation
- Risk assessment using ML
- Automated campaign optimization

Author: RAGLOX Team
Date: 2026-01-05
Version: 3.0.0
"""

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
import math

logger = logging.getLogger("raglox.ml.attack_planner")


class PredictionConfidence(Enum):
    """Prediction confidence levels"""
    VERY_LOW = "very_low"    # < 30%
    LOW = "low"              # 30-50%
    MEDIUM = "medium"        # 50-70%
    HIGH = "high"            # 70-90%
    VERY_HIGH = "very_high"  # > 90%


@dataclass
class FeatureVector:
    """Feature vector for ML prediction"""
    target_os: str
    target_services: List[str]
    vulnerability_type: str
    attack_technique: str
    defense_level: float  # 0.0-1.0
    network_complexity: float  # 0.0-1.0
    target_value: float  # 0.0-1.0
    time_of_day: int  # 0-23
    previous_attempts: int
    similar_success_rate: float  # 0.0-1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class AttackPrediction:
    """ML-based attack prediction"""
    technique_id: str
    success_probability: float  # 0.0-1.0
    detection_probability: float  # 0.0-1.0
    execution_time_estimate_ms: int
    confidence: PredictionConfidence
    recommended: bool
    reasoning: List[str]
    alternative_techniques: List[str]
    risk_score: float  # 0.0-1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['confidence'] = self.confidence.value
        return d


@dataclass
class OptimizationResult:
    """Campaign optimization result"""
    original_success_rate: float
    optimized_success_rate: float
    improvement_percent: float
    technique_changes: List[Dict[str, Any]]
    estimated_time_saved_ms: int
    risk_reduction: float
    confidence: PredictionConfidence


class MLAttackPlanner:
    """
    ML/AI-powered attack planning system.
    
    Uses historical data, pattern recognition, and heuristics to:
    - Predict attack success rates
    - Recommend optimal techniques
    - Optimize attack campaigns
    - Assess risks intelligently
    """
    
    def __init__(
        self,
        historical_data: Optional[List[Dict[str, Any]]] = None,
        enable_learning: bool = True
    ):
        """
        Initialize ML attack planner.
        
        Args:
            historical_data: Historical attack data for training
            enable_learning: Enable continuous learning
        """
        self.historical_data = historical_data or []
        self.enable_learning = enable_learning
        
        # Pattern database
        self.success_patterns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.failure_patterns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        # Technique performance tracking
        self.technique_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'attempts': 0,
            'successes': 0,
            'avg_duration_ms': 0,
            'detection_rate': 0.0,
            'last_used': None
        })
        
        # Target-specific learning
        self.target_patterns: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'vulnerabilities': [],
            'successful_techniques': [],
            'failed_techniques': [],
            'defense_level': 0.5
        })
        
        # Load historical data
        if self.historical_data:
            self._train_on_historical_data()
        
        logger.info("MLAttackPlanner initialized with learning enabled" if enable_learning else "MLAttackPlanner initialized in read-only mode")
    
    def _train_on_historical_data(self):
        """Train on historical attack data"""
        for record in self.historical_data:
            self._learn_from_record(record)
        
        logger.info(f"Trained on {len(self.historical_data)} historical records")
    
    def _learn_from_record(self, record: Dict[str, Any]):
        """Learn from a single attack record"""
        technique = record.get('technique_id', 'unknown')
        success = record.get('success', False)
        
        # Update technique stats
        stats = self.technique_stats[technique]
        stats['attempts'] += 1
        if success:
            stats['successes'] += 1
        
        # Update patterns
        if success:
            self.success_patterns[technique].append(record)
        else:
            self.failure_patterns[technique].append(record)
        
        # Update target patterns
        target_info = record.get('target_info', {})
        target_key = f"{target_info.get('os', 'unknown')}_{target_info.get('type', 'unknown')}"
        
        if success:
            self.target_patterns[target_key]['successful_techniques'].append(technique)
        else:
            self.target_patterns[target_key]['failed_techniques'].append(technique)
    
    def predict_attack_success(
        self,
        technique_id: str,
        target_info: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> AttackPrediction:
        """
        Predict success probability for an attack technique.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            target_info: Target information (OS, services, etc.)
            context: Additional context (time, defenses, etc.)
        
        Returns:
            Attack prediction with success probability and recommendations
        """
        context = context or {}
        
        # Extract features
        features = self._extract_features(technique_id, target_info, context)
        
        # Calculate base success probability
        base_prob = self._calculate_base_probability(technique_id, features)
        
        # Apply context modifiers
        modified_prob = self._apply_context_modifiers(base_prob, features, context)
        
        # Calculate detection probability
        detection_prob = self._estimate_detection_probability(technique_id, features)
        
        # Estimate execution time
        exec_time = self._estimate_execution_time(technique_id, features)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(modified_prob, detection_prob)
        
        # Determine confidence
        confidence = self._determine_confidence(technique_id, features)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            technique_id,
            modified_prob,
            detection_prob,
            features
        )
        
        # Find alternatives
        alternatives = self._find_alternative_techniques(
            technique_id,
            target_info,
            modified_prob
        )
        
        # Recommend or not
        recommended = self._should_recommend(
            modified_prob,
            detection_prob,
            risk_score
        )
        
        return AttackPrediction(
            technique_id=technique_id,
            success_probability=modified_prob,
            detection_probability=detection_prob,
            execution_time_estimate_ms=exec_time,
            confidence=confidence,
            recommended=recommended,
            reasoning=reasoning,
            alternative_techniques=alternatives,
            risk_score=risk_score
        )
    
    def _extract_features(
        self,
        technique_id: str,
        target_info: Dict[str, Any],
        context: Dict[str, Any]
    ) -> FeatureVector:
        """Extract features for ML prediction"""
        # Target features
        target_os = target_info.get('os', 'unknown').lower()
        target_services = target_info.get('services', [])
        vuln_type = target_info.get('vulnerability_type', 'unknown')
        
        # Context features
        defense_level = context.get('defense_level', 0.5)
        network_complexity = context.get('network_complexity', 0.5)
        target_value = context.get('target_value', 0.5)
        time_of_day = datetime.now().hour
        
        # Historical features
        target_key = f"{target_os}_{target_info.get('type', 'unknown')}"
        target_pattern = self.target_patterns.get(target_key, {})
        previous_attempts = len(target_pattern.get('failed_techniques', []))
        
        # Calculate similar success rate
        similar_success_rate = self._calculate_similar_success_rate(
            technique_id,
            target_os,
            vuln_type
        )
        
        return FeatureVector(
            target_os=target_os,
            target_services=target_services,
            vulnerability_type=vuln_type,
            attack_technique=technique_id,
            defense_level=defense_level,
            network_complexity=network_complexity,
            target_value=target_value,
            time_of_day=time_of_day,
            previous_attempts=previous_attempts,
            similar_success_rate=similar_success_rate
        )
    
    def _calculate_base_probability(
        self,
        technique_id: str,
        features: FeatureVector
    ) -> float:
        """Calculate base success probability"""
        # Check technique stats
        stats = self.technique_stats.get(technique_id, {})
        attempts = stats.get('attempts', 0)
        successes = stats.get('successes', 0)
        
        if attempts > 0:
            # Use historical success rate
            base_prob = successes / attempts
        else:
            # Use similar technique success rate
            base_prob = features.similar_success_rate
        
        # Ensure valid range
        return max(0.1, min(0.9, base_prob))
    
    def _apply_context_modifiers(
        self,
        base_prob: float,
        features: FeatureVector,
        context: Dict[str, Any]
    ) -> float:
        """Apply context-based modifiers to probability"""
        modified_prob = base_prob
        
        # Defense level modifier (higher defense = lower success)
        defense_modifier = 1.0 - (features.defense_level * 0.3)
        modified_prob *= defense_modifier
        
        # Network complexity modifier
        complexity_modifier = 1.0 - (features.network_complexity * 0.2)
        modified_prob *= complexity_modifier
        
        # Previous attempts modifier (learning from failures)
        if features.previous_attempts > 0:
            # Slightly reduce probability after failures
            attempt_modifier = 1.0 - (features.previous_attempts * 0.05)
            modified_prob *= max(0.5, attempt_modifier)
        
        # Time of day modifier (off-hours = better)
        if features.time_of_day < 6 or features.time_of_day > 22:
            modified_prob *= 1.1  # 10% boost during off-hours
        
        # OS-specific modifiers
        if 'windows' in features.target_os.lower():
            # Windows typically easier to exploit
            modified_prob *= 1.05
        elif 'linux' in features.target_os.lower():
            # Linux typically harder
            modified_prob *= 0.95
        
        # Vulnerability type modifiers
        vuln_modifiers = {
            'rce': 1.2,  # Remote code execution very effective
            'sqli': 1.15,  # SQL injection effective
            'xss': 0.9,  # XSS less effective for infrastructure
            'auth_bypass': 1.1,
            'privesc': 0.95,
            'file_inclusion': 1.0
        }
        
        vuln_type = features.vulnerability_type.lower()
        for key, modifier in vuln_modifiers.items():
            if key in vuln_type:
                modified_prob *= modifier
                break
        
        # Ensure valid range
        return max(0.05, min(0.95, modified_prob))
    
    def _estimate_detection_probability(
        self,
        technique_id: str,
        features: FeatureVector
    ) -> float:
        """Estimate probability of detection"""
        # Base detection rate from stats
        stats = self.technique_stats.get(technique_id, {})
        base_detection = stats.get('detection_rate', 0.3)
        
        # Modify based on defense level
        detection_prob = base_detection + (features.defense_level * 0.4)
        
        # High-value targets have better monitoring
        if features.target_value > 0.7:
            detection_prob *= 1.3
        
        # Complex networks have more monitoring
        detection_prob += features.network_complexity * 0.2
        
        # Off-hours reduce detection (less monitoring)
        if features.time_of_day < 6 or features.time_of_day > 22:
            detection_prob *= 0.7
        
        return max(0.05, min(0.95, detection_prob))
    
    def _estimate_execution_time(
        self,
        technique_id: str,
        features: FeatureVector
    ) -> int:
        """Estimate execution time in milliseconds"""
        # Base time from stats
        stats = self.technique_stats.get(technique_id, {})
        base_time = stats.get('avg_duration_ms', 10000)  # Default 10 seconds
        
        # Adjust for network complexity
        time_estimate = base_time * (1.0 + features.network_complexity)
        
        # Adjust for target services (more services = longer)
        if len(features.target_services) > 5:
            time_estimate *= 1.5
        
        return int(time_estimate)
    
    def _calculate_risk_score(
        self,
        success_prob: float,
        detection_prob: float
    ) -> float:
        """Calculate overall risk score"""
        # Risk is combination of detection probability and inverse of success
        risk = (detection_prob * 0.7) + ((1.0 - success_prob) * 0.3)
        return max(0.0, min(1.0, risk))
    
    def _determine_confidence(
        self,
        technique_id: str,
        features: FeatureVector
    ) -> PredictionConfidence:
        """Determine prediction confidence level"""
        stats = self.technique_stats.get(technique_id, {})
        attempts = stats.get('attempts', 0)
        
        # More historical data = higher confidence
        if attempts > 50:
            return PredictionConfidence.VERY_HIGH
        elif attempts > 20:
            return PredictionConfidence.HIGH
        elif attempts > 5:
            return PredictionConfidence.MEDIUM
        elif attempts > 0:
            return PredictionConfidence.LOW
        else:
            return PredictionConfidence.VERY_LOW
    
    def _generate_reasoning(
        self,
        technique_id: str,
        success_prob: float,
        detection_prob: float,
        features: FeatureVector
    ) -> List[str]:
        """Generate human-readable reasoning for prediction"""
        reasoning = []
        
        # Success probability reasoning
        if success_prob > 0.7:
            reasoning.append(f"High success probability ({success_prob:.1%}) based on historical data")
        elif success_prob < 0.3:
            reasoning.append(f"Low success probability ({success_prob:.1%}) - consider alternatives")
        
        # Detection reasoning
        if detection_prob > 0.7:
            reasoning.append(f"High detection risk ({detection_prob:.1%}) - evasion techniques recommended")
        elif detection_prob < 0.3:
            reasoning.append(f"Low detection risk ({detection_prob:.1%}) - stealthy approach")
        
        # Defense level reasoning
        if features.defense_level > 0.7:
            reasoning.append("Strong defenses detected - complex evasion required")
        elif features.defense_level < 0.3:
            reasoning.append("Weak defenses - straightforward approach viable")
        
        # Time reasoning
        if features.time_of_day < 6 or features.time_of_day > 22:
            reasoning.append("Off-hours timing provides operational advantage")
        
        # Historical reasoning
        if features.previous_attempts > 2:
            reasoning.append(f"Previous attempts ({features.previous_attempts}) suggest hardened target")
        
        return reasoning
    
    def _find_alternative_techniques(
        self,
        technique_id: str,
        target_info: Dict[str, Any],
        current_prob: float
    ) -> List[str]:
        """Find alternative techniques with better success probability"""
        alternatives = []
        
        # Get target pattern
        target_os = target_info.get('os', 'unknown').lower()
        target_key = f"{target_os}_{target_info.get('type', 'unknown')}"
        target_pattern = self.target_patterns.get(target_key, {})
        
        # Find successful techniques for this target type
        successful_techniques = target_pattern.get('successful_techniques', [])
        
        # Return top alternatives
        for tech in successful_techniques[:3]:
            if tech != technique_id:
                alternatives.append(tech)
        
        return alternatives
    
    def _should_recommend(
        self,
        success_prob: float,
        detection_prob: float,
        risk_score: float
    ) -> bool:
        """Determine if technique should be recommended"""
        # Recommend if:
        # - Success probability > 50%
        # - Detection probability < 70%
        # - Risk score < 60%
        
        return (
            success_prob > 0.5 and
            detection_prob < 0.7 and
            risk_score < 0.6
        )
    
    def _calculate_similar_success_rate(
        self,
        technique_id: str,
        target_os: str,
        vuln_type: str
    ) -> float:
        """Calculate success rate for similar attacks"""
        similar_successes = 0
        similar_attempts = 0
        
        # Find similar attacks
        for tech, patterns in self.success_patterns.items():
            for pattern in patterns:
                target_info = pattern.get('target_info', {})
                if target_info.get('os', '').lower() == target_os.lower():
                    similar_successes += 1
        
        for tech, patterns in self.failure_patterns.items():
            for pattern in patterns:
                target_info = pattern.get('target_info', {})
                if target_info.get('os', '').lower() == target_os.lower():
                    similar_attempts += 1
        
        total_attempts = similar_successes + similar_attempts
        if total_attempts > 0:
            return similar_successes / total_attempts
        
        return 0.5  # Default neutral probability
    
    def optimize_campaign(
        self,
        techniques: List[str],
        target_info: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> OptimizationResult:
        """
        Optimize an attack campaign using ML predictions.
        
        Args:
            techniques: List of technique IDs in the campaign
            target_info: Target information
            context: Additional context
        
        Returns:
            Optimization result with improvements
        """
        context = context or {}
        
        # Calculate original success rate
        original_predictions = [
            self.predict_attack_success(tech, target_info, context)
            for tech in techniques
        ]
        
        original_success_rate = sum(p.success_probability for p in original_predictions) / len(original_predictions)
        original_time = sum(p.execution_time_estimate_ms for p in original_predictions)
        original_risk = sum(p.risk_score for p in original_predictions) / len(original_predictions)
        
        # Optimize: replace low-probability techniques with alternatives
        optimized_techniques = []
        technique_changes = []
        
        for i, tech in enumerate(techniques):
            pred = original_predictions[i]
            
            if not pred.recommended and pred.alternative_techniques:
                # Try first alternative
                alt_tech = pred.alternative_techniques[0]
                alt_pred = self.predict_attack_success(alt_tech, target_info, context)
                
                if alt_pred.success_probability > pred.success_probability:
                    optimized_techniques.append(alt_tech)
                    technique_changes.append({
                        'original': tech,
                        'replacement': alt_tech,
                        'improvement': alt_pred.success_probability - pred.success_probability,
                        'reason': f"Better success rate: {alt_pred.success_probability:.1%} vs {pred.success_probability:.1%}"
                    })
                else:
                    optimized_techniques.append(tech)
            else:
                optimized_techniques.append(tech)
        
        # Recalculate with optimized techniques
        optimized_predictions = [
            self.predict_attack_success(tech, target_info, context)
            for tech in optimized_techniques
        ]
        
        optimized_success_rate = sum(p.success_probability for p in optimized_predictions) / len(optimized_predictions)
        optimized_time = sum(p.execution_time_estimate_ms for p in optimized_predictions)
        optimized_risk = sum(p.risk_score for p in optimized_predictions) / len(optimized_predictions)
        
        # Calculate improvements
        improvement_percent = ((optimized_success_rate - original_success_rate) / original_success_rate) * 100
        time_saved = original_time - optimized_time
        risk_reduction = original_risk - optimized_risk
        
        # Determine confidence based on number of changes and historical data
        if len(technique_changes) == 0:
            confidence = PredictionConfidence.VERY_HIGH
        elif len(technique_changes) < len(techniques) // 3:
            confidence = PredictionConfidence.HIGH
        else:
            confidence = PredictionConfidence.MEDIUM
        
        return OptimizationResult(
            original_success_rate=original_success_rate,
            optimized_success_rate=optimized_success_rate,
            improvement_percent=improvement_percent,
            technique_changes=technique_changes,
            estimated_time_saved_ms=time_saved,
            risk_reduction=risk_reduction,
            confidence=confidence
        )
    
    def learn_from_attack(
        self,
        technique_id: str,
        target_info: Dict[str, Any],
        success: bool,
        duration_ms: int,
        detected: bool = False,
        context: Optional[Dict[str, Any]] = None
    ):
        """
        Learn from an attack execution.
        
        Args:
            technique_id: Technique that was used
            target_info: Target information
            success: Whether attack succeeded
            duration_ms: Execution duration
            detected: Whether attack was detected
            context: Additional context
        """
        if not self.enable_learning:
            return
        
        # Create record
        record = {
            'technique_id': technique_id,
            'target_info': target_info,
            'success': success,
            'duration_ms': duration_ms,
            'detected': detected,
            'context': context or {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Learn from record
        self._learn_from_record(record)
        
        # Update technique stats
        stats = self.technique_stats[technique_id]
        
        # Update average duration
        total_duration = stats['avg_duration_ms'] * (stats['attempts'] - 1) + duration_ms
        stats['avg_duration_ms'] = total_duration / stats['attempts']
        
        # Update detection rate
        if detected:
            total_detections = stats['detection_rate'] * (stats['attempts'] - 1) + 1
            stats['detection_rate'] = total_detections / stats['attempts']
        else:
            total_detections = stats['detection_rate'] * (stats['attempts'] - 1)
            stats['detection_rate'] = total_detections / stats['attempts']
        
        stats['last_used'] = datetime.now().isoformat()
        
        logger.info(f"Learned from {technique_id}: success={success}, detected={detected}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ML system statistics"""
        return {
            'total_techniques_tracked': len(self.technique_stats),
            'total_success_patterns': sum(len(patterns) for patterns in self.success_patterns.values()),
            'total_failure_patterns': sum(len(patterns) for patterns in self.failure_patterns.values()),
            'total_target_patterns': len(self.target_patterns),
            'learning_enabled': self.enable_learning
        }


# Global instance
_ml_planner: Optional[MLAttackPlanner] = None


def get_ml_planner() -> MLAttackPlanner:
    """Get or create global ML planner instance"""
    global _ml_planner
    if _ml_planner is None:
        _ml_planner = MLAttackPlanner()
    return _ml_planner


def setup_ml_planner(
    historical_data: Optional[List[Dict[str, Any]]] = None,
    enable_learning: bool = True
) -> MLAttackPlanner:
    """
    Set up global ML planner.
    
    Args:
        historical_data: Historical attack data
        enable_learning: Enable continuous learning
    
    Returns:
        Configured ML planner
    """
    global _ml_planner
    _ml_planner = MLAttackPlanner(
        historical_data=historical_data,
        enable_learning=enable_learning
    )
    return _ml_planner
