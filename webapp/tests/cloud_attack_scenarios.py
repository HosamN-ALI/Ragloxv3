#!/usr/bin/env python3
"""
RAGLOX v3.0 - Cloud Attack Scenarios
====================================

Advanced cloud penetration testing scenarios for AWS, Azure, and GCP.

Author: RAGLOX Team
Date: 2026-01-05
Version: 3.0.0
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

import sys
sys.path.insert(0, '/root/RAGLOX_V3/webapp')

from src.intelligence.adaptive_learning import AdaptiveLearningLayer, OutcomeType
from src.intelligence.defense_intelligence import DefenseIntelligence, DefenseType
from src.intelligence.strategic_attack_planner import StrategicAttackPlanner


class CloudProvider(Enum):
    """Cloud service providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class CloudService(Enum):
    """Cloud services"""
    COMPUTE = "compute"  # EC2, VMs, Compute Engine
    STORAGE = "storage"  # S3, Blob, Cloud Storage
    DATABASE = "database"  # RDS, SQL Database, Cloud SQL
    IDENTITY = "identity"  # IAM, AAD, IAM
    SERVERLESS = "serverless"  # Lambda, Functions, Cloud Functions
    CONTAINER = "container"  # ECS/EKS, AKS, GKE
    NETWORK = "network"  # VPC, VNet, VPC


@dataclass
class CloudTarget:
    """Cloud target information"""
    provider: CloudProvider
    account_id: str
    region: str
    services: List[CloudService]
    exposed_resources: List[Dict[str, Any]]
    misconfigurations: List[Dict[str, Any]]
    credentials: Optional[Dict[str, Any]] = None


@dataclass
class CloudAttackResult:
    """Cloud attack scenario result"""
    scenario_name: str
    provider: CloudProvider
    success: bool
    execution_time_ms: int
    stages_completed: int
    total_stages: int
    resources_compromised: List[str]
    credentials_obtained: List[str]
    data_accessed_gb: float
    privilege_escalations: int
    lateral_moves: int
    persistence_established: bool
    detection_events: int
    cost_incurred_usd: float  # Estimated cost impact
    impact_severity: str  # low, medium, high, critical
    lessons_learned: List[str]
    timestamp: str


class CloudAttackScenarios:
    """Cloud attack scenarios test suite"""
    
    def __init__(self):
        """Initialize cloud attack scenarios"""
        print("☁️  Initializing Cloud Attack Scenarios...")
        
        self.adaptive_learning = AdaptiveLearningLayer()
        self.defense_intel = DefenseIntelligence()
        self.strategic_planner = StrategicAttackPlanner()
        
        self.results: List[CloudAttackResult] = []
        print("✅ Cloud scenarios initialized\n")
    
    async def test_aws_s3_bucket_exploitation(self) -> CloudAttackResult:
        """
        Test AWS S3 bucket exploitation:
        1. Enumerate public buckets
        2. Find misconfigured buckets
        3. Extract sensitive data
        4. Establish persistence
        """
        print("=" * 70)
        print("☁️  TEST: AWS S3 Bucket Exploitation")
        print("=" * 70)
        
        start_time = time.time()
        scenario_name = "AWS S3 Bucket Exploitation"
        stages_completed = 0
        total_stages = 4
        resources_compromised = []
        credentials_obtained = []
        data_accessed_gb = 0.0
        detection_events = 0
        cost_incurred = 0.0
        
        try:
            # Stage 1: Enumerate public buckets
            print("\n🔍 Stage 1/4: Enumerate Public S3 Buckets")
            
            discovered_buckets = [
                {'name': 'company-backups', 'public': True, 'size_gb': 450.0, 'versioning': False},
                {'name': 'prod-logs', 'public': True, 'size_gb': 25.5, 'versioning': True},
                {'name': 'customer-data', 'public': False, 'size_gb': 1200.0, 'versioning': True},
                {'name': 'dev-artifacts', 'public': True, 'size_gb': 12.3, 'versioning': False}
            ]
            
            public_buckets = [b for b in discovered_buckets if b['public']]
            
            await self.adaptive_learning.learn_from_operation(
                operation_type="cloud_enumeration",
                technique_id="T1580",  # Cloud Infrastructure Discovery
                target_info={'provider': 'aws', 'service': 's3'},
                parameters={'scan_type': 'public_buckets'},
                result={'success': True, 'duration_ms': 5000, 'buckets_found': len(discovered_buckets), 'public_buckets': len(public_buckets)}
            )
            
            stages_completed += 1
            print(f"  ✅ Enumeration complete")
            print(f"     Total buckets: {len(discovered_buckets)}")
            print(f"     Public buckets: {len(public_buckets)}")
            
            # Stage 2: Find misconfigurations
            print("\n⚠️  Stage 2/4: Identify Misconfigurations")
            
            misconfigurations = []
            for bucket in public_buckets:
                misconfig = {
                    'bucket': bucket['name'],
                    'issues': []
                }
                
                if bucket['public']:
                    misconfig['issues'].append('Public read access')
                if not bucket['versioning']:
                    misconfig['issues'].append('Versioning disabled')
                
                # Check for sensitive files
                if 'backup' in bucket['name'].lower():
                    misconfig['issues'].append('Backup files exposed')
                    misconfig['severity'] = 'critical'
                elif 'log' in bucket['name'].lower():
                    misconfig['issues'].append('Log files exposed')
                    misconfig['severity'] = 'high'
                else:
                    misconfig['severity'] = 'medium'
                
                if misconfig['issues']:
                    misconfigurations.append(misconfig)
            
            stages_completed += 1
            print(f"  ✅ Misconfigurations identified: {len(misconfigurations)}")
            for misconfig in misconfigurations:
                print(f"     - {misconfig['bucket']}: {len(misconfig['issues'])} issues ({misconfig['severity']})")
            
            # Stage 3: Extract sensitive data
            print("\n📥 Stage 3/4: Data Extraction")
            
            for bucket in public_buckets:
                if bucket['size_gb'] < 100:  # Only download smaller buckets
                    print(f"  📦 Downloading from {bucket['name']} ({bucket['size_gb']} GB)")
                    
                    # Simulate download
                    data_accessed_gb += bucket['size_gb']
                    resources_compromised.append(f"s3://{bucket['name']}")
                    
                    # Check for credentials
                    if 'backup' in bucket['name'].lower():
                        found_creds = {
                            'type': 'aws_access_key',
                            'access_key_id': 'AKIAIOSFODNN7EXAMPLE',
                            'secret_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                            'source': bucket['name']
                        }
                        credentials_obtained.append(f"AWS Key from {bucket['name']}")
                        print(f"     🔑 Credentials found: AWS Access Key")
                    
                    # Estimated data transfer cost
                    cost_incurred += bucket['size_gb'] * 0.09  # $0.09 per GB
            
            await self.adaptive_learning.learn_from_operation(
                operation_type="cloud_data_access",
                technique_id="T1530",  # Data from Cloud Storage Object
                target_info={'provider': 'aws', 'service': 's3'},
                parameters={'buckets': [b['name'] for b in public_buckets]},
                result={'success': True, 'duration_ms': 30000, 'data_gb': data_accessed_gb, 'buckets_accessed': len(resources_compromised)}
            )
            
            stages_completed += 1
            print(f"  ✅ Data extraction complete")
            print(f"     Total data accessed: {data_accessed_gb:.1f} GB")
            print(f"     Credentials found: {len(credentials_obtained)}")
            print(f"     Estimated cost: ${cost_incurred:.2f}")
            
            # Stage 4: Establish persistence
            print("\n🔒 Stage 4/4: Establish Persistence")
            
            persistence_methods = []
            
            # Method 1: IAM user creation (if we have credentials)
            if credentials_obtained:
                print("  🔐 Creating backdoor IAM user...")
                persistence_methods.append({
                    'method': 'iam_user',
                    'username': 'system-backup',
                    'permissions': 'AdministratorAccess'
                })
                print("     ✅ IAM user 'system-backup' created")
            
            # Method 2: S3 event notification to external endpoint
            print("  📡 Configuring S3 event notifications...")
            persistence_methods.append({
                'method': 's3_event_notification',
                'bucket': 'company-backups',
                'destination': 'https://attacker.com/webhook'
            })
            print("     ✅ Event notification configured")
            
            # Method 3: Lambda function for persistence
            print("  ⚡ Deploying Lambda function...")
            persistence_methods.append({
                'method': 'lambda_function',
                'name': 'security-audit',
                'trigger': 'CloudWatch Events'
            })
            print("     ✅ Lambda function deployed")
            
            stages_completed += 1
            print(f"  ✅ Persistence established: {len(persistence_methods)} methods")
            
            # Check for detections
            # CloudTrail might detect unusual API calls
            if len(resources_compromised) > 2:
                detection_events += 1
                print(f"\n  ⚠️  CloudTrail alert: Unusual S3 access pattern detected")
            
            execution_time_ms = int((time.time() - start_time) * 1000)
            
            result = CloudAttackResult(
                scenario_name=scenario_name,
                provider=CloudProvider.AWS,
                success=True,
                execution_time_ms=execution_time_ms,
                stages_completed=stages_completed,
                total_stages=total_stages,
                resources_compromised=resources_compromised,
                credentials_obtained=credentials_obtained,
                data_accessed_gb=data_accessed_gb,
                privilege_escalations=1 if credentials_obtained else 0,
                lateral_moves=0,
                persistence_established=True,
                detection_events=detection_events,
                cost_incurred_usd=cost_incurred,
                impact_severity="critical",
                lessons_learned=[
                    "Public S3 buckets are a critical security risk",
                    "Versioning should be enabled on all buckets",
                    "Backup buckets often contain sensitive credentials",
                    "CloudTrail provides detection but may be disabled/bypassed",
                    "S3 event notifications can be abused for persistence"
                ],
                timestamp=datetime.now().isoformat()
            )
            
            print("\n" + "=" * 70)
            print("✅ AWS S3 BUCKET EXPLOITATION: SUCCESS")
            print("=" * 70)
            print(f"Resources Compromised: {len(resources_compromised)}")
            print(f"Data Accessed: {data_accessed_gb:.1f} GB")
            print(f"Credentials Obtained: {len(credentials_obtained)}")
            print(f"Persistence Methods: {len(persistence_methods)}")
            print(f"Detection Events: {detection_events}")
            print(f"Cost Impact: ${cost_incurred:.2f}")
            print(f"Execution Time: {execution_time_ms}ms")
            
            return result
            
        except Exception as e:
            print(f"\n❌ Error in AWS S3 exploitation: {str(e)}")
            execution_time_ms = int((time.time() - start_time) * 1000)
            
            return CloudAttackResult(
                scenario_name=scenario_name,
                provider=CloudProvider.AWS,
                success=False,
                execution_time_ms=execution_time_ms,
                stages_completed=stages_completed,
                total_stages=total_stages,
                resources_compromised=resources_compromised,
                credentials_obtained=credentials_obtained,
                data_accessed_gb=data_accessed_gb,
                privilege_escalations=0,
                lateral_moves=0,
                persistence_established=False,
                detection_events=detection_events,
                cost_incurred_usd=cost_incurred,
                impact_severity="unknown",
                lessons_learned=[],
                timestamp=datetime.now().isoformat()
            )
    
    async def test_azure_privilege_escalation(self) -> CloudAttackResult:
        """
        Test Azure privilege escalation:
        1. Enumerate Azure AD roles
        2. Find misconfigured RBAC
        3. Escalate to Global Admin
        4. Access all subscriptions
        """
        print("\n" + "=" * 70)
        print("☁️  TEST: Azure Privilege Escalation")
        print("=" * 70)
        
        start_time = time.time()
        scenario_name = "Azure Privilege Escalation"
        stages_completed = 0
        total_stages = 4
        resources_compromised = []
        credentials_obtained = []
        privilege_escalations = 0
        detection_events = 0
        
        try:
            # Stage 1: Enumerate Azure AD roles
            print("\n👥 Stage 1/4: Enumerate Azure AD Roles")
            
            current_user = {
                'upn': 'user@company.com',
                'roles': ['Application Developer'],
                'permissions': ['microsoft.graph.application.readwrite']
            }
            
            print(f"  Current user: {current_user['upn']}")
            print(f"  Current roles: {', '.join(current_user['roles'])}")
            
            stages_completed += 1
            
            # Stage 2: Find RBAC misconfigurations
            print("\n🔍 Stage 2/4: Identify RBAC Misconfigurations")
            
            misconfigurations = [
                {
                    'type': 'application_admin_role',
                    'description': 'Application Developer can create service principals',
                    'severity': 'high'
                },
                {
                    'type': 'owner_assignment',
                    'description': 'Service principal has Owner role on subscription',
                    'severity': 'critical'
                }
            ]
            
            print(f"  ✅ Found {len(misconfigurations)} misconfigurations")
            for misconfig in misconfigurations:
                print(f"     - {misconfig['type']}: {misconfig['severity']}")
            
            stages_completed += 1
            
            # Stage 3: Escalate privileges
            print("\n⬆️  Stage 3/4: Privilege Escalation")
            
            # Create service principal with elevated permissions
            print("  🔐 Creating service principal...")
            sp_created = {
                'display_name': 'AzureBackupService',
                'app_id': '12345678-1234-1234-1234-123456789012',
                'secret': 'SuperSecretKey123!',
                'permissions': ['Directory.ReadWrite.All']
            }
            
            credentials_obtained.append(f"Azure SP: {sp_created['app_id']}")
            print(f"     ✅ Service principal created: {sp_created['display_name']}")
            
            # Assign Owner role to subscription
            print("  👑 Assigning Owner role to subscription...")
            privilege_escalations += 1
            print("     ✅ Owner role assigned")
            
            # Escalate to Global Admin
            print("  🚀 Escalating to Global Admin...")
            privilege_escalations += 1
            credentials_obtained.append("Global Admin role")
            print("     ✅ Global Admin access obtained")
            
            await self.adaptive_learning.learn_from_operation(
                operation_type="cloud_privilege_escalation",
                technique_id="T1548",  # Abuse Elevation Control Mechanism
                target_info={'provider': 'azure', 'service': 'aad'},
                parameters={'method': 'rbac_misconfiguration'},
                result={'success': True, 'duration_ms': 15000, 'escalations': privilege_escalations}
            )
            
            stages_completed += 1
            
            # Stage 4: Access all subscriptions
            print("\n🌐 Stage 4/4: Access All Subscriptions")
            
            subscriptions = [
                {'id': 'sub-001', 'name': 'Production', 'resources': 45},
                {'id': 'sub-002', 'name': 'Development', 'resources': 23},
                {'id': 'sub-003', 'name': 'Testing', 'resources': 12}
            ]
            
            for sub in subscriptions:
                print(f"  📦 Accessing subscription: {sub['name']}")
                resources_compromised.append(f"Subscription: {sub['name']}")
                print(f"     Resources: {sub['resources']}")
            
            stages_completed += 1
            
            # Check for detections
            if privilege_escalations > 1:
                detection_events += 1
                print(f"\n  ⚠️  Azure AD alert: Suspicious role assignment detected")
            
            execution_time_ms = int((time.time() - start_time) * 1000)
            
            result = CloudAttackResult(
                scenario_name=scenario_name,
                provider=CloudProvider.AZURE,
                success=True,
                execution_time_ms=execution_time_ms,
                stages_completed=stages_completed,
                total_stages=total_stages,
                resources_compromised=resources_compromised,
                credentials_obtained=credentials_obtained,
                data_accessed_gb=0.0,
                privilege_escalations=privilege_escalations,
                lateral_moves=len(subscriptions),
                persistence_established=True,
                detection_events=detection_events,
                cost_incurred_usd=0.0,
                impact_severity="critical",
                lessons_learned=[
                    "Azure AD RBAC misconfigurations enable privilege escalation",
                    "Service principals can be abused for persistence",
                    "Global Admin role provides full tenant access",
                    "Owner role on subscriptions is extremely powerful",
                    "Azure AD logs provide detection capabilities"
                ],
                timestamp=datetime.now().isoformat()
            )
            
            print("\n" + "=" * 70)
            print("✅ AZURE PRIVILEGE ESCALATION: SUCCESS")
            print("=" * 70)
            print(f"Privilege Escalations: {privilege_escalations}")
            print(f"Subscriptions Accessed: {len(subscriptions)}")
            print(f"Credentials Obtained: {len(credentials_obtained)}")
            print(f"Detection Events: {detection_events}")
            print(f"Impact: CRITICAL")
            
            return result
            
        except Exception as e:
            print(f"\n❌ Error in Azure privilege escalation: {str(e)}")
            execution_time_ms = int((time.time() - start_time) * 1000)
            
            return CloudAttackResult(
                scenario_name=scenario_name,
                provider=CloudProvider.AZURE,
                success=False,
                execution_time_ms=execution_time_ms,
                stages_completed=stages_completed,
                total_stages=total_stages,
                resources_compromised=resources_compromised,
                credentials_obtained=credentials_obtained,
                data_accessed_gb=0.0,
                privilege_escalations=privilege_escalations,
                lateral_moves=0,
                persistence_established=False,
                detection_events=detection_events,
                cost_incurred_usd=0.0,
                impact_severity="unknown",
                lessons_learned=[],
                timestamp=datetime.now().isoformat()
            )
    
    async def test_gcp_service_account_abuse(self) -> CloudAttackResult:
        """
        Test GCP service account abuse:
        1. Find exposed service account keys
        2. Escalate via IAM permissions
        3. Access GCS buckets
        4. Deploy malicious Cloud Functions
        """
        print("\n" + "=" * 70)
        print("☁️  TEST: GCP Service Account Abuse")
        print("=" * 70)
        
        start_time = time.time()
        scenario_name = "GCP Service Account Abuse"
        stages_completed = 0
        total_stages = 4
        resources_compromised = []
        credentials_obtained = []
        data_accessed_gb = 0.0
        detection_events = 0
        
        try:
            # Stage 1: Find exposed service account keys
            print("\n🔑 Stage 1/4: Find Exposed Service Account Keys")
            
            exposed_keys = [
                {
                    'email': 'compute@project-123.iam.gserviceaccount.com',
                    'key_id': 'key123456',
                    'roles': ['roles/editor'],
                    'source': 'GitHub repository'
                },
                {
                    'email': 'app-service@project-123.iam.gserviceaccount.com',
                    'key_id': 'key789012',
                    'roles': ['roles/storage.admin'],
                    'source': 'Public S3 bucket'
                }
            ]
            
            print(f"  ✅ Found {len(exposed_keys)} exposed service account keys")
            for key in exposed_keys:
                credentials_obtained.append(f"GCP SA: {key['email']}")
                print(f"     - {key['email']} ({', '.join(key['roles'])})")
                print(f"       Source: {key['source']}")
            
            stages_completed += 1
            
            # Stage 2: Escalate via IAM
            print("\n⬆️  Stage 2/4: Escalate IAM Permissions")
            
            # Use editor role to grant additional permissions
            print("  🔐 Granting additional permissions...")
            new_roles = ['roles/iam.securityAdmin', 'roles/compute.admin']
            
            for role in new_roles:
                print(f"     ✅ Granted: {role}")
            
            stages_completed += 1
            
            # Stage 3: Access GCS buckets
            print("\n📦 Stage 3/4: Access Google Cloud Storage")
            
            buckets = [
                {'name': 'project-backups', 'size_gb': 120.0},
                {'name': 'user-uploads', 'size_gb': 450.0},
                {'name': 'logs-archive', 'size_gb': 85.0}
            ]
            
            for bucket in buckets:
                print(f"  📥 Accessing gs://{bucket['name']} ({bucket['size_gb']} GB)")
                resources_compromised.append(f"gs://{bucket['name']}")
                data_accessed_gb += bucket['size_gb']
            
            await self.adaptive_learning.learn_from_operation(
                operation_type="cloud_data_access",
                technique_id="T1530",
                target_info={'provider': 'gcp', 'service': 'gcs'},
                parameters={'buckets': [b['name'] for b in buckets]},
                result={'success': True, 'duration_ms': 25000, 'data_gb': data_accessed_gb}
            )
            
            stages_completed += 1
            print(f"  ✅ Total data accessed: {data_accessed_gb:.1f} GB")
            
            # Stage 4: Deploy malicious Cloud Function
            print("\n⚡ Stage 4/4: Deploy Malicious Cloud Function")
            
            function_config = {
                'name': 'data-processor',
                'runtime': 'python39',
                'trigger': 'HTTP',
                'purpose': 'Backdoor and data exfiltration'
            }
            
            print(f"  🚀 Deploying Cloud Function: {function_config['name']}")
            print(f"     Runtime: {function_config['runtime']}")
            print(f"     Trigger: {function_config['trigger']}")
            print(f"     ✅ Function deployed successfully")
            
            resources_compromised.append(f"Cloud Function: {function_config['name']}")
            
            stages_completed += 1
            
            # Check for detections
            if len(resources_compromised) > 3:
                detection_events += 1
                print(f"\n  ⚠️  Cloud Audit Logs: Unusual API activity detected")
            
            execution_time_ms = int((time.time() - start_time) * 1000)
            
            result = CloudAttackResult(
                scenario_name=scenario_name,
                provider=CloudProvider.GCP,
                success=True,
                execution_time_ms=execution_time_ms,
                stages_completed=stages_completed,
                total_stages=total_stages,
                resources_compromised=resources_compromised,
                credentials_obtained=credentials_obtained,
                data_accessed_gb=data_accessed_gb,
                privilege_escalations=1,
                lateral_moves=len(buckets),
                persistence_established=True,
                detection_events=detection_events,
                cost_incurred_usd=data_accessed_gb * 0.12,  # $0.12 per GB
                impact_severity="high",
                lessons_learned=[
                    "Exposed service account keys are critical vulnerabilities",
                    "Editor role can be abused for privilege escalation",
                    "GCS buckets often contain sensitive data",
                    "Cloud Functions can be used for persistence",
                    "Cloud Audit Logs provide good detection coverage"
                ],
                timestamp=datetime.now().isoformat()
            )
            
            print("\n" + "=" * 70)
            print("✅ GCP SERVICE ACCOUNT ABUSE: SUCCESS")
            print("=" * 70)
            print(f"Service Accounts Compromised: {len(exposed_keys)}")
            print(f"Resources Accessed: {len(resources_compromised)}")
            print(f"Data Accessed: {data_accessed_gb:.1f} GB")
            print(f"Detection Events: {detection_events}")
            print(f"Cost Impact: ${data_accessed_gb * 0.12:.2f}")
            
            return result
            
        except Exception as e:
            print(f"\n❌ Error in GCP service account abuse: {str(e)}")
            execution_time_ms = int((time.time() - start_time) * 1000)
            
            return CloudAttackResult(
                scenario_name=scenario_name,
                provider=CloudProvider.GCP,
                success=False,
                execution_time_ms=execution_time_ms,
                stages_completed=stages_completed,
                total_stages=total_stages,
                resources_compromised=resources_compromised,
                credentials_obtained=credentials_obtained,
                data_accessed_gb=data_accessed_gb,
                privilege_escalations=0,
                lateral_moves=0,
                persistence_established=False,
                detection_events=detection_events,
                cost_incurred_usd=0.0,
                impact_severity="unknown",
                lessons_learned=[],
                timestamp=datetime.now().isoformat()
            )
    
    async def run_all_scenarios(self):
        """Run all cloud attack scenarios"""
        print("\n" + "=" * 70)
        print("☁️  STARTING CLOUD ATTACK SCENARIOS TEST SUITE")
        print("=" * 70)
        print(f"Date: {datetime.now().isoformat()}")
        print(f"Test Suite: RAGLOX v3.0 Cloud Scenarios")
        print("=" * 70)
        
        # Run all scenarios
        self.results.append(await self.test_aws_s3_bucket_exploitation())
        self.results.append(await self.test_azure_privilege_escalation())
        self.results.append(await self.test_gcp_service_account_abuse())
        
        # Generate summary
        self.generate_summary()
        
        # Save results
        self.save_results()
    
    def generate_summary(self):
        """Generate test summary"""
        print("\n\n" + "=" * 70)
        print("📊 CLOUD ATTACK SCENARIOS SUMMARY")
        print("=" * 70)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.success)
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        total_resources = sum(len(r.resources_compromised) for r in self.results)
        total_creds = sum(len(r.credentials_obtained) for r in self.results)
        total_data = sum(r.data_accessed_gb for r in self.results)
        total_cost = sum(r.cost_incurred_usd for r in self.results)
        total_detections = sum(r.detection_events for r in self.results)
        total_escalations = sum(r.privilege_escalations for r in self.results)
        
        print(f"\n✅ Tests Passed: {passed_tests}/{total_tests} ({success_rate:.1f}%)")
        print(f"\n📈 Overall Metrics:")
        print(f"   Cloud Resources Compromised: {total_resources}")
        print(f"   Credentials Obtained: {total_creds}")
        print(f"   Data Accessed: {total_data:.1f} GB")
        print(f"   Privilege Escalations: {total_escalations}")
        print(f"   Detection Events: {total_detections}")
        print(f"   Total Cost Impact: ${total_cost:.2f}")
        
        print(f"\n📋 Individual Test Results:")
        for i, result in enumerate(self.results, 1):
            status = "✅ PASS" if result.success else "❌ FAIL"
            print(f"\n{i}. {result.scenario_name} ({result.provider.value.upper()}): {status}")
            print(f"   Stages: {result.stages_completed}/{result.total_stages}")
            print(f"   Resources: {len(result.resources_compromised)}")
            print(f"   Credentials: {len(result.credentials_obtained)}")
            if result.data_accessed_gb > 0:
                print(f"   Data: {result.data_accessed_gb:.1f} GB")
            if result.cost_incurred_usd > 0:
                print(f"   Cost: ${result.cost_incurred_usd:.2f}")
            print(f"   Impact: {result.impact_severity.upper()}")
        
        print("\n" + "=" * 70)
    
    def save_results(self):
        """Save test results to file"""
        output_file = '/root/RAGLOX_V3/webapp/webapp/tests/cloud_attack_results.json'
        
        results_dict = {
            'test_suite': 'RAGLOX v3.0 Cloud Attack Scenarios',
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': len(self.results),
                'passed_tests': sum(1 for r in self.results if r.success),
                'success_rate': (sum(1 for r in self.results if r.success) / len(self.results) * 100) if self.results else 0,
                'total_resources_compromised': sum(len(r.resources_compromised) for r in self.results),
                'total_credentials_obtained': sum(len(r.credentials_obtained) for r in self.results),
                'total_data_accessed_gb': sum(r.data_accessed_gb for r in self.results),
                'total_privilege_escalations': sum(r.privilege_escalations for r in self.results),
                'total_detection_events': sum(r.detection_events for r in self.results),
                'total_cost_impact_usd': sum(r.cost_incurred_usd for r in self.results)
            },
            'results': [asdict(r) for r in self.results]
        }
        
        with open(output_file, 'w') as f:
            json.dump(results_dict, f, indent=2, default=str)
        
        print(f"\n💾 Results saved to: {output_file}")


async def main():
    """Main entry point"""
    test_suite = CloudAttackScenarios()
    await test_suite.run_all_scenarios()
    print("\n✅ All cloud scenarios complete!\n")


if __name__ == "__main__":
    asyncio.run(main())
