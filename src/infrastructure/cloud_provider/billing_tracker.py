"""
RAGLOX v3.0 - Billing Tracker
Tracks VM costs and bandwidth overages.

Author: RAGLOX Team
Version: 3.0.0
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from decimal import Decimal

from .oneprovider_client import OneProviderClient


logger = logging.getLogger("raglox.infrastructure.cloud_provider.billing_tracker")


@dataclass
class VMCost:
    """VM cost details"""
    vm_id: str
    hostname: str
    plan_id: str
    
    # Base costs
    hourly_rate: Decimal
    daily_rate: Decimal
    monthly_rate: Decimal
    
    # Usage costs
    bandwidth_used_gb: float
    bandwidth_limit_gb: float
    bandwidth_overage_gb: float
    bandwidth_overage_cost: Decimal
    
    # Total
    total_cost: Decimal
    
    # Period
    period_start: datetime
    period_end: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vm_id": self.vm_id,
            "hostname": self.hostname,
            "plan_id": self.plan_id,
            "hourly_rate": float(self.hourly_rate),
            "daily_rate": float(self.daily_rate),
            "monthly_rate": float(self.monthly_rate),
            "bandwidth_used_gb": self.bandwidth_used_gb,
            "bandwidth_limit_gb": self.bandwidth_limit_gb,
            "bandwidth_overage_gb": self.bandwidth_overage_gb,
            "bandwidth_overage_cost": float(self.bandwidth_overage_cost),
            "total_cost": float(self.total_cost),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat()
        }


class BillingTracker:
    """
    Billing Tracker for VM cost management
    
    Features:
    - Cost calculation per VM
    - Bandwidth overage tracking
    - Cost projections
    - Budget alerts
    """
    
    # Pricing (example rates - should be loaded from config)
    PLAN_RATES = {
        "8GB-2CORE": {
            "hourly": Decimal("0.05"),
            "monthly": Decimal("35.00")
        },
        "16GB-4CORE": {
            "hourly": Decimal("0.10"),
            "monthly": Decimal("70.00")
        },
        "32GB-8CORE": {
            "hourly": Decimal("0.20"),
            "monthly": Decimal("140.00")
        }
    }
    
    BANDWIDTH_OVERAGE_RATE = Decimal("0.02")  # $0.02 per GB
    
    def __init__(
        self,
        client: OneProviderClient,
        custom_rates: Optional[Dict[str, Dict[str, Decimal]]] = None,
        bandwidth_overage_rate: Optional[Decimal] = None
    ):
        """
        Initialize Billing Tracker
        
        Args:
            client: OneProvider client
            custom_rates: Custom plan rates
            bandwidth_overage_rate: Custom bandwidth overage rate
        """
        self.client = client
        
        # Use custom rates if provided
        if custom_rates:
            self.plan_rates = custom_rates
        else:
            self.plan_rates = self.PLAN_RATES
        
        if bandwidth_overage_rate:
            self.bandwidth_overage_rate = bandwidth_overage_rate
        else:
            self.bandwidth_overage_rate = self.BANDWIDTH_OVERAGE_RATE
    
    async def get_vm_cost(
        self,
        vm_id: str,
        period_start: Optional[datetime] = None,
        period_end: Optional[datetime] = None
    ) -> VMCost:
        """
        Calculate cost for a VM
        
        Args:
            vm_id: VM ID
            period_start: Period start (default: 30 days ago)
            period_end: Period end (default: now)
        
        Returns:
            VMCost details
        """
        # Default period: last 30 days
        if not period_end:
            period_end = datetime.utcnow()
        if not period_start:
            period_start = period_end - timedelta(days=30)
        
        # Get VM info
        vm_info = await self.client.get_vm_info(vm_id)
        
        plan_id = vm_info.get("plan_id", "")
        hostname = vm_info.get("hostname", "")
        
        # Get rates
        if plan_id not in self.plan_rates:
            logger.warning(f"Unknown plan {plan_id}, using default rates")
            hourly_rate = Decimal("0.05")
            monthly_rate = Decimal("35.00")
        else:
            rates = self.plan_rates[plan_id]
            hourly_rate = rates["hourly"]
            monthly_rate = rates["monthly"]
        
        daily_rate = hourly_rate * 24
        
        # Calculate runtime cost
        hours = (period_end - period_start).total_seconds() / 3600
        runtime_cost = hourly_rate * Decimal(str(hours))
        
        # Get bandwidth usage
        bandwidth_data = await self.client.get_bandwidth_usage(vm_id)
        bandwidth_used = bandwidth_data.get("total_used_gb", 0.0)
        bandwidth_limit = bandwidth_data.get("limit_gb", 0.0)
        
        # Calculate bandwidth overage
        bandwidth_overage = max(0.0, bandwidth_used - bandwidth_limit)
        bandwidth_overage_cost = (
            self.bandwidth_overage_rate * Decimal(str(bandwidth_overage))
        )
        
        # Total cost
        total_cost = runtime_cost + bandwidth_overage_cost
        
        return VMCost(
            vm_id=vm_id,
            hostname=hostname,
            plan_id=plan_id,
            hourly_rate=hourly_rate,
            daily_rate=daily_rate,
            monthly_rate=monthly_rate,
            bandwidth_used_gb=bandwidth_used,
            bandwidth_limit_gb=bandwidth_limit,
            bandwidth_overage_gb=bandwidth_overage,
            bandwidth_overage_cost=bandwidth_overage_cost,
            total_cost=total_cost,
            period_start=period_start,
            period_end=period_end
        )
    
    async def get_project_cost(
        self,
        project_uuid: str,
        period_start: Optional[datetime] = None,
        period_end: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Calculate total cost for all VMs in project
        
        Args:
            project_uuid: Project UUID
            period_start: Period start
            period_end: Period end
        
        Returns:
            Dictionary with total cost and per-VM breakdown
        """
        # Get all VMs in project
        vms = await self.client.list_vms(project_uuid)
        
        vm_costs = []
        total_cost = Decimal("0.00")
        total_bandwidth_overage_cost = Decimal("0.00")
        
        for vm_data in vms:
            vm_id = vm_data.get("vm_id")
            
            try:
                cost = await self.get_vm_cost(
                    vm_id,
                    period_start,
                    period_end
                )
                
                vm_costs.append(cost)
                total_cost += cost.total_cost
                total_bandwidth_overage_cost += cost.bandwidth_overage_cost
                
            except Exception as e:
                logger.error(f"Failed to get cost for VM {vm_id}: {str(e)}")
        
        return {
            "project_uuid": project_uuid,
            "total_cost": float(total_cost),
            "total_bandwidth_overage_cost": float(total_bandwidth_overage_cost),
            "vm_count": len(vm_costs),
            "vms": [c.to_dict() for c in vm_costs],
            "period_start": period_start.isoformat() if period_start else None,
            "period_end": period_end.isoformat() if period_end else None
        }
    
    async def project_monthly_cost(
        self,
        project_uuid: str
    ) -> Decimal:
        """
        Project monthly cost based on current usage
        
        Args:
            project_uuid: Project UUID
        
        Returns:
            Projected monthly cost
        """
        # Get all VMs
        vms = await self.client.list_vms(project_uuid)
        
        monthly_cost = Decimal("0.00")
        
        for vm_data in vms:
            vm_id = vm_data.get("vm_id")
            plan_id = vm_data.get("plan_id", "")
            
            # Add base monthly rate
            if plan_id in self.plan_rates:
                monthly_cost += self.plan_rates[plan_id]["monthly"]
            
            # Project bandwidth overage
            try:
                bandwidth_data = await self.client.get_bandwidth_usage(vm_id)
                bandwidth_used = bandwidth_data.get("total_used_gb", 0.0)
                bandwidth_limit = bandwidth_data.get("limit_gb", 0.0)
                
                # Estimate monthly overage based on current usage
                # (This is a simple estimation - could be improved)
                overage = max(0.0, bandwidth_used - bandwidth_limit)
                monthly_cost += self.bandwidth_overage_rate * Decimal(str(overage))
                
            except Exception as e:
                logger.error(f"Failed to get bandwidth for VM {vm_id}: {str(e)}")
        
        return monthly_cost
