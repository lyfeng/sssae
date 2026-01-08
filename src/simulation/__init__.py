"""
Simulation Engine - EVM 交易模拟模块

提供基于 Foundry Anvil 的主网分叉模拟功能。
"""

from .anvil_screener import AnvilScreener, AnvilScreenerPool, find_free_port
from .models import (
    AssetChange,
    CallTrace,
    ChainId,
    EventLog,
    RiskLevel,
    SimulationRequest,
    SimulationResult,
)

__all__ = [
    # Models
    "SimulationRequest",
    "SimulationResult",
    "AssetChange",
    "CallTrace",
    "EventLog",
    "RiskLevel",
    "ChainId",
    # Anvil
    "AnvilScreener",
    "AnvilScreenerPool",
    "find_free_port",
]
