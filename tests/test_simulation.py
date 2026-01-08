"""
Simulation Engine Unit Tests
"""

import pytest
from pydantic import ValidationError

from src.simulation.models import (
    AssetChange,
    RiskLevel,
    SimulationRequest,
    SimulationResult,
)


class TestSimulationModels:
    """测试数据模型"""

    def test_simulation_request_creation(self):
        """测试创建 SimulationRequest"""
        request = SimulationRequest(
            user_intent="Swap 1 ETH to USDC",
            chain_id=1,
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            tx_value="1000000000000000000",
            tx_data="0x414bf389000000000000000000000000",
        )
        assert request.user_intent == "Swap 1 ETH to USDC"
        assert request.chain_id == 1
        assert int(request.tx_value) == 1000000000000000000

    def test_simulation_result_creation(self):
        """测试创建 SimulationResult"""
        result = SimulationResult(
            chain_id=1,
            block_number=19_000_000,
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            success=True,
            gas_used=100_000,
        )
        assert result.chain_id == 1
        assert result.success is True
        assert result.risk_level == RiskLevel.SAFE
        assert len(result.anomalies) == 0

    def test_asset_change(self):
        """测试资产变动计算"""
        change = AssetChange(
            token_address="0x" + "0" * 40,
            token_symbol="ETH",
            token_decimals=18,
            balance_before="2000000000000000000",
            balance_after="1000000000000000000",
            change_amount="-1000000000000000000",
        )
        assert change.token_symbol == "ETH"
        assert int(change.change_amount) == -1000000000000000000


class TestSimulationRequestValidation:
    """测试 SimulationRequest 验证"""

    def test_invalid_address(self):
        """测试无效地址"""
        with pytest.raises(ValidationError):
            SimulationRequest(
                user_intent="Test",
                tx_from="invalid_address",
                tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            )

    def test_empty_intent(self):
        """测试空意图"""
        with pytest.raises(ValidationError):
            SimulationRequest(
                user_intent="",
                tx_from="0x1234567890123456789012345678901234567890",
                tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            )


class TestAssetChangeCalculation:
    """测试资产变动计算"""

    def test_eth_decrease(self):
        """测试 ETH 减少"""
        change = AssetChange(
            token_address="0x" + "0" * 40,
            token_symbol="ETH",
            token_decimals=18,
            balance_before="2000000000000000000",
            balance_after="1000000000000000000",
            change_amount="-1000000000000000000",
        )
        assert int(change.change_amount) < 0

    def test_eth_increase(self):
        """测试 ETH 增加"""
        change = AssetChange(
            token_address="0x" + "0" * 40,
            token_symbol="ETH",
            token_decimals=18,
            balance_before="1000000000000000000",
            balance_after="2000000000000000000",
            change_amount="1000000000000000000",
        )
        assert int(change.change_amount) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
