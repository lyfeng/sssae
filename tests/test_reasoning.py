"""
Reasoning Layer Unit Tests
"""

import pytest
import asyncio
import os

from src.simulation.models import (
    SimulationRequest,
    SimulationResult,
    RiskLevel,
    AssetChange,
    CallTrace,
)
from src.reasoning.intent_analyzer import MockIntentAnalyzer, IntentAnalyzer
from src.reasoning.roma_analyzer import MockROMAAnalyzer
from src.reasoning.prompts import PromptTemplates, KnownRiskPatterns


class TestPromptTemplates:
    """测试 Prompt 模板"""

    def test_system_prompt_exists(self):
        """测试系统提示词存在"""
        assert PromptTemplates.SYSTEM_PROMPT
        assert "SSSEA" in PromptTemplates.SYSTEM_PROMPT

    def test_intent_alignment_template(self):
        """测试意图对齐模板"""
        prompt = PromptTemplates.build_intent_alignment_prompt(
            user_intent="Swap 1 ETH to USDC",
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            tx_value="1000000000000000000",
            tx_data="0x414bf389",
            success=True,
            gas_used=100000,
            error_message="",
            asset_changes=[
                {"token_symbol": "ETH", "change_amount": "-1000000000000000000"},
                {"token_symbol": "USDC", "change_amount": "2500000000"},
            ],
            call_trace_summary="[深度1] 0x123... -> 0xE59...",
            detected_anomalies=[],
        )
        assert "Swap 1 ETH to USDC" in prompt
        assert "0xE592427A0AEce92De3Edee1F18E0157C05861564" in prompt
        assert "ETH: -1000000000000000000" in prompt

    def test_slippage_template(self):
        """测试滑点验证模板"""
        prompt = PromptTemplates.build_slippage_verification_prompt(
            max_slippage=0.005,
            input_amount="1 ETH",
            expected_output="2500 USDC",
            actual_output="2490 USDC",
            actual_slippage=0.004,
        )
        assert "0.5%" in prompt
        assert "0.4%" in prompt


class TestKnownRiskPatterns:
    """测试已知风险模式库"""

    def test_extract_function_selector(self):
        """测试提取函数选择器"""
        selector = KnownRiskPatterns.extract_function_selector(
            "0x095ea7b3b000000000000000000000000"
        )
        assert selector == "0x095ea7b3"

    def test_get_function_name(self):
        """测试获取函数名"""
        name = KnownRiskPatterns.get_function_name("0x095ea7b3")
        assert "approve" in name

    def test_is_official_contract(self):
        """测试官方合约识别"""
        # Uniswap V2 Router
        is_official = KnownRiskPatterns.is_official_contract(
            "ethereum",
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        )
        assert is_official is True

        # 随机地址
        is_official = KnownRiskPatterns.is_official_contract(
            "ethereum",
            "0x1234567890123456789012345678901234567890",
        )
        assert is_official is False


class TestMockIntentAnalyzer:
    """测试 Mock 意图分析器"""

    @pytest.fixture
    def analyzer(self):
        return MockIntentAnalyzer()

    def test_safe_transaction(self, analyzer):
        """测试安全交易分析"""
        request = SimulationRequest(
            user_intent="Swap 1 ETH to USDC",
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            tx_value="1000000000000000000",
        )

        result = SimulationResult(
            chain_id=1,
            block_number=19_000_000,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            tx_value=request.tx_value,
            success=True,
            gas_used=150000,
            asset_changes=[
                AssetChange(
                    token_address="0x" + "0" * 40,
                    token_symbol="ETH",
                    token_decimals=18,
                    balance_before="2000000000000000000",
                    balance_after="1000000000000000000",
                    change_amount="-1000000000000000000",
                ),
                AssetChange(
                    token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    token_symbol="USDC",
                    token_decimals=6,
                    balance_before="0",
                    balance_after="2500000000",
                    change_amount="2500000000",
                ),
            ],
        )

        analysis = asyncio.run(analyzer.analyze(request, result))
        assert analysis.risk_level == RiskLevel.SAFE
        assert analysis.confidence > 0

    def test_failed_transaction(self, analyzer):
        """测试失败交易分析"""
        request = SimulationRequest(
            user_intent="Swap 1 ETH to USDC",
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
        )

        result = SimulationResult(
            chain_id=1,
            block_number=19_000_000,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            success=False,
            gas_used=0,
            error_message="Revert with reason: Insufficient liquidity",
        )

        analysis = asyncio.run(analyzer.analyze(request, result))
        assert analysis.risk_level == RiskLevel.WARNING
        assert "失败" in analysis.summary

    def test_unexpected_eth_out(self, analyzer):
        """测试异常 ETH 转出"""
        request = SimulationRequest(
            user_intent="Swap 1 ETH to USDC",
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            tx_value="1000000000000000000",  # 1 ETH
        )

        result = SimulationResult(
            chain_id=1,
            block_number=19_000_000,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            tx_value=request.tx_value,
            success=True,
            gas_used=100000,
            asset_changes=[
                AssetChange(
                    token_address="0x" + "0" * 40,
                    token_symbol="ETH",
                    token_decimals=18,
                    balance_before="2000000000000000000",
                    balance_after="0",
                    change_amount="-2000000000000000000",  # 转出了 2 ETH！
                ),
            ],
        )

        analysis = asyncio.run(analyzer.analyze(request, result))
        assert analysis.risk_level == RiskLevel.CRITICAL
        assert any("异常" in a or "转出" in a for a in analysis.anomalies)

    def test_deep_call_stack(self, analyzer):
        """测试调用深度检测"""
        request = SimulationRequest(
            user_intent="Execute contract",
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
        )

        result = SimulationResult(
            chain_id=1,
            block_number=19_000_000,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            success=True,
            gas_used=500000,
            call_traces=[
                CallTrace(
                    depth=25,
                    from_address="0x1234567890123456789012345678901234567890",
                    to_address="0xE592427A0AEce92De3Edee1F18E0157C05861564",
                    value="0",
                    input_data="0x",
                ),
            ],
        )

        analysis = asyncio.run(analyzer.analyze(request, result))
        assert analysis.risk_level == RiskLevel.WARNING
        assert any("重入" in a or "深度" in a for a in analysis.anomalies)


class TestMockROMAAnalyzer:
    """测试 Mock ROMA 分析器"""

    @pytest.fixture
    def analyzer(self):
        return MockROMAAnalyzer()

    def test_safe_transaction(self, analyzer):
        """测试安全交易分析"""
        request = SimulationRequest(
            user_intent="Swap 1 ETH to USDC",
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            tx_value="1000000000000000000",
        )

        result = SimulationResult(
            chain_id=1,
            block_number=19_000_000,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            tx_value=request.tx_value,
            success=True,
            gas_used=150000,
            asset_changes=[
                AssetChange(
                    token_address="0x" + "0" * 40,
                    token_symbol="ETH",
                    token_decimals=18,
                    balance_before="2000000000000000000",
                    balance_after="1000000000000000000",
                    change_amount="-1000000000000000000",
                ),
                AssetChange(
                    token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    token_symbol="USDC",
                    token_decimals=6,
                    balance_before="0",
                    balance_after="2500000000",
                    change_amount="2500000000",
                ),
            ],
        )

        analysis = asyncio.run(analyzer.analyze(request, result))
        assert analysis.risk_level == RiskLevel.SAFE
        assert analysis.raw_response == "mock_roma_response"

    def test_fallback_to_rules(self, analyzer):
        """测试回退到规则检查"""
        request = SimulationRequest(
            user_intent="Swap 1 ETH to USDC",
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
            tx_value="1000000000000000000",
        )

        # 模拟异常 ETH 转出
        result = SimulationResult(
            chain_id=1,
            block_number=19_000_000,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            tx_value=request.tx_value,
            success=True,
            gas_used=100000,
            asset_changes=[
                AssetChange(
                    token_address="0x" + "0" * 40,
                    token_symbol="ETH",
                    token_decimals=18,
                    balance_before="2000000000000000000",
                    balance_after="0",
                    change_amount="-2000000000000000000",  # 转出了 2 ETH
                ),
            ],
        )

        analysis = asyncio.run(analyzer.analyze(request, result))
        assert analysis.risk_level == RiskLevel.CRITICAL


class TestROMAFallback:
    """测试 ROMA 不可用时的回退逻辑"""

    def test_roma_not_available_fallback(self):
        """测试 ROMA 未安装时的回退行为"""
        # 即使 ROMA 没有安装，MockROMAAnalyzer 应该能正常工作
        analyzer = MockROMAAnalyzer()

        request = SimulationRequest(
            user_intent="Test transaction",
            tx_from="0x1234567890123456789012345678901234567890",
            tx_to="0xE592427A0AEce92De3Edee1F18E0157C05861564",
        )

        result = SimulationResult(
            chain_id=1,
            block_number=19_000_000,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            success=True,
            gas_used=100000,
        )

        analysis = asyncio.run(analyzer.analyze(request, result))
        assert analysis.risk_level in [RiskLevel.SAFE, RiskLevel.WARNING, RiskLevel.CRITICAL]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
