"""
Perception Agent - 感知层Agent

负责解析用户输入、验证数据格式、提取关键信息。
"""

import logging
from typing import Any

from .base import AgentContext, AgentResult, BaseAgent

logger = logging.getLogger(__name__)


class PerceptionAgent(BaseAgent):
    """
    感知层Agent

    功能：
    - 解析用户自然语言意图
    - 验证交易数据格式
    - 提取关键参数（链ID、地址、金额等）
    - 规范化输入数据
    """

    agent_name = "perception"
    description = "解析用户输入并验证交易数据"

    async def execute(self, context: AgentContext) -> AgentResult:
        """
        执行感知层分析

        Args:
            context: 包含用户意图和交易数据的上下文

        Returns:
            AgentResult: 解析后的规范化数据
        """
        try:
            # 1. 解析用户意图
            intent_analysis = await self._parse_user_intent(context.user_intent)

            # 2. 验证和规范化交易数据
            tx_data = await self._validate_tx_data(context.tx_data)

            # 3. 提取关键参数
            key_params = await self._extract_key_params(context.user_intent, tx_data)

            # 4. 确定任务类型和复杂度
            task_type, complexity = await self._classify_task(context, key_params)

            # 5. 构建结果
            result_data = {
                "user_intent": context.user_intent,
                "intent_analysis": intent_analysis,
                "validated_tx_data": tx_data,
                "key_params": key_params,
                "task_type": task_type,
                "complexity": complexity,
                "is_valid": True,
            }

            # 更新上下文
            context.metadata.update(result_data)

            return AgentResult(
                agent_name=self.agent_name,
                success=True,
                execution_time=0.0,
                data=result_data,
                error=None,
                next_step=self._determine_next_step(task_type, complexity),
                confidence=0.95,
            )

        except Exception as e:
            logger.error(f"Perception Agent执行失败: {e}", exc_info=True)
            return AgentResult(
                agent_name=self.agent_name,
                success=False,
                execution_time=0.0,
                error=f"输入解析失败: {str(e)}",
                next_step=None,
                confidence=0.0,
            )

    async def _parse_user_intent(self, intent: str) -> dict[str, Any]:
        """
        解析用户意图

        Args:
            intent: 用户输入的自然语言意图

        Returns:
            解析后的意图结构化数据
        """
        intent_lower = intent.lower()

        # 意图分类
        intent_type = "unknown"
        if "swap" in intent_lower or "exchange" in intent_lower:
            intent_type = "swap"
        elif "approve" in intent_lower or "authorize" in intent_lower:
            intent_type = "approve"
        elif "transfer" in intent_lower or "send" in intent_lower:
            intent_type = "transfer"
        elif "mint" in intent_lower:
            intent_type = "mint"
        elif "stake" in intent_lower or "deposit" in intent_lower:
            intent_type = "stake"
        elif "claim" in intent_lower:
            intent_type = "claim"

        # 提取金额
        import re

        amount_pattern = r"(\d+(?:\.\d+)?)\s*(?:eth|usdc|usdt|dai|wbtc)?"
        amounts = re.findall(amount_pattern, intent_lower, re.IGNORECASE)

        # 提取滑点容忍度
        slippage_pattern = r"(?:slippage|slip)\s*(?:of\s*)?(\d+(?:\.\d+)?)%?"
        slippage_match = re.search(slippage_pattern, intent_lower)
        slippage = float(slippage_match.group(1)) / 100 if slippage_match else None

        return {
            "intent_type": intent_type,
            "amounts": amounts,
            "slippage_tolerance": slippage,
            "raw_intent": intent,
        }

    async def _validate_tx_data(self, tx_data: dict[str, Any]) -> dict[str, Any]:
        """
        验证交易数据

        Args:
            tx_data: 原始交易数据

        Returns:
            验证并规范化后的交易数据
        """
        validated = {}

        # 验证地址格式
        for key in ["tx_from", "tx_to", "from", "to"]:
            if key in tx_data:
                address = tx_data[key]
                if not isinstance(address, str):
                    raise ValueError(f"{key} 必须是字符串")
                if not address.startswith("0x") or len(address) != 42:
                    raise ValueError(f"{key} 地址格式无效")
                # 标准化地址
                validated[key] = address.lower()

        # 验证并转换value
        for key in ["tx_value", "value", "amount"]:
            if key in tx_data:
                value = tx_data[key]
                validated[key] = self._normalize_value(value)

        # 验证calldata
        for key in ["tx_data", "data", "calldata"]:
            if key in tx_data:
                data = tx_data[key]
                if not data.startswith("0x"):
                    data = "0x" + data
                validated[key] = data

        # 设置默认值
        validated.setdefault("tx_value", "0")
        validated.setdefault("tx_data", "0x")

        return validated

    def _normalize_value(self, value: Any) -> str:
        """规范化value值"""
        if isinstance(value, int):
            return hex(value)
        if isinstance(value, float):
            # 假设是以ETH为单位，转换为wei
            wei = int(value * 1e18)
            return hex(wei)
        if isinstance(value, str):
            if value.startswith("0x"):
                return value
            try:
                # 尝试转换为整数
                return hex(int(value))
            except ValueError:
                return "0"
        return "0"

    async def _extract_key_params(self, intent: str, tx_data: dict[str, Any]) -> dict[str, Any]:
        """提取关键参数"""
        return {
            "chain_id": tx_data.get("chain_id", 1),
            "tx_from": tx_data.get("tx_from", tx_data.get("from", "")),
            "tx_to": tx_data.get("tx_to", tx_data.get("to", "")),
            "tx_value": tx_data.get("tx_value", tx_data.get("value", "0")),
            "tx_data": tx_data.get("tx_data", tx_data.get("data", "0x")),
            "gas_limit": tx_data.get("gas_limit", 30_000_000),
        }

    async def _classify_task(
        self, context: AgentContext, params: dict[str, Any]
    ) -> tuple[str, str]:
        """
        分类任务类型和复杂度

        Returns:
            (task_type, complexity): 任务类型和复杂度
        """
        # 根据意图类型确定任务类型
        intent_type = context.metadata.get("intent_analysis", {}).get("intent_type", "unknown")

        # 根据交易特征确定复杂度
        complexity = "simple"
        calldata = params.get("tx_data", "")
        if len(calldata) > 1000:
            complexity = "complex"
        elif len(calldata) > 200:
            complexity = "medium"

        # 特定任务类型需要复杂分析
        if intent_type in ["swap", "approve"]:
            complexity = max(complexity, "medium")

        return intent_type, complexity

    def _determine_next_step(self, task_type: str, complexity: str) -> str:
        """确定下一步流程"""
        if complexity == "complex":
            return "planner"  # 需要任务分解
        else:
            return "executor"  # 直接执行
