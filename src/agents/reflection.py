"""
Reflection Agent - 反思层Agent

负责分析执行结果、决定是否需要重试或调整策略。
"""

import logging
from typing import Any

from .base import AgentContext, AgentResult, BaseAgent

logger = logging.getLogger(__name__)


class ReflectionAgent(BaseAgent):
    """
    反思层Agent

    功能：
    - 分析执行结果质量
    - 检测异常和失败原因
    - 决定是否需要重试
    - 生成改进建议
    - 触发自适应重试
    """

    agent_name = "reflection"
    description = "分析结果并决定是否需要重试"

    def __init__(
        self, config: dict[str, Any] | None = None, toolkits: dict[str, Any] | None = None
    ):
        super().__init__(config, toolkits)
        self.max_retries = config.get("max_retries", 3) if config else 3
        self.retry_count = 0

    async def execute(self, context: AgentContext) -> AgentResult:
        """
        执行反思分析

        Args:
            context: 包含执行结果的上下文

        Returns:
            AgentResult: 反思分析结果
        """
        try:
            # 1. 分析执行结果
            quality_assessment = await self._assess_quality(context)

            # 2. 检测异常
            anomalies = await self._detect_anomalies(context, quality_assessment)

            # 3. 分析失败原因
            failure_analysis = await self._analyze_failures(context, quality_assessment)

            # 4. 决定是否需要重试
            retry_decision = await self._make_retry_decision(
                context, quality_assessment, failure_analysis
            )

            # 5. 生成改进建议
            improvements = await self._generate_improvements(context, failure_analysis)

            result_data = {
                "quality_assessment": quality_assessment,
                "anomalies": anomalies,
                "failure_analysis": failure_analysis,
                "retry_decision": retry_decision,
                "improvements": improvements,
                "retry_count": self.retry_count,
            }

            # 更新上下文
            context.metadata["reflection"] = result_data

            return AgentResult(
                agent_name=self.agent_name,
                success=quality_assessment.get("overall_success", True),
                execution_time=0.0,
                data=result_data,
                error=None,
                next_step=retry_decision.get("next_step", "aggregator"),
                confidence=quality_assessment.get("confidence", 0.7),
            )

        except Exception as e:
            logger.error(f"Reflection Agent执行失败: {e}", exc_info=True)
            return AgentResult(
                agent_name=self.agent_name,
                success=False,
                execution_time=0.0,
                error=f"反思分析失败: {str(e)}",
                next_step=None,
                confidence=0.0,
            )

    async def _assess_quality(self, context: AgentContext) -> dict[str, Any]:
        """评估执行结果质量"""
        assessment = {
            "overall_success": True,
            "confidence": 0.7,
            "issues": [],
        }

        # 检查模拟结果
        sim_result = context.simulation_result or {}
        if sim_result.get("success") is False:
            assessment["overall_success"] = False
            assessment["issues"].append("交易模拟失败")
            assessment["confidence"] = 0.3

        # 检查攻击检测结果
        attack_detection = sim_result.get("data", {}) if isinstance(sim_result, dict) else {}
        if isinstance(attack_detection, dict) and attack_detection.get("risk_score", 0) > 0.5:
            assessment["has_security_concerns"] = True
            assessment["risk_score"] = attack_detection.get("risk_score")
            if attack_detection.get("risk_score", 0) > 0.7:
                assessment["confidence"] = 0.9  # 高风险但明确

        # 检查trace分析
        trace_issues = (
            sim_result.get("data", {}).get("findings", []) if isinstance(sim_result, dict) else []
        )
        if trace_issues:
            assessment["trace_issues"] = trace_issues

        return assessment

    async def _detect_anomalies(
        self, context: AgentContext, quality: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """检测异常"""
        anomalies = []

        # 从执行结果中提取异常
        sim_result = context.simulation_result or {}

        # 检查交易失败
        if isinstance(sim_result, dict):
            execution = sim_result.get("data", {}).get("execution", {})
            if execution.get("success") is False:
                anomalies.append(
                    {
                        "type": "transaction_failure",
                        "severity": "high",
                        "message": execution.get("error", "交易执行失败"),
                    }
                )

            # 检查资产异常变动
            asset_changes = sim_result.get("data", {}).get("asset_changes", [])
            for change in asset_changes:
                amount = int(change.get("change", 0))
                if amount < -int(1e18):  # 超过1 ETH转出
                    anomalies.append(
                        {
                            "type": "unexpected_outflow",
                            "severity": "critical",
                            "message": f"异常大额转出: {abs(amount) / 1e18} ETH",
                            "token": change.get("token"),
                        }
                    )

        return anomalies

    async def _analyze_failures(
        self, context: AgentContext, quality: dict[str, Any]
    ) -> dict[str, Any]:
        """分析失败原因"""
        analysis = {
            "has_failures": False,
            "failure_types": [],
            "remediation_steps": [],
        }

        issues = quality.get("issues", [])
        if issues:
            analysis["has_failures"] = True

            for issue in issues:
                if "模拟失败" in issue:
                    analysis["failure_types"].append("execution_error")
                    analysis["remediation_steps"].append("检查交易参数和合约状态")
                elif "超时" in issue:
                    analysis["failure_types"].append("timeout")
                    analysis["remediation_steps"].append("增加超时时间或优化模拟配置")

        return analysis

    async def _make_retry_decision(
        self, context: AgentContext, quality: dict[str, Any], failure: dict[str, Any]
    ) -> dict[str, Any]:
        """决定是否需要重试"""
        decision = {
            "should_retry": False,
            "retry_strategy": None,
            "next_step": "aggregator",
        }

        # 如果结果良好，不需要重试
        if quality.get("overall_success") and quality.get("confidence", 0) > 0.7:
            return decision

        # 如果有可重试的失败
        if failure.get("has_failures") and self.retry_count < self.max_retries:
            retryable_types = ["timeout", "execution_error"]
            if any(t in retryable_types for t in failure.get("failure_types", [])):
                decision["should_retry"] = True
                decision["retry_strategy"] = self._select_retry_strategy(failure)
                decision["next_step"] = "executor"
                self.retry_count += 1

        return decision

    def _select_retry_strategy(self, failure: dict[str, Any]) -> dict[str, Any]:
        """选择重试策略"""
        failure_types = failure.get("failure_types", [])

        if "timeout" in failure_types:
            return {
                "type": "increase_timeout",
                "params": {"timeout_multiplier": 2},
            }
        elif "execution_error" in failure_types:
            return {
                "type": "state_override",
                "params": {
                    "strategies": [
                        "increase_balance",
                        "modify_timestamp",
                        "adjust_gas_limit",
                    ]
                },
            }
        else:
            return {"type": "simple_retry"}

    async def _generate_improvements(
        self, context: AgentContext, failure: dict[str, Any]
    ) -> list[str]:
        """生成改进建议"""
        improvements = []

        if failure.get("has_failures"):
            improvements.extend(failure.get("remediation_steps", []))

        # 基于用户意图的建议
        intent_lower = context.user_intent.lower()
        if "swap" in intent_lower:
            improvements.append("确认使用官方DEX合约")
            improvements.append("检查滑点设置是否合理")

        if "approve" in intent_lower:
            improvements.append("验证授权额度是否合理")
            improvements.append("确认授权目标合约可信")

        return improvements
