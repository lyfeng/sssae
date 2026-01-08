"""
Aggregator Agent - 聚合层Agent

负责聚合所有Agent的结果，生成最终报告。
"""

import logging
from datetime import datetime
from typing import Any

from .base import AgentContext, AgentResult, BaseAgent

logger = logging.getLogger(__name__)


class AggregatorAgent(BaseAgent):
    """
    聚合层Agent

    功能：
    - 聚合所有Agent的执行结果
    - 生成最终安全评估
    - 创建可解释性报告
    - 格式化输出结果
    """

    agent_name = "aggregator"
    description = "聚合结果并生成最终报告"

    async def execute(self, context: AgentContext) -> AgentResult:
        """
        执行结果聚合

        Args:
            context: 包含所有执行结果的上下文

        Returns:
            AgentResult: 最终聚合报告
        """
        try:
            # 1. 收集所有结果
            all_results = await self._collect_results(context)

            # 2. 生成安全评估
            security_assessment = await self._generate_security_assessment(context, all_results)

            # 3. 创建可解释性报告
            explainability_report = await self._create_explainability_report(context, all_results)

            # 4. 生成推荐操作
            recommendations = await self._generate_recommendations(context, security_assessment)

            # 5. 构建最终报告
            final_report = await self._build_final_report(
                context, all_results, security_assessment, explainability_report, recommendations
            )

            return AgentResult(
                agent_name=self.agent_name,
                success=True,
                execution_time=0.0,
                data=final_report,
                error=None,
                next_step=None,  # 最终步骤
                confidence=security_assessment.get("confidence", 0.7),
            )

        except Exception as e:
            logger.error(f"Aggregator Agent执行失败: {e}", exc_info=True)
            return AgentResult(
                agent_name=self.agent_name,
                success=False,
                execution_time=0.0,
                error=f"结果聚合失败: {str(e)}",
                next_step=None,
                confidence=0.0,
            )

    async def _collect_results(self, context: AgentContext) -> dict[str, Any]:
        """收集所有Agent结果"""
        return {
            "perception": context.metadata.get("intent_analysis"),
            "simulation": context.simulation_result,
            "reflection": context.metadata.get("reflection"),
            "execution_history": context.step_history,
            "user_intent": context.user_intent,
        }

    async def _generate_security_assessment(
        self, context: AgentContext, results: dict[str, Any]
    ) -> dict[str, Any]:
        """生成安全评估"""
        assessment = {
            "risk_level": "SAFE",
            "confidence": 0.7,
            "risk_score": 0.0,
            "findings": [],
        }

        # 从反思结果中获取风险评估
        reflection = results.get("reflection", {})
        if reflection:
            quality = reflection.get("quality_assessment", {})
            if quality.get("has_security_concerns"):
                assessment["risk_level"] = "WARNING"
                assessment["risk_score"] = quality.get("risk_score", 0.5)

        # 从攻击检测结果获取风险
        sim_result = results.get("simulation", {})
        if isinstance(sim_result, dict):
            attack_detection = sim_result.get("data", {})
            if isinstance(attack_detection, dict) and attack_detection.get("risk_score"):
                assessment["risk_score"] = max(
                    assessment["risk_score"], attack_detection.get("risk_score", 0)
                )
                if attack_detection.get("risk_score", 0) > 0.7:
                    assessment["risk_level"] = "CRITICAL"

        # 从异常检测结果获取风险
        if reflection:
            anomalies = reflection.get("anomalies", [])
            critical_anomalies = [a for a in anomalies if a.get("severity") == "critical"]
            if critical_anomalies:
                assessment["risk_level"] = "CRITICAL"
                assessment["risk_score"] = 0.9
                assessment["findings"].extend([a["message"] for a in critical_anomalies])

        return assessment

    async def _create_explainability_report(
        self, context: AgentContext, results: dict[str, Any]
    ) -> dict[str, Any]:
        """创建可解释性报告"""
        report = {
            "execution_summary": self._generate_execution_summary(results),
            "decision_path": results.get("execution_history", []),
            "key_findings": [],
            "evidence": [],
        }

        # 从模拟结果提取证据
        sim_result = results.get("simulation", {})
        if isinstance(sim_result, dict):
            data = sim_result.get("data", {})

            # 资产变动证据
            asset_changes = data.get("asset_changes", [])
            if asset_changes:
                report["evidence"].append(
                    {
                        "type": "asset_changes",
                        "description": f"检测到 {len(asset_changes)} 项资产变动",
                        "details": asset_changes[:5],
                    }
                )

            # 调用链证据
            call_traces = data.get("call_traces", [])
            if call_traces:
                report["evidence"].append(
                    {
                        "type": "call_chain",
                        "description": f"交易包含 {len(call_traces)} 个合约调用",
                        "max_depth": max((t.get("depth", 0) for t in call_traces), default=0),
                    }
                )

        return report

    def _generate_execution_summary(self, results: dict[str, Any]) -> str:
        """生成执行摘要"""
        steps = results.get("execution_history", [])
        sim_result = results.get("simulation", {})

        summary_parts = [
            f"执行了 {len(steps)} 个步骤",
        ]

        if isinstance(sim_result, dict) and sim_result.get("success"):
            summary_parts.append("交易模拟成功")
        else:
            summary_parts.append("交易模拟失败或未执行")

        return "; ".join(summary_parts)

    async def _generate_recommendations(
        self, context: AgentContext, assessment: dict[str, Any]
    ) -> list[str]:
        """生成推荐操作"""
        recommendations = []

        risk_level = assessment.get("risk_level", "SAFE")

        if risk_level == "CRITICAL":
            recommendations = [
                "立即停止此交易",
                "检查目标合约地址是否正确",
                "验证交易calldata是否被篡改",
                "建议人工审核",
            ]
        elif risk_level == "WARNING":
            recommendations = [
                "谨慎执行此交易",
                "确认了解所有潜在风险",
                "考虑降低交易金额",
            ]
        else:
            recommendations = [
                "交易安全性评估通过",
                "可以继续执行",
            ]

        # 添加反思层的改进建议
        reflection = context.metadata.get("reflection", {})
        if reflection:
            improvements = reflection.get("improvements", [])
            recommendations.extend(improvements)

        return recommendations

    async def _build_final_report(
        self,
        context: AgentContext,
        results: dict[str, Any],
        assessment: dict[str, Any],
        explainability: dict[str, Any],
        recommendations: list[str],
    ) -> dict[str, Any]:
        """构建最终报告"""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "user_intent": context.user_intent,
            "verdict": {
                "risk_level": assessment["risk_level"],
                "confidence": assessment["confidence"],
                "risk_score": assessment["risk_score"],
            },
            "summary": self._generate_summary(assessment, context),
            "findings": assessment["findings"],
            "recommendations": recommendations,
            "execution_details": {
                "steps": results.get("execution_history", []),
                "summary": explainability.get("execution_summary", ""),
            },
            "evidence": explainability.get("evidence", []),
            "transaction_info": self._extract_transaction_info(context),
        }

    def _generate_summary(self, assessment: dict[str, Any], context: AgentContext) -> str:
        """生成摘要"""
        risk_level = assessment["risk_level"]
        confidence = assessment["confidence"]

        summaries = {
            "SAFE": f"交易安全性评估通过 (置信度: {confidence:.0%})",
            "WARNING": f"检测到潜在风险 (置信度: {confidence:.0%})",
            "CRITICAL": f"检测到严重安全风险 (置信度: {confidence:.0%})",
        }

        return summaries.get(risk_level, "评估完成")

    def _extract_transaction_info(self, context: AgentContext) -> dict[str, Any]:
        """提取交易信息"""
        key_params = context.metadata.get("key_params", {})
        return {
            "from": key_params.get("tx_from", ""),
            "to": key_params.get("tx_to", ""),
            "value": key_params.get("tx_value", "0"),
            "data_preview": key_params.get("tx_data", "0x")[:100] + "...",
        }
