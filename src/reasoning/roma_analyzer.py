"""
ROMA-based Intent Analyzer - 使用 ROMA 框架的意图分析器

ROMA (Recursive Open Meta-Agents) 是一个递归式元智能体框架，
可以自动分解复杂任务、执行子任务、聚合结果并进行验证。
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from pydantic import BaseModel, Field

from ..simulation.models import (
    SimulationRequest,
    SimulationResult,
    RiskLevel,
    AssetChange,
)
from .intent_analyzer import (
    IntentAnalysisResult,
    _max_risk,
    KnownRiskPatterns,
)
from .prompts import PromptTemplates


logger = logging.getLogger(__name__)


class ROMAIntentAnalyzer:
    """
    基于 ROMA 框架的意图分析器

    使用 ROMA 的递归推理能力进行更深入的安全审计分析。
    """

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        model: str = "openai/gpt-4o",
        provider: str = "openrouter",
    ):
        """
        初始化 ROMA 意图分析器

        Args:
            api_key: LLM API Key
            base_url: API Base URL (可选，默认使用提供商默认 URL)
            model: 使用的模型
            provider: LLM 提供商 (openrouter, openai, anthropic, etc.)
        """
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.provider = provider

        # 延迟导入 ROMA，允许在没有安装的情况下运行
        try:
            from roma_dspy import Atomizer, Executor, Verifier
            from dspy import OpenAI

            # 配置 DSPy 使用指定的 LLM
            if provider == "openrouter":
                llm = OpenAI(
                    base_url="https://openrouter.ai/api/v1",
                    api_key=api_key,
                    model=model,
                )
            elif provider == "openai" and base_url:
                llm = OpenAI(
                    base_url=base_url,
                    api_key=api_key,
                    model=model,
                )
            else:
                llm = OpenAI(
                    api_key=api_key,
                    model=model,
                )

            # 配置 DSPy
            import dspy
            dspy.configure(lm=llm)

            # 初始化 ROMA 模块
            self.atomizer = Atomizer()
            self.executor = Executor()
            self.verifier = Verifier()
            self.roma_available = True

            logger.info(f"ROMA initialized with model: {model}")

        except ImportError as e:
            logger.warning(f"ROMA not available: {e}")
            self.roma_available = False
            self.atomizer = None
            self.executor = None
            self.verifier = None

    async def analyze(
        self,
        request: SimulationRequest,
        result: SimulationResult,
    ) -> IntentAnalysisResult:
        """
        执行意图对齐分析

        Args:
            request: 模拟请求（包含用户意图）
            result: 模拟执行结果

        Returns:
            IntentAnalysisResult: 分析结果
        """
        # 1. 首先进行基于规则的快速检查
        rule_based_result = self._rule_based_check(request, result)

        # 如果规则检查已经发现严重问题，直接返回
        if rule_based_result["risk_level"] == RiskLevel.CRITICAL:
            return IntentAnalysisResult(
                risk_level=RiskLevel.CRITICAL,
                confidence=1.0,
                summary=rule_based_result["summary"],
                analysis=rule_based_result["analysis"],
                anomalies=rule_based_result["anomalies"],
                recommendations=rule_based_result["recommendations"],
            )

        # 2. 使用 ROMA 进行深度分析
        if self.roma_available:
            roma_result = await self._roma_analyze(request, result, rule_based_result)
        else:
            # 回退到传统 LLM 分析
            roma_result = await self._fallback_llm_analyze(request, result)

        # 3. 合并规则和 ROMA 的结果
        final_result = self._merge_results(rule_based_result, roma_result, result)

        return final_result

    def _rule_based_check(
        self,
        request: SimulationRequest,
        result: SimulationResult,
    ) -> Dict[str, Any]:
        """
        基于规则的快速检查

        检查项：
        1. 交易是否失败
        2. 是否有异常的 ETH 转出
        3. 调用深度是否过深（重入风险）
        4. 是否有危险的函数调用
        """
        risk_level = RiskLevel.SAFE
        anomalies = []
        recommendations = []
        summary = "基于规则的初步检查通过"
        analysis = ""

        # 检查 1: 交易失败
        if not result.success:
            risk_level = RiskLevel.WARNING
            summary = "交易执行失败"
            analysis = f"交易在模拟中失败，可能原因：{result.error_message or '未知错误'}"
            anomalies.append(f"交易执行失败: {result.error_message}")
            recommendations.append("检查交易参数和合约状态")

        # 检查 2: 异常的 ETH 转出
        tx_value_int = int(request.tx_value) if not request.tx_value.startswith("0x") else int(request.tx_value, 16)
        for change in result.asset_changes:
            if change.token_symbol == "ETH":
                change_int = int(change.change_amount)
                # 如果转出的 ETH 超过 tx_value，说明有额外的转出
                if change_int < -tx_value_int:
                    risk_level = RiskLevel.CRITICAL
                    summary = "检测到异常的 ETH 转出"
                    extra_out = abs(change_int) - tx_value_int
                    anomalies.append(f"异常 ETH 转出: 额外转出 {extra_out / 1e18:.4f} ETH")
                    recommendations.append("立即停止交易，这可能是钓鱼攻击")

        # 检查 3: 调用深度（重入风险）
        if result.call_traces:
            max_depth = max(t.depth for t in result.call_traces)
            if max_depth > 20:
                risk_level = _max_risk(risk_level, RiskLevel.WARNING)
                anomalies.append(f"调用深度过深 ({max_depth})，可能存在重入风险")
                recommendations.append("检查合约是否存在重入漏洞")

        # 检查 4: 危险的函数选择器
        selector = KnownRiskPatterns.extract_function_selector(request.tx_data)
        func_name = KnownRiskPatterns.get_function_name(selector)
        if func_name != "unknown":
            # 检查是否为官方合约
            is_official = KnownRiskPatterns.is_official_contract(
                "ethereum", request.tx_to
            )
            if not is_official:
                risk_level = _max_risk(risk_level, RiskLevel.WARNING)
                anomalies.append(f"检测到敏感函数调用: {func_name}")
                recommendations.append(f"确认 {request.tx_to} 是可信的官方合约")

        # 检查 5: 资产变动是否与意图一致
        if "swap" in request.user_intent.lower() and result.asset_changes:
            # 用户想 swap，应该有资产减少和增加
            has_decrease = any(int(c.change_amount) < 0 for c in result.asset_changes)
            has_increase = any(int(c.change_amount) > 0 for c in result.asset_changes)
            if not (has_decrease and has_increase) and result.success:
                risk_level = _max_risk(risk_level, RiskLevel.WARNING)
                anomalies.append("Swap 交易后资产变动异常")
                recommendations.append("验证交易是否真的执行了兑换")

        return {
            "risk_level": risk_level,
            "confidence": 0.8,
            "summary": summary,
            "analysis": analysis,
            "anomalies": anomalies,
            "recommendations": recommendations,
        }

    async def _roma_analyze(
        self,
        request: SimulationRequest,
        result: SimulationResult,
        rule_based_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        使用 ROMA 框架进行深度分析

        ROMA 的递归推理流程：
        1. Atomizer 判断分析任务的复杂度
        2. 如果复杂，Planner 分解为子任务
        3. Executor 执行各个子任务
        4. Aggregator 聚合结果
        5. Verifier 验证结果质量
        """
        try:
            # 构建分析上下文
            context = self._build_analysis_context(request, result, rule_based_result)

            # 使用 Atomizer 判断任务类型
            goal = self._build_analysis_goal(request, result)

            # 对于安全审计，我们使用 Executor 直接执行分析任务
            # 因为意图分析通常是一个相对原子化的任务
            analysis_prompt = self._build_roma_prompt(request, result, context)

            # 调用 ROMA Executor 进行分析
            executor_result = self.executor(
                goal=goal,
                context=analysis_prompt,
            )

            # 解析 ROMA 的输出
            return self._parse_roma_result(executor_result, rule_based_result)

        except Exception as e:
            logger.error(f"ROMA 分析失败: {e}")
            # 回退到传统 LLM 分析
            return await self._fallback_llm_analyze(request, result)

    def _build_analysis_goal(
        self,
        request: SimulationRequest,
        result: SimulationResult,
    ) -> str:
        """构建 ROMA 分析目标"""
        return f"""分析以下 Web3 交易的安全性和意图对齐情况：

用户意图: {request.user_intent}
目标合约: {request.tx_to}
执行状态: {'成功' if result.success else '失败'}

请评估：
1. 交易结果是否与用户意图一致
2. 是否存在异常的资金流向或授权操作
3. 调用栈中是否有可疑操作
4. 最终风险评估 (SAFE/WARNING/CRITICAL)

输出 JSON 格式：{{"risk_level": "...", "confidence": 0.9, "summary": "...", "analysis": "...", "anomalies": [...], "recommendations": [...]}}
"""

    def _build_analysis_context(
        self,
        request: SimulationRequest,
        result: SimulationResult,
        rule_based_result: Dict[str, Any],
    ) -> str:
        """构建分析上下文"""
        asset_changes_text = "\n".join([
            f"- {c.token_symbol}: {c.change_amount}"
            for c in result.asset_changes
        ]) if result.asset_changes else "无资产变动"

        call_trace_summary = self._summarize_call_traces(result.call_traces)

        return f"""<transaction_context>
<user_intent>{request.user_intent}</user_intent>
<tx_from>{request.tx_from}</tx_from>
<tx_to>{request.tx_to}</tx_to>
<tx_value>{request.tx_value}</tx_value>
<tx_data>{request.tx_data[:200]}...</tx_data>

<execution_result>
<success>{result.success}</success>
<gas_used>{result.gas_used}</gas_used>
<error_message>{result.error_message or '无'}</error_message>

<asset_changes>
{asset_changes_text}
</asset_changes>

<call_traces>
{call_trace_summary}
</call_traces>
</execution_result>

<rule_based_check>
<risk_level>{rule_based_result['risk_level']}</risk_level>
<anomalies>
{'\\n'.join(rule_based_result['anomalies'])}
</anomalies>
</rule_based_check>
</transaction_context>
"""

    def _build_roma_prompt(
        self,
        request: SimulationRequest,
        result: SimulationResult,
        context: str,
    ) -> str:
        """构建 ROMA 分析提示词"""
        return f"""你是 SSSEA (Sentient Security Sandbox Execution Agent)，一个专门用于 Web3 交易安全审计的 AI Agent。

{context}

请进行深度分析并输出 JSON 格式结果：
{{
    "risk_level": "SAFE|WARNING|CRITICAL",
    "confidence": 0.0-1.0,
    "summary": "简要总结（1-2句话）",
    "analysis": "详细分析",
    "anomalies": ["异常1", "异常2"],
    "recommendations": ["建议1", "建议2"]
}}
"""

    def _parse_roma_result(
        self,
        roma_output: Any,
        rule_based_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """解析 ROMA 的输出结果"""
        try:
            # ROMA 的输出可能是字符串或其他格式
            if isinstance(roma_output, str):
                # 尝试提取 JSON
                json_match = self._extract_json(roma_output)
                if json_match:
                    result = json.loads(json_match)
                else:
                    raise ValueError("无法从 ROMA 输出中提取 JSON")
            elif hasattr(roma_output, "result"):
                result = json.loads(roma_output.result)
            elif isinstance(roma_output, dict):
                result = roma_output
            else:
                # 尝试转换为 JSON
                result = json.loads(str(roma_output))

            return {
                "risk_level": RiskLevel(result.get("risk_level", "WARNING")),
                "confidence": float(result.get("confidence", 0.7)),
                "summary": result.get("summary", "ROMA 分析完成"),
                "analysis": result.get("analysis", ""),
                "anomalies": result.get("anomalies", []),
                "recommendations": result.get("recommendations", []),
                "raw_response": str(roma_output),
                "prompt_tokens": 0,  # ROMA 不直接提供 token 统计
                "completion_tokens": 0,
            }

        except Exception as e:
            logger.error(f"解析 ROMA 结果失败: {e}")
            # 返回保守的默认结果
            return {
                "risk_level": RiskLevel.WARNING,
                "confidence": 0.5,
                "summary": "ROMA 分析结果解析失败",
                "analysis": f"分析结果解析错误: {str(e)}",
                "anomalies": [],
                "recommendations": ["建议人工审核此交易"],
                "raw_response": str(roma_output),
                "prompt_tokens": 0,
                "completion_tokens": 0,
            }

    def _extract_json(self, text: str) -> Optional[str]:
        """从文本中提取 JSON"""
        # 尝试找到第一个完整的 JSON 对象
        brace_count = 0
        start_idx = -1

        for i, char in enumerate(text):
            if char == "{":
                if brace_count == 0:
                    start_idx = i
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0 and start_idx >= 0:
                    return text[start_idx:i + 1]

        return None

    async def _fallback_llm_analyze(
        self,
        request: SimulationRequest,
        result: SimulationResult,
    ) -> Dict[str, Any]:
        """
        回退到传统 LLM 分析

        当 ROMA 不可用或失败时，使用传统的 OpenAI API 调用。
        """
        from openai import AsyncOpenAI

        client = AsyncOpenAI(
            api_key=self.api_key,
            base_url=self.base_url or "https://api.openai.com/v1",
        )

        # 构建提示词
        prompt = PromptTemplates.build_intent_alignment_prompt(
            user_intent=request.user_intent,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            tx_value=request.tx_value,
            tx_data=request.tx_data,
            success=result.success,
            gas_used=result.gas_used,
            error_message=result.error_message or "",
            asset_changes=[
                {"token_symbol": c.token_symbol, "change_amount": c.change_amount}
                for c in result.asset_changes
            ],
            call_trace_summary=self._summarize_call_traces(result.call_traces),
            detected_anomalies=result.anomalies,
        )

        try:
            response = await client.chat.completions.create(
                model=self.model.split("/")[-1],  # 移除提供商前缀
                messages=[
                    {"role": "system", "content": PromptTemplates.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content
            result = json.loads(content)

            return {
                "risk_level": RiskLevel(result.get("risk_level", "SAFE")),
                "confidence": result.get("confidence", 0.5),
                "summary": result.get("summary", ""),
                "analysis": result.get("analysis", ""),
                "anomalies": result.get("anomalies", []),
                "recommendations": result.get("recommendations", []),
                "raw_response": content,
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
            }

        except Exception as e:
            logger.error(f"回退 LLM 分析失败: {e}")
            return {
                "risk_level": RiskLevel.WARNING,
                "confidence": 0.5,
                "summary": "LLM 分析失败",
                "analysis": f"分析服务不可用: {str(e)}",
                "anomalies": [],
                "recommendations": ["建议人工审核此交易"],
                "raw_response": None,
                "prompt_tokens": 0,
                "completion_tokens": 0,
            }

    def _summarize_call_traces(self, traces: List) -> str:
        """总结调用栈"""
        if not traces:
            return "无调用数据"

        summary = []
        for trace in traces[:5]:
            summary.append(
                f"[深度{trace.depth}] {trace.from_address} -> {trace.to_address}"
                + (f" (${int(trace.value) / 1e18:.4f} ETH)" if int(trace.value) > 0 else "")
            )

        if len(traces) > 5:
            summary.append(f"... 还有 {len(traces) - 5} 个调用")

        return "\n".join(summary)

    def _merge_results(
        self,
        rule_based: Dict[str, Any],
        llm_based: Dict[str, Any],
        result: SimulationResult,
    ) -> IntentAnalysisResult:
        """
        合并规则检查和 LLM 分析的结果

        策略：
        1. 风险等级取两者中较高的
        2. 合并异常列表
        3. 优先使用 LLM 的分析文本
        """
        risk_order = {RiskLevel.CRITICAL: 2, RiskLevel.WARNING: 1, RiskLevel.SAFE: 0}
        final_risk = max(
            rule_based["risk_level"],
            llm_based["risk_level"],
            key=lambda x: risk_order[x],
        )

        all_anomalies = list(set(
            rule_based["anomalies"] + llm_based["anomalies"] + result.anomalies
        ))

        all_recommendations = list(set(
            rule_based["recommendations"] + llm_based["recommendations"]
        ))

        result.risk_level = final_risk
        result.anomalies = all_anomalies
        result.intent_analysis = llm_based.get("analysis", rule_based["analysis"])

        return IntentAnalysisResult(
            risk_level=final_risk,
            confidence=max(rule_based["confidence"], llm_based["confidence"]),
            summary=llm_based.get("summary", rule_based["summary"]),
            analysis=llm_based.get("analysis", rule_based["analysis"]),
            anomalies=all_anomalies,
            recommendations=all_recommendations,
            raw_response=llm_based.get("raw_response"),
            prompt_tokens=llm_based.get("prompt_tokens", 0),
            completion_tokens=llm_based.get("completion_tokens", 0),
        )


class MockROMAAnalyzer(ROMAIntentAnalyzer):
    """
    Mock ROMA 分析器

    用于测试和 MVP 阶段，不需要真实的 API Key。
    """

    def __init__(self):
        """不需要 API Key"""
        self.roma_available = False
        self.atomizer = None
        self.executor = None
        self.verifier = None
        self.api_key = "mock"
        self.model = "mock"

    async def analyze(
        self,
        request: SimulationRequest,
        result: SimulationResult,
    ) -> IntentAnalysisResult:
        """Mock 分析逻辑"""
        rule_based = self._rule_based_check(request, result)

        return IntentAnalysisResult(
            risk_level=rule_based["risk_level"],
            confidence=rule_based["confidence"],
            summary=rule_based["summary"],
            analysis=rule_based["analysis"] or "Mock ROMA 分析：基于规则的快速检查",
            anomalies=rule_based["anomalies"],
            recommendations=rule_based["recommendations"],
            raw_response="mock_roma_response",
        )
