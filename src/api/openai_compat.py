"""
OpenAI Chat Completion Compatible API

实现符合 OpenAI API 标准的接口，使 SSSEA 能被其他 Agent 通过标准 SDK 调用。
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

from ..simulation.models import SimulationRequest, SimulationResult
from ..simulation.anvil_screener import AnvilScreener
from ..reasoning import (
    MockIntentAnalyzer,
    IntentAnalyzer,
    ROMAIntentAnalyzer,
    MockROMAAnalyzer,
)
from ..attestation.mock_quote import generate_attestation_metadata
from ..config import get_settings


logger = logging.getLogger(__name__)


# =============================================================================
# OpenAI API Request/Response Models
# =============================================================================


class ChatMessage(BaseModel):
    """Chat 消息"""
    role: str
    content: str
    name: Optional[str] = None
    tool_calls: Optional[List[Any]] = None


class ToolFunction(BaseModel):
    """Tool 函数定义"""
    name: str
    arguments: str  # JSON string


class ToolCall(BaseModel):
    """Tool 调用"""
    id: str
    type: str = "function"
    function: ToolFunction


class Tool(BaseModel):
    """Tool 定义"""
    type: str = "function"
    function: Dict[str, Any]


class ToolChoice(BaseModel):
    """Tool 选择"""
    type: str = "function"
    function: Dict[str, str]


class ChatCompletionRequest(BaseModel):
    """Chat Completion 请求"""
    model: str
    messages: List[ChatMessage]
    tools: Optional[List[Tool]] = None
    tool_choice: Optional[str | ToolChoice] = "auto"
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False


class Usage(BaseModel):
    """Token 使用统计"""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatCompletionResponse(BaseModel):
    """Chat Completion 响应"""
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[Dict[str, Any]]
    usage: Usage
    system_fingerprint: Optional[str] = None

    # SSSEA 扩展字段
    metadata: Optional[Dict[str, Any]] = None


class SimulationToolArgs(BaseModel):
    """simulate_tx 工具参数"""
    user_intent: str
    chain_id: int = 1
    tx_from: str
    tx_to: str
    tx_value: str = "0"
    tx_data: str = "0x"


# =============================================================================
# SSSEA Tool Definitions
# =============================================================================

SIMULATE_TX_TOOL = {
    "type": "function",
    "function": {
        "name": "simulate_tx",
        "description": (
            "在 TEE 隔离沙盒中模拟 Web3 交易执行，并进行意图对齐审计。"
            "返回详细的资产变动、风险评级和 OML 证明。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "user_intent": {
                    "type": "string",
                    "description": "用户的自然语言意图，如 'Swap 1 ETH to USDC, slippage 0.5%'",
                },
                "chain_id": {
                    "type": "integer",
                    "description": "链 ID，默认为以太坊主网 (1)",
                    "default": 1,
                },
                "tx_from": {
                    "type": "string",
                    "description": "交易发起者地址",
                },
                "tx_to": {
                    "type": "string",
                    "description": "交易目标地址",
                },
                "tx_value": {
                    "type": "string",
                    "description": "交易 value（wei 格式）",
                    "default": "0",
                },
                "tx_data": {
                    "type": "string",
                    "description": "交易 calldata",
                    "default": "0x",
                },
            },
            "required": ["user_intent", "tx_from", "tx_to"],
        },
    },
}


# =============================================================================
# API Handler
# =============================================================================

class SSSEAHandler:
    """
    SSSEA API 处理器

    处理 OpenAI 兼容的 Chat Completion 请求。
    """

    def __init__(self, settings: Optional[Any] = None):
        self.settings = settings or get_settings()
        self.analyzer = self._create_analyzer()
        self._screener: Optional[AnvilScreener] = None

    def _create_analyzer(self) -> Any:
        """
        根据配置创建推理分析器

        支持的推理引擎：
        - "roma": 使用 ROMA 递归推理框架
        - "openai": 直接使用 OpenAI API
        - "mock": 使用 Mock 分析器（测试用）
        """
        engine = self.settings.reasoning_engine.lower()

        if engine == "roma":
            # 尝试使用 ROMA
            api_key = self.settings.roma_api_key or self.settings.openai_api_key
            if api_key:
                logger.info("Using ROMAIntentAnalyzer")
                return ROMAIntentAnalyzer(
                    api_key=api_key,
                    base_url=self.settings.openai_base_url,
                    model=self.settings.roma_model,
                    provider=self.settings.roma_provider,
                )
            else:
                logger.warning("ROMA API key not configured, using MockROMAAnalyzer")
                return MockROMAAnalyzer()

        elif engine == "openai":
            # 使用传统 OpenAI
            if self.settings.openai_api_key:
                logger.info(f"Using IntentAnalyzer with model: {self.settings.openai_model}")
                return IntentAnalyzer(
                    api_key=self.settings.openai_api_key,
                    base_url=self.settings.openai_base_url,
                    model=self.settings.openai_model,
                )
            else:
                logger.warning("OpenAI API key not configured, using MockIntentAnalyzer")
                return MockIntentAnalyzer()

        else:  # engine == "mock" or unknown
            logger.info("Using MockROMAAnalyzer for testing")
            return MockROMAAnalyzer()

    async def handle_chat_completion(
        self,
        request: ChatCompletionRequest,
    ) -> ChatCompletionResponse:
        """
        处理 Chat Completion 请求

        Args:
            request: Chat Completion 请求

        Returns:
            ChatCompletionResponse: 响应
        """
        # 检查是否请求了 simulate_tx 工具
        if request.tools and any(
            t.function.get("name") == "simulate_tx"
            for t in request.tools
        ):
            return await self._handle_simulation(request)

        # 如果没有请求工具，返回普通聊天响应
        return await self._handle_chat(request)

    async def _handle_simulation(
        self,
        request: ChatCompletionRequest,
    ) -> ChatCompletionResponse:
        """
        处理模拟请求

        1. 解析用户消息中的意图和交易数据
        2. 调用 AnvilScreener 执行模拟
        3. 调用 IntentAnalyzer 进行意图审计
        4. 返回带 OML 证明的响应
        """
        # 1. 提取意图和交易数据
        intent, tx_params = self._extract_transaction_params(request)

        # 2. 构建模拟请求
        sim_request = SimulationRequest(
            user_intent=intent,
            chain_id=tx_params.get("chain_id", 1),
            tx_from=tx_params["tx_from"],
            tx_to=tx_params["tx_to"],
            tx_value=tx_params.get("tx_value", "0"),
            tx_data=tx_params.get("tx_data", "0x"),
        )

        # 3. 执行模拟（MVP 阶段使用 Mock 结果）
        sim_result = await self._run_simulation(sim_request)

        # 4. 意图分析
        analysis = await self.analyzer.analyze(sim_request, sim_result)

        # 5. 生成 OML 证明
        attestation = generate_attestation_metadata(
            simulation_result={
                "risk_level": analysis.risk_level.value,
                "confidence": analysis.confidence,
                "anomalies": analysis.anomalies,
            },
            model_name=request.model,
        )

        # 6. 构建 Tool Call 响应
        tool_call_id = f"call_{uuid.uuid4().hex[:24]}"
        result_data = {
            "verdict": analysis.risk_level.value,
            "confidence": analysis.confidence,
            "summary": analysis.summary,
            "analysis": analysis.analysis,
            "asset_changes": [
                {
                    "token": c.token_symbol,
                    "amount": c.change_amount,
                }
                for c in sim_result.asset_changes
            ],
            "anomalies": analysis.anomalies,
            "recommendations": analysis.recommendations,
            "gas_used": sim_result.gas_used,
        }

        response = ChatCompletionResponse(
            id=f"chatcmpl-{uuid.uuid4().hex[:28]}",
            created=int(time.time()),
            model=request.model,
            choices=[{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": self._format_response_message(analysis, sim_result),
                    "tool_calls": [{
                        "id": tool_call_id,
                        "type": "function",
                        "function": {
                            "name": "simulate_tx",
                            "arguments": json.dumps(tx_params),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            usage=Usage(
                prompt_tokens=100,  # Mock
                completion_tokens=len(analysis.analysis) // 4,
                total_tokens=100 + len(analysis.analysis) // 4,
            ),
            system_fingerprint=attestation["system_fingerprint"],
            metadata={
                "oml_attestation": attestation["oml_attestation"],
                "risk_level": analysis.risk_level.value,
                "risk_score": int(analysis.confidence * 100),
                "asset_impact": {
                    c.token_symbol: c.change_amount
                    for c in sim_result.asset_changes
                },
            },
        )

        return response

    async def _handle_chat(
        self,
        request: ChatCompletionRequest,
    ) -> ChatCompletionResponse:
        """处理普通聊天请求"""
        last_message = request.messages[-1].content if request.messages else ""

        response = ChatCompletionResponse(
            id=f"chatcmpl-{uuid.uuid4().hex[:28]}",
            created=int(time.time()),
            model=request.model,
            choices=[{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": (
                        "我是 SSSEA 安全审计 Agent。"
                        "请使用 simulate_tx 工具来审计 Web3 交易。"
                    ),
                },
                "finish_reason": "stop",
            }],
            usage=Usage(
                prompt_tokens=10,
                completion_tokens=20,
                total_tokens=30,
            ),
            system_fingerprint=f"sssea@mock_{uuid.uuid4().hex[:8]}",
        )

        return response

    def _extract_transaction_params(
        self,
        request: ChatCompletionRequest,
    ) -> tuple[str, Dict[str, Any]]:
        """
        从请求中提取交易参数

        优先级：
        1. tool_calls 中的参数
        2. 用户消息中的 JSON
        3. 消息文本解析
        """
        # 检查最后一条消息是否有 tool_calls
        for msg in reversed(request.messages):
            if msg.tool_calls:
                for call in msg.tool_calls:
                    if call.get("function", {}).get("name") == "simulate_tx":
                        args = json.loads(call["function"]["arguments"])
                        return args.get("user_intent", ""), args

        # 尝试从最后一条消息解析 JSON
        last_message = request.messages[-1]
        try:
            data = json.loads(last_message.content)
            if "tx_from" in data and "tx_to" in data:
                return data.get("user_intent", ""), data
        except json.JSONDecodeError:
            pass

        # 默认返回示例
        return "请审计此交易", {
            "chain_id": 1,
            "tx_from": "0x" + "0" * 40,
            "tx_to": "0x" + "0" * 40,
            "tx_value": "0",
            "tx_data": "0x",
        }

    async def _run_simulation(
        self,
        request: SimulationRequest,
    ) -> SimulationResult:
        """
        运行交易模拟

        MVP 阶段：返回 Mock 结果
        生产环境：使用真实的 AnvilScreener
        """
        # MVP 阶段返回 Mock 结果
        return SimulationResult(
            chain_id=request.chain_id,
            block_number=19_000_000,
            tx_from=request.tx_from,
            tx_to=request.tx_to,
            tx_value=request.tx_value,
            tx_data=request.tx_data,
            success=True,
            gas_used=150_000,
            asset_changes=[
                # Mock: 假设是一个成功的 swap
                # 实际环境会从 Anvil 获取真实数据
            ],
        )

    def _format_response_message(
        self,
        analysis: Any,
        result: SimulationResult,
    ) -> str:
        """格式化响应消息"""
        risk_emoji = {
            "SAFE": "✅",
            "WARNING": "⚠️",
            "CRITICAL": "🚨",
        }

        emoji = risk_emoji.get(analysis.risk_level.value, "")
        lines = [
            f"{emoji} **安全审计结果**: {analysis.risk_level.value}",
            f"**置信度**: {analysis.confidence:.0%}",
            "",
            f"**摘要**: {analysis.summary}",
        ]

        if analysis.anomalies:
            lines.extend(["", "**检测到的问题**:"])
            lines.extend(f"- {a}" for a in analysis.anomalies)

        if analysis.recommendations:
            lines.extend(["", "**建议**:"])
            lines.extend(f"- {r}" for r in analysis.recommendations)

        return "\n".join(lines)


# =============================================================================
# Helper Functions
# =============================================================================

def create_chat_completion_response(
    model: str,
    content: str,
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> ChatCompletionResponse:
    """创建 Chat Completion 响应的便捷函数"""
    return ChatCompletionResponse(
        id=f"chatcmpl-{uuid.uuid4().hex[:28]}",
        created=int(time.time()),
        model=model,
        choices=[{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content,
                **({"tool_calls": tool_calls} if tool_calls else {}),
            },
            "finish_reason": "tool_calls" if tool_calls else "stop",
        }],
        usage=Usage(
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
        ),
        metadata=metadata,
    )
