"""
OpenAI Chat Completion Compatible API

实现符合 OpenAI API 标准的接口，使 SSSEA 能被其他 Agent 通过标准 SDK 调用。
基于 ROMA Pipeline 进行完整的递归推理分析。
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
            "基于ROMA框架进行递归推理分析。"
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

    使用 ROMA Pipeline 进行完整的递归推理分析。
    """

    def __init__(self, settings: Optional[Any] = None):
        self.settings = settings or get_settings()
        self._roma_pipeline = None
        self._initialize_pipeline()

    def _initialize_pipeline(self) -> None:
        """初始化 ROMA Pipeline"""
        try:
            from ..agents import SSSEAPipeline
            from ..config.roma_config import load_profile

            # 根据环境加载配置
            profile = "dev" if self.settings.api_reload else "prod"
            config = load_profile(profile)
            self._roma_pipeline = SSSEAPipeline(config)
            logger.info(f"ROMA Pipeline initialized with profile: {profile}")

        except ImportError as e:
            logger.error(f"Failed to import ROMA Pipeline: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize ROMA Pipeline: {e}")
            raise

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

        # 返回普通聊天响应
        return await self._handle_chat(request)

    async def _handle_simulation(
        self,
        request: ChatCompletionRequest,
    ) -> ChatCompletionResponse:
        """处理模拟请求"""
        # 1. 提取意图和交易数据
        intent, tx_params = self._extract_transaction_params(request)

        # 2. 运行 ROMA Pipeline
        return await self._handle_with_pipeline(request, intent, tx_params)

    async def _handle_with_pipeline(
        self,
        request: ChatCompletionRequest,
        intent: str,
        tx_params: Dict[str, Any],
    ) -> ChatCompletionResponse:
        """使用ROMA Pipeline处理请求"""
        try:
            # 运行ROMA Pipeline
            result = await self._roma_pipeline.run(
                user_intent=intent,
                tx_data=tx_params,
            )

            # 构建响应
            return self._build_response(request, intent, tx_params, result)

        except Exception as e:
            logger.error(f"ROMA Pipeline执行失败: {e}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"模拟执行失败: {str(e)}"
            )

    def _build_response(
        self,
        request: ChatCompletionRequest,
        intent: str,
        tx_params: Dict[str, Any],
        result: Dict[str, Any],
    ) -> ChatCompletionResponse:
        """构建响应"""
        verdict = result.get("verdict", {})
        tool_call_id = f"call_{uuid.uuid4().hex[:24]}"

        # 格式化响应消息
        content = self._format_result_message(result)

        # 生成证明
        attestation = generate_attestation_metadata(
            simulation_result={
                "risk_level": verdict.get("risk_level", "UNKNOWN"),
                "confidence": verdict.get("confidence", 0.7),
            },
            model_name=request.model,
        )

        return ChatCompletionResponse(
            id=f"chatcmpl-{uuid.uuid4().hex[:28]}",
            created=int(time.time()),
            model=request.model,
            choices=[{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
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
                prompt_tokens=100,
                completion_tokens=len(content) // 4,
                total_tokens=100 + len(content) // 4,
            ),
            system_fingerprint=attestation["system_fingerprint"],
            metadata={
                "oml_attestation": attestation["oml_attestation"],
                "risk_level": verdict.get("risk_level", "UNKNOWN"),
                "risk_score": int(verdict.get("confidence", 0.7) * 100),
                "pipeline_used": True,
                "execution_steps": result.get("execution_details", {}).get("steps", []),
            },
        )

    def _format_result_message(self, result: Dict[str, Any]) -> str:
        """格式化结果消息"""
        verdict = result.get("verdict", {})
        risk_level = verdict.get("risk_level", "UNKNOWN")

        risk_emoji = {
            "SAFE": "✅",
            "WARNING": "⚠️",
            "CRITICAL": "🚨",
        }

        emoji = risk_emoji.get(risk_level, "")
        lines = [
            f"{emoji} **安全审计结果**: {risk_level}",
            f"**置信度**: {verdict.get('confidence', 0.7):.0%}",
            "",
            f"**摘要**: {result.get('summary', '')}",
        ]

        findings = result.get("findings", [])
        if findings:
            lines.extend(["", "**检测到的问题**:"])
            lines.extend(f"- {f}" for f in findings)

        recommendations = result.get("recommendations", [])
        if recommendations:
            lines.extend(["", "**建议**:"])
            lines.extend(f"- {r}" for r in recommendations[:5])

        return "\n".join(lines)

    async def _handle_chat(
        self,
        request: ChatCompletionRequest,
    ) -> ChatCompletionResponse:
        """处理普通聊天请求"""
        response = ChatCompletionResponse(
            id=f"chatcmpl-{uuid.uuid4().hex[:28]}",
            created=int(time.time()),
            model=request.model,
            choices=[{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": (
                        "我是 SSSEA 安全审计 Agent，基于 ROMA 框架进行递归推理分析。"
                        "请使用 simulate_tx 工具来审计 Web3 交易。"
                    ),
                },
                "finish_reason": "stop",
            }],
            usage=Usage(
                prompt_tokens=10,
                completion_tokens=25,
                total_tokens=35,
            ),
            system_fingerprint=f"sssea-roma@{uuid.uuid4().hex[:8]}",
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
