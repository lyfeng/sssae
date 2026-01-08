"""
SSSEA Agent - FastAPI Main Entry

Sentient Security Sandbox Execution Agent
基于 TEE 的 Web3 安全审计智能体
"""

import logging
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.openai_compat import (
    SIMULATE_TX_TOOL,
    ChatCompletionRequest,
    ChatCompletionResponse,
    SSSEAHandler,
)
from .config import get_settings

# =============================================================================
# Logging Configuration
# =============================================================================


def setup_logging(level: str = "INFO"):
    """配置日志"""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
    )


# =============================================================================
# Lifespan Management
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    settings = get_settings()
    setup_logging(settings.log_level)

    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("SSSEA Agent 启动中...")
    logger.info(f"环境: {'生产' if settings.is_production else '开发'}")
    logger.info(f"TEE 指纹: {settings.tee_hardware_fingerprint}")
    logger.info("=" * 60)

    # 初始化处理器
    app.state.handler = SSSEAHandler(settings)

    yield

    # 清理资源
    logger.info("SSSEA Agent 关闭中...")


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="SSSEA Agent",
    description="Sentient Security Sandbox Execution Agent - 基于 TEE 的 Web3 安全审计智能体",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Health Check
# =============================================================================


@app.get("/health")
async def health_check():
    """健康检查端点"""
    return {
        "status": "healthy",
        "service": "sssea-agent",
        "version": "0.1.0",
    }


@app.get("/")
async def root():
    """根路径"""
    return {
        "name": "SSSEA Agent",
        "description": "Sentient Security Sandbox Execution Agent",
        "version": "0.1.0",
        "endpoints": {
            "health": "/health",
            "v1_chat_completions": "/v1/chat/completions",
            "tools": "/v1/tools",
        },
    }


# =============================================================================
# OpenAI Compatible Endpoints
# =============================================================================


@app.get("/v1/models")
async def list_models():
    """列出可用模型（兼容 OpenAI API）"""
    return {
        "object": "list",
        "data": [
            {
                "id": "sssea-v1-mock",
                "object": "model",
                "created": 1704067200,
                "owned_by": "sssea",
            },
            {
                "id": "sssea-v1-enclave",
                "object": "model",
                "created": 1704067200,
                "owned_by": "sssea",
            },
        ],
    }


@app.get("/v1/tools")
async def list_tools():
    """列出可用工具"""
    return {
        "object": "list",
        "data": [SIMULATE_TX_TOOL],
    }


@app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(request: ChatCompletionRequest):
    """
    Chat Completion 端点（兼容 OpenAI API）

    这是 SSSEA 的核心接口，其他 Agent 通过此接口调用安全审计服务。

    ## 请求示例
    ```json
    {
      "model": "sssea-v1-mock",
      "messages": [
        {
          "role": "user",
          "content": "请审计以下交易：..."
        }
      ],
      "tools": [
        {
          "type": "function",
          "function": {
            "name": "simulate_tx",
            "arguments": {"user_intent": "...", "tx_from": "...", "tx_to": "..."}
          }
        }
      ]
    }
    ```

    ## 响应示例
    ```json
    {
      "id": "chatcmpl-xxx",
      "choices": [...],
      "metadata": {
        "oml_attestation": "0x...",
        "risk_level": "SAFE",
        "risk_score": 95
      }
    }
    ```
    """
    try:
        handler: SSSEAHandler = app.state.handler
        response = await handler.handle_chat_completion(request)
        return response
    except Exception as e:
        logging.getLogger(__name__).error(f"处理请求失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# SSSEA Specific Endpoints
# =============================================================================


@app.post("/api/v1/simulate")
async def simulate_transaction(request: Request):
    """
    直接模拟端点（基于 ROMA Pipeline）

    简化的 REST API，直接调用 ROMA Pipeline 进行安全审计。

    ## 请求示例
    ```json
    {
      "user_intent": "Swap 1 ETH to USDC",
      "chain_id": 1,
      "tx_from": "0x...",
      "tx_to": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
      "tx_value": "1000000000000000000",
      "tx_data": "0x..."
    }
    ```
    """
    try:
        data = await request.json()

        # 获取 ROMA Pipeline
        handler: SSSEAHandler = app.state.handler
        pipeline = handler._roma_pipeline
        if pipeline is None:
            raise HTTPException(status_code=500, detail="ROMA Pipeline is not initialized")

        # 构建交易数据
        tx_data = {
            "chain_id": data.get("chain_id", 1),
            "tx_from": data["tx_from"],
            "tx_to": data["tx_to"],
            "tx_value": data.get("tx_value", "0"),
            "tx_data": data.get("tx_data", "0x"),
        }

        # 运行 ROMA Pipeline
        result = await pipeline.run(
            user_intent=data.get("user_intent", ""),
            tx_data=tx_data,
        )

        # 返回结果
        return {
            "verdict": result.get("verdict", {}).get("risk_level", "UNKNOWN"),
            "confidence": result.get("verdict", {}).get("confidence", 0.7),
            "summary": result.get("summary", ""),
            "findings": result.get("findings", []),
            "recommendations": result.get("recommendations", []),
            "execution_steps": result.get("execution_details", {}).get("steps", []),
            "attestation": result.get("metadata", {}).get("oml_attestation"),
        }

    except Exception as e:
        logging.getLogger(__name__).error(f"模拟失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Error Handlers
# =============================================================================


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """处理值错误"""
    return JSONResponse(
        status_code=400,
        content={"error": {"message": str(exc), "type": "invalid_request_error"}},
    )


@app.exception_handler(NotImplementedError)
async def not_implemented_handler(request: Request, exc: NotImplementedError):
    """处理未实现功能"""
    return JSONResponse(
        status_code=501,
        content={"error": {"message": str(exc), "type": "not_implemented"}},
    )


# =============================================================================
# Main
# =============================================================================


def main():
    """主入口"""
    settings = get_settings()

    uvicorn.run(
        "src.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()
