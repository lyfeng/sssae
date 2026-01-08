"""
Simulation Engine Data Models

定义模拟执行过程中使用的数据结构。
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator


class ChainId(int, Enum):
    """支持的链 ID"""

    ETHEREUM = 1
    SEPOLIA = 11155111
    ARBITRUM = 42161
    POLYGON = 137


class RiskLevel(str, Enum):
    """风险等级"""

    SAFE = "SAFE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AssetChange(BaseModel):
    """单个资产变动"""

    token_address: str = Field(..., description="Token 地址（ETH 为 address(0)）")
    token_symbol: str = Field(..., description="Token 符号")
    token_decimals: int = Field(default=18, description="Token 精度")
    balance_before: str = Field(..., description="执行前余额（wei）")
    balance_after: str = Field(..., description="执行后余额（wei）")
    change_amount: str = Field(..., description="变动金额（带符号，正为增加，负为减少）")
    change_usd: float | None = Field(None, description="变动金额估算（USD）")

    @field_serializer("balance_before", "balance_after", "change_amount")
    def serialize_str(self, value: str) -> str:
        return str(value)


class CallTrace(BaseModel):
    """单个调用跟踪"""

    depth: int = Field(..., description="调用深度")
    from_address: str = Field(..., description="调用者地址")
    to_address: str = Field(..., description="被调用地址")
    value: str = Field(default="0", description="转移的 ETH 数量（wei）")
    input_data: str = Field(..., description="调用数据（calldata）")
    output_data: str = Field(default="0x", description="返回数据")
    gas_used: int = Field(default=0, description="消耗的 gas")
    error: str | None = Field(None, description="错误信息（如有）")


class EventLog(BaseModel):
    """事件日志"""

    address: str = Field(..., description="合约地址")
    topics: list[str] = Field(..., description="事件主题")
    data: str = Field(..., description="事件数据")
    log_index: int = Field(..., description="日志索引")


class SimulationResult(BaseModel):
    """模拟执行结果"""

    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat(),
        }
    )

    # 元数据
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    chain_id: int = Field(..., description="链 ID")
    block_number: int = Field(..., description="分叉区块号")

    # 交易信息
    tx_from: str = Field(..., description="交易发起者")
    tx_to: str = Field(..., description="交易目标地址")
    tx_value: str = Field(default="0", description="交易 value（wei）")
    tx_data: str = Field(default="0x", description="交易 calldata")

    # 执行状态
    success: bool = Field(..., description="交易是否成功")
    gas_used: int = Field(default=0, description="消耗的 gas")
    gas_limit: int = Field(default=0, description="gas 限制")
    error_message: str | None = Field(None, description="失败原因")

    # 资产变动
    asset_changes: list[AssetChange] = Field(default_factory=list, description="所有地址的资产变动")

    # 调用跟踪
    call_traces: list[CallTrace] = Field(default_factory=list, description="完整调用栈")

    # 事件日志
    events: list[EventLog] = Field(default_factory=list, description="触发的事件")

    # 意图审计（由 Reasoning Layer 填充）
    risk_level: RiskLevel = Field(default=RiskLevel.SAFE)
    intent_analysis: str | None = Field(None, description="意图分析结果")
    anomalies: list[str] = Field(default_factory=list, description="检测到的异常行为")


class AnvilProcessInfo(BaseModel):
    """Anvil 进程信息"""

    pid: int = Field(..., description="进程 ID")
    port: int = Field(..., description="监听端口")
    rpc_url: str = Field(..., description="RPC URL")
    fork_url: str = Field(..., description="分叉源 URL")
    fork_block: int = Field(..., description="分叉区块号")
    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SimulationRequest(BaseModel):
    """模拟请求"""

    # 用户意图
    user_intent: str = Field(..., min_length=1, description="用户的自然语言意图")

    # 交易数据
    chain_id: int = Field(default=1, description="链 ID")
    tx_from: str = Field(..., description="交易发起者地址")
    tx_to: str = Field(..., description="交易目标地址")
    tx_value: str = Field(default="0", description="交易 value（wei）")
    tx_data: str = Field(default="0x", description="交易 calldata")

    # 模拟选项
    fork_block: int | None = Field(None, description="分叉区块号（默认最新）")
    gas_limit: int = Field(default=30_000_000, description="gas 限制")
    trace_depth: int = Field(default=10, description="最大跟踪深度")

    # 额外上下文
    context: dict[str, Any] = Field(default_factory=dict, description="额外的上下文信息")

    @field_validator("tx_from", "tx_to")
    @classmethod
    def validate_address(cls, v: str) -> str:
        """验证以太坊地址格式"""
        if not v.startswith("0x") or len(v) != 42:
            raise ValueError(f"无效的以太坊地址: {v}")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError(f"无效的以太坊地址: {v}")
        return v

    @field_validator("tx_value")
    @classmethod
    def validate_tx_value(cls, v: str) -> str:
        """验证 tx_value 是有效的十六进制或十进制字符串"""
        if v.startswith("0x"):
            try:
                int(v, 16)
            except ValueError:
                raise ValueError(f"无效的 tx_value: {v}")
        else:
            try:
                int(v)
            except ValueError:
                raise ValueError(f"无效的 tx_value: {v}")
        return v
