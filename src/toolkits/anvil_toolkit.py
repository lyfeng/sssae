"""
AnvilToolkit - EVM 模拟工具集

将AnvilScreener封装为符合ROMA规范的Toolkit，
提供EVM交易模拟、状态查询、trace分析等功能。
"""

import logging
from typing import Any

from ..simulation.anvil_screener import AnvilScreener, AnvilScreenerPool
from ..simulation.models import SimulationRequest, SimulationResult
from .base import BaseToolkit, ToolkitResult

logger = logging.getLogger(__name__)


class AnvilToolkit(BaseToolkit):
    """
    Anvil EVM模拟工具集

    功能：
    - 启动/停止Anvil分叉节点
    - 模拟交易执行
    - 获取交易trace
    - 查询账户余额和状态
    """

    tool_name = "anvil_simulator"
    description = (
        "EVM交易模拟工具，支持主网分叉、交易执行、trace分析。"
        "用于在TEE隔离环境中安全地模拟Web3交易。"
    )

    def _initialize(self) -> None:
        """初始化Anvil配置"""
        self.fork_url = self.config.get("fork_url", "https://eth.llamarpc.com")
        self.fork_block = self.config.get("fork_block")
        self.anvil_path = self.config.get("anvil_path", "anvil")
        self.base_port = self.config.get("base_port", 8545)
        self.timeout = self.config.get("timeout", 30)
        self.pool_size = self.config.get("pool_size", 3)

        # 初始化进程池
        self._pool: AnvilScreenerPool | None = None
        self._screener: AnvilScreener | None = None

    async def _get_screener(self) -> AnvilScreener:
        """获取或创建AnvilScreener实例"""
        if self._screener is None:
            self._screener = AnvilScreener(
                fork_url=self.fork_url,
                fork_block=self.fork_block,
                anvil_path=self.anvil_path,
                base_port=self.base_port,
                timeout=self.timeout,
            )
            if not self._screener.is_running:
                self._screener.start()
        return self._screener

    async def validate_input(self, **kwargs) -> tuple[bool, str | None]:
        """验证输入参数"""
        action = kwargs.get("action")
        if action == "simulate_tx":
            required = ["tx_from", "tx_to", "user_intent"]
            for field in required:
                if field not in kwargs:
                    return False, f"缺少必需参数: {field}"
            # 验证地址格式
            tx_from = kwargs.get("tx_from", "")
            tx_to = kwargs.get("tx_to", "")
            if not tx_from.startswith("0x") or len(tx_from) != 42:
                return False, "无效的tx_from地址格式"
            if not tx_to.startswith("0x") or len(tx_to) != 42:
                return False, "无效的tx_to地址格式"
        return True, None

    async def execute(self, action: str = "simulate_tx", **kwargs) -> ToolkitResult:
        """
        执行Anvil工具

        Args:
            action: 操作类型
                - simulate_tx: 模拟交易执行
                - get_balance: 查询余额
                - get_code: 查询合约代码
                - start: 启动Anvil节点
                - stop: 停止Anvil节点
            **kwargs: 操作参数

        Returns:
            ToolkitResult: 执行结果
        """
        handler = getattr(self, f"_handle_{action}", None)
        if handler is None:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=f"未知的操作类型: {action}",
                data={"action": action},
            )

        return await handler(**kwargs)

    async def _handle_simulate_tx(
        self,
        user_intent: str,
        tx_from: str,
        tx_to: str,
        tx_value: str = "0",
        tx_data: str = "0x",
        chain_id: int = 1,
        fork_block: int | None = None,
        **kwargs,
    ) -> ToolkitResult:
        """
        模拟交易执行

        Args:
            user_intent: 用户意图描述
            tx_from: 发起地址
            tx_to: 目标地址
            tx_value: 交易value
            tx_data: 交易calldata
            chain_id: 链ID
            fork_block: 分叉区块号

        Returns:
            ToolkitResult: 包含模拟执行结果
        """
        screener = await self._get_screener()

        # 构建模拟请求
        request = SimulationRequest(
            user_intent=user_intent,
            chain_id=chain_id,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_value=tx_value,
            tx_data=tx_data,
            fork_block=fork_block,
        )

        try:
            # 执行模拟
            result: SimulationResult = await screener.simulate(request)

            # 转换为字典格式
            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,  # 会被__call__覆盖
                error=None,
                data={
                    "transaction": {
                        "from": result.tx_from,
                        "to": result.tx_to,
                        "value": result.tx_value,
                        "data": result.tx_data,
                    },
                    "execution": {
                        "success": result.success,
                        "gas_used": result.gas_used,
                        "gas_limit": result.gas_limit,
                        "error": result.error_message,
                        "block_number": result.block_number,
                    },
                    "asset_changes": [
                        {
                            "token": c.token_symbol,
                            "address": c.token_address,
                            "before": c.balance_before,
                            "after": c.balance_after,
                            "change": c.change_amount,
                        }
                        for c in result.asset_changes
                    ],
                    "call_traces": [
                        {
                            "depth": t.depth,
                            "from": t.from_address,
                            "to": t.to_address,
                            "value": t.value,
                            "input": t.input_data[:100] + "..."
                            if len(t.input_data) > 100
                            else t.input_data,
                            "gas_used": t.gas_used,
                            "error": t.error,
                        }
                        for t in result.call_traces[:50]  # 限制trace数量
                    ],
                    "events": [
                        {
                            "address": e.address,
                            "topics": e.topics,
                            "data": e.data[:100] + "..." if len(e.data) > 100 else e.data,
                        }
                        for e in result.events
                    ],
                    "anomalies": result.anomalies,
                },
                metadata={
                    "fork_url": screener.fork_url,
                    "fork_block": screener._process_info.fork_block
                    if screener._process_info
                    else None,
                    "rpc_url": screener.rpc_url if screener.is_running else None,
                },
            )

        except Exception as e:
            logger.error(f"交易模拟失败: {e}", exc_info=True)
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=str(e),
                data={
                    "tx_from": tx_from,
                    "tx_to": tx_to,
                    "user_intent": user_intent,
                },
            )

    async def _handle_get_balance(
        self, address: str, token_address: str | None = None, **kwargs
    ) -> ToolkitResult:
        """
        查询余额

        Args:
            address: 查询的地址
            token_address: Token地址（None表示查询ETH）

        Returns:
            ToolkitResult: 余额信息
        """
        screener = await self._get_screener()

        try:
            if token_address is None or token_address == "0x" + "0" * 40:
                # 查询ETH余额
                balance = screener.w3.eth.get_balance(address)
                return ToolkitResult(
                    success=True,
                    tool_name=self.tool_name,
                    execution_time=0.0,
                    error=None,
                    data={
                        "address": address,
                        "token": "ETH",
                        "balance": str(balance),
                        "balance_ether": float(screener.w3.from_wei(balance, "ether")),
                    },
                )
            else:
                # TODO: 实现ERC20余额查询
                return ToolkitResult(
                    success=False,
                    tool_name=self.tool_name,
                    execution_time=0.0,
                    error="ERC20余额查询暂未实现",
                    data={},
                )

        except Exception as e:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=str(e),
                data={},
            )

    async def _handle_get_code(self, address: str, **kwargs) -> ToolkitResult:
        """
        查询合约代码

        Args:
            address: 合约地址

        Returns:
            ToolkitResult: 合约代码信息
        """
        screener = await self._get_screener()

        try:
            code = screener.w3.eth.get_code(address)
            is_contract = len(code) > 0

            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={
                    "address": address,
                    "is_contract": is_contract,
                    "code_length": len(code),
                    "code_hash": code.hex()[:64] if is_contract else None,
                },
            )

        except Exception as e:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=str(e),
                data={},
            )

    async def _handle_start(self, **kwargs) -> ToolkitResult:
        """启动Anvil节点"""
        try:
            screener = await self._get_screener()
            screener.start()

            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={
                    "status": "running",
                    "rpc_url": screener.rpc_url,
                    "fork_block": screener._process_info.fork_block
                    if screener._process_info
                    else None,
                },
            )

        except Exception as e:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=str(e),
                data={},
            )

    async def _handle_stop(self, **kwargs) -> ToolkitResult:
        """停止Anvil节点"""
        try:
            if self._screener:
                self._screener.stop()
                self._screener = None

            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={"status": "stopped"},
            )

        except Exception as e:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=str(e),
                data={},
            )

    def get_schema(self) -> dict[str, Any]:
        """获取工具Schema"""
        return {
            "name": self.tool_name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["simulate_tx", "get_balance", "get_code", "start", "stop"],
                        "description": "操作类型",
                    },
                    "user_intent": {
                        "type": "string",
                        "description": "用户的自然语言意图（simulate_tx必需）",
                    },
                    "tx_from": {
                        "type": "string",
                        "description": "交易发起者地址（simulate_tx必需）",
                    },
                    "tx_to": {
                        "type": "string",
                        "description": "交易目标地址（simulate_tx必需）",
                    },
                    "tx_value": {
                        "type": "string",
                        "description": "交易value（wei格式）",
                        "default": "0",
                    },
                    "tx_data": {
                        "type": "string",
                        "description": "交易calldata",
                        "default": "0x",
                    },
                    "address": {
                        "type": "string",
                        "description": "查询的地址（get_balance/get_code必需）",
                    },
                },
            },
        }

    async def cleanup(self) -> None:
        """清理资源"""
        if self._screener:
            self._screener.stop()
        if self._pool:
            await self._pool.shutdown()
