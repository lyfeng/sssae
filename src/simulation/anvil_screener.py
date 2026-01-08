"""
AnvilScreener - 核心模拟引擎

基于 Foundry Anvil 实现主网分叉模拟，捕获资产变动和调用栈。
参考《一个具体的流程.md》中的实现逻辑。
"""

import asyncio
import logging
import socket
import subprocess
from datetime import datetime
from typing import Any

from web3 import Web3

from .models import (
    AnvilProcessInfo,
    AssetChange,
    CallTrace,
    EventLog,
    SimulationRequest,
    SimulationResult,
)

logger = logging.getLogger(__name__)


# ERC-20 ABI（仅包含需要的函数）
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
]


def find_free_port(start_port: int = 8545, max_attempts: int = 100) -> int:
    """查找可用端口"""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise OSError(f"无法在 {start_port}-{start_port + max_attempts} 范围内找到可用端口")


class AnvilScreener:
    """
    Anvil 模拟引擎

    核心功能：
    1. 动态启动 Anvil 分叉节点
    2. 在沙盒中执行交易
    3. 捕获资产变动和调用栈
    4. 清理进程资源
    """

    def __init__(
        self,
        fork_url: str,
        fork_block: int | None = None,
        anvil_path: str = "anvil",
        base_port: int = 8545,
        timeout: int = 30,
    ):
        """
        初始化 AnvilScreener

        Args:
            fork_url: 主网 RPC URL
            fork_block: 分叉区块号（None 为最新区块）
            anvil_path: anvil 可执行文件路径
            base_port: 起始端口
            timeout: 模拟超时时间（秒）
        """
        self.fork_url = fork_url
        self.fork_block = fork_block
        self.anvil_path = anvil_path
        self.base_port = base_port
        self.timeout = timeout

        self._process: subprocess.Popen | None = None
        self._process_info: AnvilProcessInfo | None = None
        self._w3: Web3 | None = None

    @property
    def is_running(self) -> bool:
        """检查 Anvil 进程是否运行中"""
        return self._process is not None and self._process.poll() is None

    @property
    def rpc_url(self) -> str:
        """获取 RPC URL"""
        if self._process_info is None:
            raise RuntimeError("Anvil 进程未启动")
        return self._process_info.rpc_url

    @property
    def w3(self) -> Web3:
        """获取 Web3 实例"""
        if self._w3 is None:
            raise RuntimeError("Anvil 进程未启动")
        return self._w3

    def start(self) -> AnvilProcessInfo:
        """
        启动 Anvil 分叉节点

        Returns:
            AnvilProcessInfo: 进程信息
        """
        if self.is_running:
            if self._process_info is None:
                raise RuntimeError("Process is running but process_info is None")
            return self._process_info

        port = find_free_port(self.base_port)
        rpc_url = f"http://127.0.0.1:{port}"

        # 构建 Anvil 命令
        cmd = [
            self.anvil_path,
            "--fork-url",
            self.fork_url,
            "--port",
            str(port),
            "--host",
            "127.0.0.1",
            "--chain-id",
            "31337",  # Anvil 默认 chain ID
            "--block-time",
            "0",  # 不自动挖矿
        ]

        if self.fork_block is not None:
            cmd.extend(["--fork-block-number", str(self.fork_block)])

        logger.info(f"启动 Anvil: {' '.join(cmd)}")

        # 启动进程
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # 等待进程就绪
        self._wait_for_ready(rpc_url)

        # 连接 Web3
        self._w3 = Web3(Web3.HTTPProvider(rpc_url))

        # 获取当前区块号
        if self.fork_block:
            block_number = self.fork_block
        else:
            if self._w3 is None:
                raise RuntimeError("Web3 instance is None")
            block_number = self.w3.eth.block_number

        self._process_info = AnvilProcessInfo(
            pid=self._process.pid,
            port=port,
            rpc_url=rpc_url,
            fork_url=self.fork_url,
            fork_block=block_number,
        )

        logger.info(f"Anvil 已启动: {rpc_url} (PID: {self._process.pid})")
        return self._process_info

    def _wait_for_ready(self, rpc_url: str, max_wait: int = 10) -> None:
        """等待 Anvil 就绪"""
        import time

        import httpx

        start = datetime.now()

        while (datetime.now() - start).seconds < max_wait:
            try:
                response = httpx.post(
                    rpc_url,
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_blockNumber",
                        "params": [],
                        "id": 1,
                    },
                    timeout=1,
                )
                if response.status_code == 200:
                    logger.debug("Anvil 就绪")
                    return
            except Exception:
                pass
            time.sleep(0.1)

        raise RuntimeError(f"Anvil 启动超时: {rpc_url}")

    def stop(self) -> None:
        """停止 Anvil 进程"""
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
            logger.info("Anvil 进程已停止")

        self._process_info = None
        self._w3 = None

    def __enter__(self):
        """上下文管理器入口"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出"""
        self.stop()

    async def simulate(self, request: SimulationRequest) -> SimulationResult:
        """
        执行交易模拟

        Args:
            request: 模拟请求

        Returns:
            SimulationResult: 模拟结果
        """
        if not self.is_running:
            self.start()

        # 记录执行前状态
        snapshot_id = self.w3.eth.snapshot()

        try:
            # 获取执行前余额
            before_balances = await self._get_balances(
                request.tx_from, request.tx_to, request.tx_value
            )

            # 执行交易
            tx_hash, receipt, trace = await self._execute_transaction(request)

            # 获取执行后余额
            after_balances = await self._get_balances(
                request.tx_from, request.tx_to, request.tx_value
            )

            # 计算资产变动
            asset_changes = self._calculate_asset_changes(before_balances, after_balances)

            # 解析调用栈
            call_traces = self._parse_traces(trace)

            # 解析事件
            events = self._parse_events(receipt)

            # 构建结果
            result = SimulationResult(
                chain_id=request.chain_id,
                block_number=self._process_info.fork_block if self._process_info else 0,
                tx_from=request.tx_from,
                tx_to=request.tx_to,
                tx_value=request.tx_value,
                tx_data=request.tx_data,
                success=receipt["status"] == 1,
                gas_used=receipt.get("gasUsed", 0),
                gas_limit=request.gas_limit,
                asset_changes=asset_changes,
                call_traces=call_traces,
                events=events,
                error_message=None,
                intent_analysis=None,
            )

            # 检查异常行为
            result.anomalies = self._detect_anomalies(request, result)

            return result

        finally:
            # 恢复快照
            self.w3.eth.revert(snapshot_id)

    async def _get_balances(self, *addresses: str) -> dict[tuple[str, str], int]:
        """
        获取地址的余额

        Returns:
            Dict[(address, token_address), balance]
        """
        balances = {}

        for addr in addresses:
            if not addr or addr == "0x" + "0" * 40:
                continue

            addr = Web3.to_checksum_address(addr)

            # ETH 余额
            balances[(addr, "0x" + "0" * 40)] = self.w3.eth.get_balance(addr)

            # TODO: 在实际执行中，需要根据 event logs 获取涉及的 ERC20 token
            # 这里简化处理，只处理 ETH

        return balances

    def _calculate_asset_changes(
        self,
        before: dict[tuple[str, str], int],
        after: dict[tuple[str, str], int],
    ) -> list[AssetChange]:
        """计算资产变动"""
        changes = []
        all_keys = set(before.keys()) | set(after.keys())

        for addr, token_addr in all_keys:
            before_balance = before.get((addr, token_addr), 0)
            after_balance = after.get((addr, token_addr), 0)
            change = after_balance - before_balance

            if change != 0:
                token_symbol = "ETH" if token_addr == "0x" + "0" * 40 else "UNKNOWN"
                changes.append(
                    AssetChange(
                        token_address=token_addr,
                        token_symbol=token_symbol,
                        token_decimals=18,
                        balance_before=str(before_balance),
                        balance_after=str(after_balance),
                        change_amount=str(change),
                        change_usd=None,
                    )
                )

        return changes

    async def _execute_transaction(
        self, request: SimulationRequest
    ) -> tuple[str, dict[str, Any], Any]:
        """
        执行交易

        Returns:
            (tx_hash, receipt, debug_trace)
        """
        # 构建交易
        tx = {
            "from": request.tx_from,
            "to": request.tx_to,
            "value": request.tx_value,
            "data": request.tx_data,
            "gas": request.gas_limit,
            "chainId": self.w3.eth.chain_id,
        }

        # 获取 nonce
        tx["nonce"] = self.w3.eth.get_transaction_count(request.tx_from)

        # 使用Impersonated Account发送交易
        self.w3.provider.make_request("anvil_impersonateAccount", [request.tx_from])

        try:
            # 发送交易
            tx_hash = self.w3.eth.send_transaction(tx)

            # 等待交易确认
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=self.timeout)

            # 获取 trace（如果支持）
            trace = None
            try:
                trace = self.w3.provider.make_request(
                    "debug_traceTransaction",
                    [tx_hash.hex(), {"trace": []}],
                )
            except Exception as e:
                logger.debug(f"获取 trace 失败: {e}")

            return tx_hash.hex(), receipt, trace

        finally:
            self.w3.provider.make_request("anvil_stopImpersonatingAccount", [request.tx_from])

    def _parse_traces(self, trace_result: dict[str, Any]) -> list[CallTrace]:
        """解析调用跟踪"""
        traces = []

        if not trace_result or "result" not in trace_result:
            return traces

        result = trace_result["result"]

        # 处理 struct logs 格式
        if "structLogs" in result:
            for log in result["structLogs"]:
                traces.append(
                    CallTrace(
                        depth=log.get("depth", 0),
                        from_address=log.get("from", ""),
                        to_address=log.get("to", ""),
                        value=log.get("value", "0"),
                        input_data=log.get("input", "0x"),
                        output_data=log.get("output", "0x"),
                        gas_used=log.get("gasCost", 0),
                        error=log.get("error"),
                    )
                )

        return traces

    def _parse_events(self, receipt: dict[str, Any]) -> list[EventLog]:
        """解析事件日志"""
        events = []

        for log in receipt.get("logs", []):
            events.append(
                EventLog(
                    address=log.get("address", ""),
                    topics=[
                        log.get("topic0", ""),
                        log.get("topic1", ""),
                        log.get("topic2", ""),
                        log.get("topic3", ""),
                    ],
                    data=log.get("data", "0x"),
                    log_index=log.get("logIndex", 0),
                )
            )

        return events

    def _detect_anomalies(self, request: SimulationRequest, result: SimulationResult) -> list[str]:
        """
        检测异常行为

        检查项：
        1. 交易是否失败
        2. 是否有异常的授权操作
        3. 资产变动是否与意图严重不符
        """
        anomalies = []

        # 检查交易失败
        if not result.success:
            anomalies.append(f"交易执行失败: {result.error_message or 'Unknown error'}")

        # 检查是否有大额 ETH 转出（非预期）
        for change in result.asset_changes:
            if change.token_symbol == "ETH":
                change_int = int(change.change_amount)
                # 如果转出的 ETH 超过 tx_value
                if change_int < -int(request.tx_value):
                    anomalies.append(f"检测到异常 ETH 转出: {abs(change_int) / 1e18:.4f} ETH")

        # 检查调用深度（可能是重入攻击）
        if result.call_traces:
            max_depth = max(t.depth for t in result.call_traces)
            if max_depth > 20:
                anomalies.append(f"调用深度过深 ({max_depth})，可能存在重入风险")

        return anomalies


class AnvilScreenerPool:
    """
    Anvil 进程池

    管理多个 Anvil 实例，支持并发模拟。
    """

    def __init__(
        self,
        fork_url: str,
        pool_size: int = 3,
        anvil_path: str = "anvil",
        base_port: int = 8545,
    ):
        self.fork_url = fork_url
        self.pool_size = pool_size
        self.anvil_path = anvil_path
        self.base_port = base_port
        self._pool: list[AnvilScreener] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> AnvilScreener:
        """获取一个空闲的 Anvil 实例"""
        async with self._lock:
            if not self._pool:
                screener = AnvilScreener(
                    fork_url=self.fork_url,
                    anvil_path=self.anvil_path,
                    base_port=self.base_port + len(self._pool),
                )
                screener.start()
                self._pool.append(screener)
            return self._pool[0]

    async def release(self, screener: AnvilScreener) -> None:
        """释放 Anvil 实例"""
        # MVP 阶段简单实现，不进行复杂的管理
        pass

    async def shutdown(self) -> None:
        """关闭所有实例"""
        for screener in self._pool:
            screener.stop()
        self._pool.clear()
