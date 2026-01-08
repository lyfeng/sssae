"""
ForensicsToolkit - 取证分析工具集

提供交易回放、异常检测、trace分析等取证功能。
"""

import logging
from datetime import datetime
from typing import Any

from .base import BaseToolkit, ToolkitResult

logger = logging.getLogger(__name__)


# 危险函数签名库
DANGEROUS_SELECTORS = {
    # 授权相关
    "0x095ea7b3": "approve",
    "0xd505accf": "permit",
    # 所有权转移
    "0xf2fde38b": "transferOwnership",
    "0xa9059cbb": "transfer",
    "0x23b872dd": "transferFrom",
    # 多签相关
    "0x69d2809b": "confirmTransaction",
    "0x8456cb59": "submitTransaction",
    # 委托
    "0xdd62ed3e": "allowance",
    # 升险操作
    "0x52ef6b2c": "setSlippage",
    "0x1ae4388": "delegate",
}

# 已知攻击模式
ATTACK_PATTERNS = {
    "reentrancy": {
        "signatures": ["call", "delegatecall", "staticcall"],
        "indicators": ["深度调用", "外部调用后余额变化"],
    },
    "flashloan": {
        "signatures": ["flashLoan", "executeOperation"],
        "indicators": ["无抵押借贷", "闪电贷回调"],
    },
    "approval_max": {
        "signatures": ["approve"],
        "indicators": ["无限授权", "0xffffffffffffffff"],
    },
    "honeypot": {
        "signatures": ["transfer"],
        "indicators": ["无法卖出", "交易限制"],
    },
    "drain": {
        "signatures": ["withdraw", "sweep"],
        "indicators": ["余额归零", "资金抽离"],
    },
}


class ForensicsToolkit(BaseToolkit):
    """
    取证分析工具集

    功能：
    - 分析交易trace
    - 检测攻击模式
    - 回放交易
    - 生成安全报告
    """

    tool_name = "forensics_analyzer"
    description = (
        "交易取证分析工具，用于检测攻击模式、分析调用链、识别异常行为，生成详细的安全报告。"
    )

    def _initialize(self) -> None:
        """初始化配置"""
        self.max_trace_depth = self.config.get("max_trace_depth", 50)
        self.enable_ml_detection = self.config.get("enable_ml_detection", False)

    async def validate_input(self, **kwargs) -> tuple[bool, str | None]:
        """验证输入参数"""
        action = kwargs.get("action")
        if action in ["analyze_trace", "detect_attack"]:
            if "trace" not in kwargs and "call_traces" not in kwargs:
                return False, "缺少trace或call_traces参数"
        return True, None

    async def execute(self, action: str = "analyze_trace", **kwargs) -> ToolkitResult:
        """
        执行取证分析

        Args:
            action: 操作类型
                - analyze_trace: 分析交易trace
                - detect_attack: 检测攻击模式
                - check_risk_patterns: 检查风险模式
                - replay_analysis: 回放分析
                - generate_report: 生成安全报告
            **kwargs: 分析参数

        Returns:
            ToolkitResult: 分析结果
        """
        handler = getattr(self, f"_handle_{action}", None)
        if handler is None:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=f"未知的操作类型: {action}",
            )

        return await handler(**kwargs)

    async def _handle_analyze_trace(
        self,
        call_traces: list[dict[str, Any]],
        tx_from: str,
        tx_to: str,
        tx_value: str = "0",
        **kwargs,
    ) -> ToolkitResult:
        """
        分析交易trace

        Args:
            call_traces: 调用trace列表
            tx_from: 发起地址
            tx_to: 目标地址
            tx_value: 交易value

        Returns:
            ToolkitResult: trace分析结果
        """
        if not call_traces:
            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={
                    "summary": "无调用trace",
                    "call_count": 0,
                    "max_depth": 0,
                    "findings": [],
                },
            )

        # 统计调用信息
        call_count = len(call_traces)
        max_depth = max((t.get("depth", 0) for t in call_traces), default=0)

        # 分析调用链
        call_chain = self._analyze_call_chain(call_traces)

        # 检测危险函数调用
        dangerous_calls = self._detect_dangerous_calls(call_traces)

        # 分析ETH流向
        eth_flows = self._analyze_eth_flows(call_traces, tx_from)

        # 检测重入风险
        reentrancy_risk = self._detect_reentrancy(call_traces)

        # 检测delegatecall
        delegatecall_targets = self._detect_delegatecall(call_traces)

        # 生成发现列表
        findings = []

        if max_depth > 20:
            findings.append(
                {
                    "severity": "warning",
                    "type": "deep_call_stack",
                    "message": f"调用深度过深({max_depth})，可能存在递归或重入风险",
                }
            )

        if dangerous_calls:
            findings.append(
                {
                    "severity": "warning",
                    "type": "dangerous_function",
                    "message": f"检测到{len(dangerous_calls)}个危险函数调用",
                    "calls": dangerous_calls[:5],
                }
            )

        if reentrancy_risk:
            findings.append(
                {
                    "severity": "high",
                    "type": "reentrancy",
                    "message": "检测到可能的重入攻击模式",
                    "details": reentrancy_risk,
                }
            )

        if delegatecall_targets:
            findings.append(
                {
                    "severity": "high",
                    "type": "delegatecall",
                    "message": f"检测到{len(delegatecall_targets)}个delegatecall调用",
                    "targets": delegatecall_targets,
                }
            )

        return ToolkitResult(
            success=True,
            tool_name=self.tool_name,
            execution_time=0.0,
            error=None,
            data={
                "summary": f"分析完成: {call_count}个调用, 最大深度{max_depth}",
                "call_count": call_count,
                "max_depth": max_depth,
                "call_chain": call_chain[:20],  # 限制长度
                "dangerous_calls": dangerous_calls,
                "eth_flows": eth_flows,
                "findings": findings,
            },
        )

    async def _handle_detect_attack(
        self,
        call_traces: list[dict[str, Any]],
        asset_changes: list[dict[str, Any]],
        user_intent: str,
        **kwargs,
    ) -> ToolkitResult:
        """
        检测攻击模式

        Args:
            call_traces: 调用trace
            asset_changes: 资产变动
            user_intent: 用户意图

        Returns:
            ToolkitResult: 攻击检测结果
        """
        detected_attacks = []

        # 1. 检测重入攻击
        reentrancy = await self._check_reentrancy_attack(call_traces)
        if reentrancy:
            detected_attacks.append(
                {
                    "type": "reentrancy",
                    "severity": "critical",
                    "confidence": reentrancy["confidence"],
                    "details": reentrancy,
                }
            )

        # 2. 检测授权陷阱
        approval_trap = await self._check_approval_trap(call_traces, asset_changes, user_intent)
        if approval_trap:
            detected_attacks.append(
                {
                    "type": "approval_trap",
                    "severity": "critical",
                    "confidence": approval_trap["confidence"],
                    "details": approval_trap,
                }
            )

        # 3. 检测钓鱼攻击
        phishing = await self._check_phishing_attack(call_traces, asset_changes, user_intent)
        if phishing:
            detected_attacks.append(
                {
                    "type": "phishing",
                    "severity": "critical",
                    "confidence": phishing["confidence"],
                    "details": phishing,
                }
            )

        # 4. 检测资金抽离
        drain = await self._check_drain_attack(call_traces, asset_changes)
        if drain:
            detected_attacks.append(
                {
                    "type": "drain",
                    "severity": "critical",
                    "confidence": drain["confidence"],
                    "details": drain,
                }
            )

        # 5. 检测闪电贷攻击
        flashloan = await self._check_flashloan_attack(call_traces)
        if flashloan:
            detected_attacks.append(
                {
                    "type": "flashloan",
                    "severity": "warning",
                    "confidence": flashloan["confidence"],
                    "details": flashloan,
                }
            )

        # 计算总体风险评分
        risk_score = self._calculate_risk_score(detected_attacks)

        return ToolkitResult(
            success=True,
            tool_name=self.tool_name,
            execution_time=0.0,
            error=None,
            data={
                "attacks_detected": len(detected_attacks),
                "risk_score": risk_score,
                "risk_level": self._get_risk_level(risk_score),
                "attacks": detected_attacks,
                "summary": self._generate_attack_summary(detected_attacks),
            },
        )

    async def _handle_check_risk_patterns(
        self, tx_to: str, tx_data: str, call_traces: list[dict[str, Any]] | None = None, **kwargs
    ) -> ToolkitResult:
        """
        检查风险模式

        Args:
            tx_to: 目标地址
            tx_data: 交易数据
            call_traces: 调用trace

        Returns:
            ToolkitResult: 风险模式检测结果
        """
        risks = []

        # 检查函数选择器
        selector = self._extract_selector(tx_data)
        if selector in DANGEROUS_SELECTORS:
            risks.append(
                {
                    "type": "dangerous_selector",
                    "selector": selector,
                    "function": DANGEROUS_SELECTORS[selector],
                    "severity": "medium",
                }
            )

        # 检查无限授权
        if "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" in tx_data.lower():
            risks.append(
                {
                    "type": "unlimited_approval",
                    "severity": "high",
                    "message": "检测到无限授权(uint256 max)",
                }
            )

        # 检查已知钓鱼合约
        if self._is_known_scam_contract(tx_to):
            risks.append(
                {
                    "type": "known_scam_contract",
                    "severity": "critical",
                    "address": tx_to,
                }
            )

        # 检查调用深度
        if call_traces:
            max_depth = max((t.get("depth", 0) for t in call_traces), default=0)
            if max_depth > 30:
                risks.append(
                    {
                        "type": "deep_call_stack",
                        "severity": "warning",
                        "depth": max_depth,
                    }
                )

        return ToolkitResult(
            success=True,
            tool_name=self.tool_name,
            execution_time=0.0,
            error=None,
            data={
                "selector": selector,
                "risks": risks,
                "risk_count": len(risks),
            },
        )

    async def _handle_replay_analysis(
        self,
        original_result: dict[str, Any],
        override_params: dict[str, Any] | None = None,
        **kwargs,
    ) -> ToolkitResult:
        """
        回放分析（使用state override）

        Args:
            original_result: 原始执行结果
            override_params: 状态覆盖参数

        Returns:
            ToolkitResult: 回放分析结果
        """
        # 这里需要与AnvilToolkit配合
        # 简化实现：返回回放建议
        return ToolkitResult(
            success=True,
            tool_name=self.tool_name,
            execution_time=0.0,
            error=None,
            data={
                "original_success": original_result.get("success", False),
                "replay_suggestions": [
                    "尝试增加gas limit",
                    "尝试修改block.timestamp",
                    "尝试增加账户余额",
                    "尝试修改token授权额度",
                ],
                "status": "suggestions_provided",
            },
        )

    async def _handle_generate_report(
        self, analysis_results: dict[str, Any], tx_info: dict[str, Any], **kwargs
    ) -> ToolkitResult:
        """
        生成安全报告

        Args:
            analysis_results: 分析结果
            tx_info: 交易信息

        Returns:
            ToolkitResult: 安全报告
        """
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "transaction": {
                "from": tx_info.get("tx_from"),
                "to": tx_info.get("tx_to"),
                "value": tx_info.get("tx_value"),
            },
            "summary": analysis_results.get("summary", ""),
            "risk_level": analysis_results.get("risk_level", "UNKNOWN"),
            "confidence": analysis_results.get("confidence", 0.0),
            "findings": analysis_results.get("findings", []),
            "recommendations": analysis_results.get("recommendations", []),
        }

        return ToolkitResult(
            success=True,
            tool_name=self.tool_name,
            execution_time=0.0,
            error=None,
            data={"report": report},
        )

    # ==================== 辅助方法 ====================

    def _analyze_call_chain(self, traces: list[dict]) -> list[str]:
        """分析调用链"""
        chain = []
        for trace in traces[:30]:
            from_addr = trace.get("from_address", trace.get("from", ""))[:10]
            to_addr = trace.get("to_address", trace.get("to", ""))[:10]
            depth = trace.get("depth", 0)
            chain.append(f"{'  ' * depth}{from_addr} -> {to_addr}")
        return chain

    def _detect_dangerous_calls(self, traces: list[dict]) -> list[dict]:
        """检测危险函数调用"""
        dangerous = []
        for trace in traces:
            input_data = trace.get("input_data", trace.get("input", ""))
            selector = self._extract_selector(input_data)
            if selector in DANGEROUS_SELECTORS:
                dangerous.append(
                    {
                        "selector": selector,
                        "function": DANGEROUS_SELECTORS[selector],
                        "from": trace.get("from_address", "")[:10],
                        "to": trace.get("to_address", "")[:10],
                    }
                )
        return dangerous

    def _analyze_eth_flows(self, traces: list[dict], initiator: str) -> list[dict]:
        """分析ETH流向"""
        flows = []
        for trace in traces:
            value = trace.get("value", "0")
            if int(value, 16) if value.startswith("0x") else int(value) > 0:
                flows.append(
                    {
                        "from": trace.get("from_address", "")[:10],
                        "to": trace.get("to_address", "")[:10],
                        "value": value,
                    }
                )
        return flows

    def _detect_reentrancy(self, traces: list[dict]) -> dict | None:
        """检测重入模式"""
        if not traces:
            return None

        # 简单检测：同一个地址在不同深度被多次调用
        call_map = {}
        for trace in traces:
            to_addr = trace.get("to_address", trace.get("to", ""))
            depth = trace.get("depth", 0)
            if to_addr not in call_map:
                call_map[to_addr] = []
            call_map[to_addr].append(depth)

        # 检测是否有地址在多个深度被调用
        for addr, depths in call_map.items():
            if len(set(depths)) > 3:  # 同一地址在3+个不同深度被调用
                return {
                    "pattern": "potential_reentrancy",
                    "address": addr[:10],
                    "depths": depths,
                }

        return None

    def _detect_delegatecall(self, traces: list[dict]) -> list[str]:
        """检测delegatecall调用"""
        targets = []
        for trace in traces:
            # delegatecall的selector通常不会在普通交易中出现
            # 这里需要更精确的检测
            if "delegatecall" in str(trace).lower():
                to_addr = trace.get("to_address", trace.get("to", ""))
                if to_addr:
                    targets.append(to_addr[:10])
        return targets

    def _extract_selector(self, data: str) -> str:
        """提取函数选择器"""
        if data.startswith("0x") and len(data) >= 10:
            return "0x" + data[2:10].lower()
        return "0x00000000"

    def _is_known_scam_contract(self, address: str) -> bool:
        """检查是否为已知钓鱼合约"""
        # TODO: 连接到链上数据库
        return False

    # ==================== 攻击检测 ====================

    async def _check_reentrancy_attack(self, traces: list[dict]) -> dict | None:
        """检查重入攻击"""
        reentrancy = self._detect_reentrancy(traces)
        if reentrancy:
            return {
                "confidence": 0.7,
                "pattern": reentrancy,
            }
        return None

    async def _check_approval_trap(
        self, traces: list[dict], changes: list[dict], intent: str
    ) -> dict | None:
        """检查授权陷阱"""
        # 检测：approve后立即transfer
        for trace in traces:
            selector = self._extract_selector(trace.get("input_data", ""))
            if selector == "0x095ea7b3":  # approve
                # 检查是否在非官方合约上授权
                to_addr = trace.get("to_address", "")
                if not self._is_official_defi_contract(to_addr):
                    return {
                        "confidence": 0.8,
                        "target": to_addr[:10],
                        "reason": "非官方合约授权",
                    }
        return None

    async def _check_phishing_attack(
        self, traces: list[dict], changes: list[dict], intent: str
    ) -> dict | None:
        """检查钓鱼攻击"""
        # 检测资金流向非预期地址
        for change in changes:
            if change.get("token") == "ETH":
                amount = int(change.get("change", "0"))
                if amount < -int(1e18):  # 超过1 ETH转出
                    return {
                        "confidence": 0.6,
                        "amount": abs(amount) / 1e18,
                        "reason": "异常大额ETH转出",
                    }
        return None

    async def _check_drain_attack(self, traces: list[dict], changes: list[dict]) -> dict | None:
        """检查资金抽离"""
        # 检测余额是否归零
        total_out = sum(int(c.get("change", 0)) for c in changes if int(c.get("change", 0)) < 0)
        if abs(total_out) > int(1e18):  # 超过1 ETH
            return {
                "confidence": 0.7,
                "drained_amount": abs(total_out) / 1e18,
            }
        return None

    async def _check_flashloan_attack(self, traces: list[dict]) -> dict | None:
        """检查闪电贷攻击"""
        for trace in traces:
            input_data = trace.get("input_data", "").lower()
            if "flashloan" in input_data or "flashloan" in str(trace).lower():
                return {
                    "confidence": 0.8,
                    "type": "flashloan_detected",
                }
        return None

    def _is_official_defi_contract(self, address: str) -> bool:
        """检查是否为官方DeFi合约"""
        # 简化实现，实际应查询官方合约列表
        official_contracts = {
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
            "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # Uniswap V3 Router
        }
        return address.lower() in [c.lower() for c in official_contracts]

    def _calculate_risk_score(self, attacks: list[dict]) -> float:
        """计算风险评分"""
        if not attacks:
            return 0.0

        score = 0.0
        for attack in attacks:
            severity = attack.get("severity", "low")
            confidence = attack.get("confidence", 0.5)

            if severity == "critical":
                score += 0.4 * confidence
            elif severity == "high":
                score += 0.3 * confidence
            elif severity == "warning":
                score += 0.15 * confidence
            else:
                score += 0.1 * confidence

        return min(score, 1.0)

    def _get_risk_level(self, score: float) -> str:
        """根据评分获取风险等级"""
        if score >= 0.7:
            return "CRITICAL"
        elif score >= 0.4:
            return "WARNING"
        else:
            return "SAFE"

    def _generate_attack_summary(self, attacks: list[dict]) -> str:
        """生成攻击摘要"""
        if not attacks:
            return "未检测到攻击模式"

        types = [a["type"] for a in attacks]
        return f"检测到 {len(attacks)} 种攻击模式: {', '.join(types)}"

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
                        "enum": [
                            "analyze_trace",
                            "detect_attack",
                            "check_risk_patterns",
                            "replay_analysis",
                            "generate_report",
                        ],
                        "description": "操作类型",
                    },
                    "call_traces": {
                        "type": "array",
                        "description": "调用trace列表",
                    },
                    "asset_changes": {
                        "type": "array",
                        "description": "资产变动列表",
                    },
                    "user_intent": {
                        "type": "string",
                        "description": "用户意图",
                    },
                    "tx_from": {
                        "type": "string",
                        "description": "发起地址",
                    },
                    "tx_to": {
                        "type": "string",
                        "description": "目标地址",
                    },
                    "tx_data": {
                        "type": "string",
                        "description": "交易数据",
                    },
                },
            },
        }
