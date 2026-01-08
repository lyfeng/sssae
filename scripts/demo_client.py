#!/usr/bin/env python3
"""
SSSEA E2E Demo Client

模拟 DeFi 助手 Agent 调用 SSSEA 的完整场景。
参考《Agent2Agent协作.md》中的协作流程。
"""

import asyncio
import json
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx

# =============================================================================
# Demo Scenarios
# =============================================================================

SCENARIOS = {
    "safe_swap": {
        "name": "安全交易 - Uniswap V3 Swap",
        "description": "用户在 Uniswap V3 上将 1 ETH 兑换为 USDC，滑点 0.5%",
        "user_intent": "在 Uniswap V3 上将 1 ETH 兑换为等值的 USDC，滑点容忍度 0.5%",
        "tx": {
            "chain_id": 1,
            "tx_from": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",  # Binance Wallet
            "tx_to": "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # Uniswap V3 SwapRouter
            "tx_value": "1000000000000000000",  # 1 ETH
            "tx_data": "0x414bf389000000000000000000000000",  # 示例 calldata
        },
        "expected_verdict": "SAFE",
    },
    "phishing_approval": {
        "name": "钓鱼攻击 - 恶意无限授权",
        "description": "钓鱼网站诱骗用户给未知合约无限授权",
        "user_intent": "我要参与质押，获得收益",
        "tx": {
            "chain_id": 1,
            "tx_from": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            "tx_to": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  # 钓鱼合约
            "tx_value": "0",
            "tx_data": "0x095ea7b3" + "0" * 64 + "f" * 64,  # approve(spender, uint256(-1))
        },
        "expected_verdict": "WARNING",  # 官方 Uniswap 合约检测
    },
    "failed_transaction": {
        "name": "失败交易 - 流动性不足",
        "description": "交易因流动性不足而失败",
        "user_intent": "Swap 100 ETH to USDC",
        "tx": {
            "chain_id": 1,
            "tx_from": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0",
            "tx_to": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
            "tx_value": "100000000000000000000",  # 100 ETH
            "tx_data": "0x414bf389000000000000000000000000",
        },
        "expected_verdict": "SAFE",  # Mock 模拟会返回 SAFE
    },
}


# =============================================================================
# Demo Client
# =============================================================================


class SSSEAClient:
    """SSSEA 客户端"""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        # trust_env=False 禁用从环境变量读取代理
        self.client = httpx.AsyncClient(
            timeout=30.0,
            trust_env=False,  # 禁用代理
        )

    async def health_check(self) -> bool:
        """检查服务健康状态"""
        try:
            response = await self.client.get(f"{self.base_url}/health")
            return response.status_code == 200
        except Exception:
            return False

    async def list_tools(self) -> dict:
        """列出可用工具"""
        response = await self.client.get(f"{self.base_url}/v1/tools")
        return response.json()

    async def simulate_transaction(
        self,
        user_intent: str,
        tx_from: str,
        tx_to: str,
        tx_value: str = "0",
        tx_data: str = "0x",
        chain_id: int = 1,
    ) -> dict:
        """
        通过 OpenAI 兼容接口调用模拟

        模拟 DeFi 助手 Agent 调用 SSSEA 的场景。
        """
        payload = {
            "model": "sssea-v1-mock",
            "messages": [
                {
                    "role": "system",
                    "content": "你是一个安全审计 Agent。请分析这笔交易是否符合用户的意图。",
                },
                {
                    "role": "user",
                    "content": f"请审计以下交易：意图 - {user_intent}",
                },
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "simulate_tx",
                        "arguments": json.dumps(
                            {
                                "user_intent": user_intent,
                                "chain_id": chain_id,
                                "tx_from": tx_from,
                                "tx_to": tx_to,
                                "tx_value": tx_value,
                                "tx_data": tx_data,
                            }
                        ),
                    },
                }
            ],
        }

        response = await self.client.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
        )

        return response.json()

    async def simulate_direct(self, user_intent: str, **tx_params) -> dict:
        """直接调用模拟接口（简化版）"""
        payload = {
            "user_intent": user_intent,
            **tx_params,
        }

        response = await self.client.post(
            f"{self.base_url}/api/v1/simulate",
            json=payload,
        )

        return response.json()

    async def close(self):
        """关闭客户端"""
        await self.client.aclose()


# =============================================================================
# Demo Runner
# =============================================================================


class DemoRunner:
    """Demo 运行器"""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.client = SSSEAClient(base_url)
        self.passed = 0
        self.failed = 0

    def print_header(self, text: str):
        """打印标题"""
        print("\n" + "=" * 60)
        print(f"  {text}")
        print("=" * 60)

    def print_section(self, text: str):
        """打印小节"""
        print(f"\n>>> {text}")

    def print_result(self, key: str, value: str):
        """打印结果"""
        print(f"    {key}: {value}")

    async def run(self, scenario_name: str = None):
        """运行 Demo"""
        self.print_header("SSSEA Agent E2E Demo")

        # 1. 健康检查
        self.print_section("1. 健康检查")
        if not await self.client.health_check():
            print("    ❌ SSSEA 服务未启动！")
            print("    请先运行: python src/main.py")
            return
        print("    ✅ SSSEA 服务运行正常")

        # 2. 列出可用工具
        self.print_section("2. 可用工具")
        tools = await self.client.list_tools()
        for tool in tools.get("data", []):
            name = tool["function"]["name"]
            desc = tool["function"]["description"][:50] + "..."
            print(f"    📦 {name}: {desc}")

        # 3. 运行场景
        scenarios = [scenario_name] if scenario_name else list(SCENARIOS.keys())

        for scenario_id in scenarios:
            await self.run_scenario(scenario_id)

        # 4. 总结
        self.print_header("测试总结")
        print(f"    通过: {self.passed}")
        print(f"    失败: {self.failed}")
        print(f"    总计: {self.passed + self.failed}")

        if self.failed == 0:
            print("\n    🎉 所有测试通过！")
        else:
            print(f"\n    ⚠️  {self.failed} 个测试失败")

    async def run_scenario(self, scenario_id: str):
        """运行单个场景"""
        scenario = SCENARIOS.get(scenario_id)
        if not scenario:
            print(f"    ❌ 场景不存在: {scenario_id}")
            self.failed += 1
            return

        self.print_section(f"场景: {scenario['name']}")
        print(f"    描述: {scenario['description']}")
        print(f"    意图: {scenario['user_intent']}")

        # 调用模拟
        result = await self.client.simulate_direct(
            user_intent=scenario["user_intent"],
            **scenario["tx"],
        )

        # 解析结果
        verdict = result.get("verdict", "UNKNOWN")
        confidence = result.get("confidence", 0)
        summary = result.get("summary", "")
        anomalies = result.get("anomalies", [])
        attestation = result.get("attestation", "")

        # 打印结果
        print("\n    审计结果:")
        self.print_result("风险等级", verdict)
        self.print_result("置信度", f"{confidence:.0%}")
        self.print_result("摘要", summary)

        if anomalies:
            print("\n    检测到的问题:")
            for a in anomalies:
                print(f"      - {a}")

        if attestation:
            attestation_short = attestation[:40] + "..." if len(attestation) > 40 else attestation
            print(f"\n    OML 证明: {attestation_short}")

        # 验证预期结果
        expected = scenario.get("expected_verdict")
        if expected:
            if verdict == expected:
                print(f"\n    ✅ 符合预期 ({expected})")
                self.passed += 1
            else:
                print(f"\n    ❌ 不符合预期 (预期: {expected}, 实际: {verdict})")
                self.failed += 1


# =============================================================================
# Main
# =============================================================================


async def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="SSSEA E2E Demo")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000",
        help="SSSEA API URL",
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        help="运行特定场景",
    )
    args = parser.parse_args()

    runner = DemoRunner(base_url=args.url)
    try:
        await runner.run(scenario_name=args.scenario)
    finally:
        await runner.client.close()


if __name__ == "__main__":
    asyncio.run(main())
