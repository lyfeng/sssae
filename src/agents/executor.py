"""
Executor Agent - 执行层Agent

负责执行子任务，调用工具，收集结果。
"""

import asyncio
import logging
from typing import Any

from .base import AgentContext, AgentResult, BaseAgent

logger = logging.getLogger(__name__)


class ExecutorAgent(BaseAgent):
    """
    执行层Agent

    功能：
    - 按照执行计划调用工具
    - 管理子任务执行顺序
    - 处理执行错误和重试
    - 收集子任务结果
    """

    agent_name = "executor"
    description = "执行子任务并调用工具"

    async def execute(self, context: AgentContext) -> AgentResult:
        """
        执行子任务

        Args:
            context: 包含执行计划的上下文

        Returns:
            AgentResult: 执行结果汇总
        """
        try:
            plan = context.metadata.get("plan")
            if not plan:
                # 简单模式，直接执行模拟
                return await self._execute_simple_mode(context)

            # 复杂模式，按照计划执行
            return await self._execute_plan(context, plan)

        except Exception as e:
            logger.error(f"Executor Agent执行失败: {e}", exc_info=True)
            return AgentResult(
                agent_name=self.agent_name,
                success=False,
                execution_time=0.0,
                error=f"任务执行失败: {str(e)}",
                next_step=None,
                confidence=0.0,
            )

    async def _execute_simple_mode(self, context: AgentContext) -> AgentResult:
        """简单模式：直接执行交易模拟"""
        results = {}

        # 获取参数
        params = context.metadata.get("key_params", {})

        # 1. 启动Anvil
        if self.has_toolkit("anvil_simulator"):
            anvil_tool = self.get_toolkit("anvil_simulator")
            assert anvil_tool is not None
            start_result = await anvil_tool(action="start")
            results["start"] = start_result.to_dict()

        # 2. 模拟交易
        if self.has_toolkit("anvil_simulator"):
            anvil_tool = self.get_toolkit("anvil_simulator")
            assert anvil_tool is not None
            sim_result = await anvil_tool(
                action="simulate_tx", user_intent=context.user_intent, **params
            )
            results["simulation"] = sim_result.to_dict()
            context.simulation_result = sim_result.to_dict()

        # 3. 分析trace
        if results["simulation"].get("success") and self.has_toolkit("forensics_analyzer"):
            forensics_tool = self.get_toolkit("forensics_analyzer")
            assert forensics_tool is not None
            trace_result = await forensics_tool(
                action="analyze_trace",
                call_traces=results["simulation"]["data"].get("call_traces", []),
                tx_from=params.get("tx_from"),
                tx_to=params.get("tx_to"),
                tx_value=params.get("tx_value", "0"),
            )
            results["trace_analysis"] = trace_result.to_dict()

        # 4. 检测攻击
        if results["simulation"].get("success") and self.has_toolkit("forensics_analyzer"):
            forensics_tool = self.get_toolkit("forensics_analyzer")
            assert forensics_tool is not None
            attack_result = await forensics_tool(
                action="detect_attack",
                call_traces=results["simulation"]["data"].get("call_traces", []),
                asset_changes=results["simulation"]["data"].get("asset_changes", []),
                user_intent=context.user_intent,
            )
            results["attack_detection"] = attack_result.to_dict()

        return AgentResult(
            agent_name=self.agent_name,
            success=results.get("simulation", {}).get("success", True),
            execution_time=0.0,
            data=results,
            error=None,
            next_step="reflection",
            confidence=0.85,
        )

    async def _execute_plan(self, context: AgentContext, plan: dict[str, Any]) -> AgentResult:
        """按照执行计划执行子任务"""
        results = {}
        tasks = plan["execution_plan"]["tasks"]
        parallel_groups = plan["execution_plan"].get("parallel_groups", [])

        # 如果有并行组，按组执行
        if parallel_groups:
            for group in parallel_groups:
                group_results = await self._execute_parallel(context, tasks, group)
                results.update(group_results)
        else:
            # 顺序执行
            for task in tasks:
                result = await self._execute_task(context, task, results)
                results[task["id"]] = result

                # 如果关键任务失败，停止执行
                if task["priority"] == "critical" and not result.get("success"):
                    logger.error(f"关键任务 {task['id']} 失败，停止执行")
                    break

        # 保存结果到上下文
        if "simulate_tx" in results:
            context.simulation_result = results["simulate_tx"]

        # 检查整体成功率
        success_count = sum(1 for r in results.values() if r.get("success", False))
        overall_success = success_count > len(results) / 2

        return AgentResult(
            agent_name=self.agent_name,
            success=overall_success,
            execution_time=0.0,
            data=results,
            error=None,
            next_step="reflection" if overall_success else "aggregator",
            confidence=success_count / len(results) if results else 0.0,
        )

    async def _execute_parallel(
        self, context: AgentContext, all_tasks: list[dict], task_ids: list[str]
    ) -> dict[str, Any]:
        """并行执行一组任务"""
        task_map = {t["id"]: t for t in all_tasks}

        # 创建协程
        coroutines = [self._execute_task(context, task_map[task_id], {}) for task_id in task_ids]

        # 并行执行
        results_list = await asyncio.gather(*coroutines, return_exceptions=True)

        # 组装结果
        results = {}
        for task_id, result in zip(task_ids, results_list):
            if isinstance(result, Exception):
                results[task_id] = {"success": False, "error": str(result)}
            else:
                results[task_id] = result

        return results

    async def _execute_task(
        self, context: AgentContext, task: dict[str, Any], previous_results: dict[str, Any]
    ) -> dict[str, Any]:
        """执行单个子任务"""
        tool_name = task["tool"]
        action = task["action"]
        params = task.get("params", {}).copy()

        # 注入上下文参数
        if "user_intent" not in params:
            params["user_intent"] = context.user_intent

        # 获取工具
        tool = self.get_toolkit(tool_name)
        if tool is None:
            return {
                "success": False,
                "error": f"工具 {tool_name} 不可用",
                "task_id": task["id"],
            }

        # 执行工具
        try:
            result = await tool(action=action, **params)
            return result.to_dict()
        except Exception as e:
            logger.error(f"任务 {task['id']} 执行失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "task_id": task["id"],
            }
