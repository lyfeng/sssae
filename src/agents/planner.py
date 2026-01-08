"""
Planner Agent - 规划层Agent

负责将复杂任务分解为子任务，生成执行计划。
"""

import logging
from typing import Any

from .base import AgentContext, AgentResult, BaseAgent

logger = logging.getLogger(__name__)


class PlannerAgent(BaseAgent):
    """
    规划层Agent

    功能：
    - 分析任务复杂度
    - 将复杂任务分解为子任务
    - 生成执行DAG（有向无环图）
    - 确定子任务之间的依赖关系
    """

    agent_name = "planner"
    description = "将复杂任务分解为可执行的子任务"

    async def execute(self, context: AgentContext) -> AgentResult:
        """
        执行规划层分析

        Args:
            context: Agent上下文

        Returns:
            AgentResult: 任务分解结果和执行计划
        """
        try:
            # 1. 分析任务
            task_analysis = await self._analyze_task(context)

            # 2. 生成子任务列表
            subtasks = await self._generate_subtasks(context, task_analysis)

            # 3. 构建执行DAG
            execution_plan = await self._build_execution_dag(subtasks)

            # 4. 估算资源需求
            resource_estimate = await self._estimate_resources(execution_plan)

            result_data = {
                "task_analysis": task_analysis,
                "subtasks": subtasks,
                "execution_plan": execution_plan,
                "resource_estimate": resource_estimate,
                "estimated_steps": len(subtasks),
            }

            # 更新上下文
            context.metadata["plan"] = result_data

            return AgentResult(
                agent_name=self.agent_name,
                success=True,
                execution_time=0.0,
                data=result_data,
                error=None,
                next_step="executor",
                confidence=0.9,
            )

        except Exception as e:
            logger.error(f"Planner Agent执行失败: {e}", exc_info=True)
            return AgentResult(
                agent_name=self.agent_name,
                success=False,
                execution_time=0.0,
                error=f"任务规划失败: {str(e)}",
                next_step=None,
                confidence=0.0,
            )

    async def _analyze_task(self, context: AgentContext) -> dict[str, Any]:
        """分析任务特征"""
        tx_data = context.metadata.get("validated_tx_data", {})
        intent_analysis = context.metadata.get("intent_analysis", {})

        analysis = {
            "task_type": intent_analysis.get("intent_type", "unknown"),
            "has_value": int(tx_data.get("tx_value", "0"), 16) > 0,
            "has_calldata": len(tx_data.get("tx_data", "0x")) > 2,
            "calldata_size": len(tx_data.get("tx_data", "0x")),
            "target_contract": tx_data.get("tx_to", ""),
        }

        # 判断是否需要特殊处理
        analysis["needs_deep_analysis"] = analysis["calldata_size"] > 200 or analysis["has_value"]

        return analysis

    async def _generate_subtasks(
        self, context: AgentContext, analysis: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """生成子任务列表"""
        subtasks = []

        # 子任务1: 合约静态分析
        if analysis["has_calldata"]:
            subtasks.append(
                {
                    "id": "static_analysis",
                    "name": "静态合约分析",
                    "tool": "forensics_analyzer",
                    "action": "check_risk_patterns",
                    "params": {
                        "tx_to": analysis["target_contract"],
                        "tx_data": context.metadata.get("validated_tx_data", {}).get(
                            "tx_data", "0x"
                        ),
                    },
                    "priority": "high",
                }
            )

        # 子任务2: 环境准备
        subtasks.append(
            {
                "id": "setup_environment",
                "name": "准备模拟环境",
                "tool": "anvil_simulator",
                "action": "start",
                "params": {},
                "priority": "high",
            }
        )

        # 子任务3: 交易模拟
        subtasks.append(
            {
                "id": "simulate_tx",
                "name": "执行交易模拟",
                "tool": "anvil_simulator",
                "action": "simulate_tx",
                "params": {
                    "user_intent": context.user_intent,
                    **context.metadata.get("key_params", {}),
                },
                "priority": "critical",
                "depends_on": ["setup_environment"],
            }
        )

        # 子任务4: Trace分析
        subtasks.append(
            {
                "id": "trace_analysis",
                "name": "分析调用链",
                "tool": "forensics_analyzer",
                "action": "analyze_trace",
                "params": {
                    "tx_from": context.metadata.get("key_params", {}).get("tx_from"),
                    "tx_to": context.metadata.get("key_params", {}).get("tx_to"),
                    "tx_value": context.metadata.get("key_params", {}).get("tx_value"),
                },
                "priority": "medium",
                "depends_on": ["simulate_tx"],
            }
        )

        # 子任务5: 攻击检测
        subtasks.append(
            {
                "id": "attack_detection",
                "name": "检测攻击模式",
                "tool": "forensics_analyzer",
                "action": "detect_attack",
                "params": {},
                "priority": "high",
                "depends_on": ["simulate_tx", "trace_analysis"],
            }
        )

        return subtasks

    async def _build_execution_dag(self, subtasks: list[dict[str, Any]]) -> dict[str, Any]:
        """构建执行DAG"""
        # 按依赖关系排序
        ordered = []
        remaining = subtasks.copy()
        executed = set()

        while remaining:
            # 找到没有未完成依赖的任务
            ready = [t for t in remaining if all(d in executed for d in t.get("depends_on", []))]

            if not ready:
                # 循环依赖或错误，按优先级取一个
                ready = [max(remaining, key=lambda t: self._priority_value(t["priority"]))]

            task = ready[0]
            ordered.append(task)
            executed.add(task["id"])
            remaining.remove(task)

        return {
            "tasks": ordered,
            "total": len(ordered),
            "parallel_groups": self._group_parallel_tasks(ordered),
        }

    def _group_parallel_tasks(self, tasks: list[dict]) -> list[list[str]]:
        """将任务分组为可并行的组"""
        groups = []
        current_group = []
        current_deps = set()

        for task in tasks:
            task_deps = set(task.get("depends_on", []))
            # 如果当前任务依赖之前的任务，需要开始新组
            if task_deps & current_deps:
                groups.append([t["id"] for t in current_group])
                current_group = [task]
                current_deps = {task["id"]}
            else:
                current_group.append(task)
                current_deps.add(task["id"])

        if current_group:
            groups.append([t["id"] for t in current_group])

        return groups

    def _priority_value(self, priority: str) -> int:
        """获取优先级数值"""
        order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        return order.get(priority, 0)

    async def _estimate_resources(self, plan: dict[str, Any]) -> dict[str, Any]:
        """估算资源需求"""
        return {
            "estimated_time_seconds": len(plan["tasks"]) * 5,
            "memory_mb": 512,
            "required_tools": list(set(t["tool"] for t in plan["tasks"])),
        }
