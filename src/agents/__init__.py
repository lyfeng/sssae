"""
ROMA Agent Pipeline for SSSEA

实现符合ROMA框架规范的Agent Pipeline，包括：
- Perception Agent: 输入解析和任务理解
- Planner Agent: 任务分解和子任务规划
- Executor Agent: 执行子任务并调用工具
- Reflection Agent: 结果分析和自适应重试
- Aggregator Agent: 聚合结果并生成报告
"""

from .aggregator import AggregatorAgent
from .base import AgentContext, AgentResult, BaseAgent
from .executor import ExecutorAgent
from .perception import PerceptionAgent
from .pipeline import SSSEAPipeline
from .planner import PlannerAgent
from .reflection import ReflectionAgent

__all__ = [
    "BaseAgent",
    "AgentResult",
    "AgentContext",
    "PerceptionAgent",
    "PlannerAgent",
    "ExecutorAgent",
    "ReflectionAgent",
    "AggregatorAgent",
    "SSSEAPipeline",
]
