"""
SSSEA Pipeline - ROMA Agent Pipeline

完整的Agent执行流程，协调各个Agent的调用。
"""

import logging
from typing import Any

from ..toolkits.base import ToolkitRegistry
from .aggregator import AggregatorAgent
from .base import AgentContext
from .executor import ExecutorAgent
from .perception import PerceptionAgent
from .planner import PlannerAgent
from .reflection import ReflectionAgent

logger = logging.getLogger(__name__)


class SSSEAPipeline:
    """
    SSSEA Agent Pipeline

    ROMA风格的完整执行流程：
    Perception -> Planner -> Executor -> Reflection -> Aggregator

    支持简单任务的快速路径和复杂任务的完整分析。
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        初始化Pipeline

        Args:
            config: Pipeline配置
        """
        self.config = config or {}
        self.toolkit_registry = ToolkitRegistry()
        self._initialize_toolkits()
        self._initialize_agents()

    def _initialize_toolkits(self) -> None:
        """初始化工具集"""
        from ..toolkits import AnvilToolkit, ForensicsToolkit, TEEToolkit

        # 获取各toolkit配置
        anvil_config = self.config.get("anvil", {})
        tee_config = self.config.get("tee", {})
        forensics_config = self.config.get("forensics", {})

        # 注册toolkit
        self.toolkit_registry.register(AnvilToolkit(anvil_config))
        self.toolkit_registry.register(TEEToolkit(tee_config))
        self.toolkit_registry.register(ForensicsToolkit(forensics_config))

        logger.info(f"已注册 {len(self.toolkit_registry.list_tools())} 个工具")

    def _initialize_agents(self) -> None:
        """初始化Agent"""
        toolkits = {
            "anvil_simulator": self.toolkit_registry.get("anvil_simulator"),
            "tee_manager": self.toolkit_registry.get("tee_manager"),
            "forensics_analyzer": self.toolkit_registry.get("forensics_analyzer"),
        }

        self.perception = PerceptionAgent(self.config.get("perception", {}), toolkits)
        self.planner = PlannerAgent(self.config.get("planner", {}), toolkits)
        self.executor = ExecutorAgent(self.config.get("executor", {}), toolkits)
        self.reflection = ReflectionAgent(self.config.get("reflection", {}), toolkits)
        self.aggregator = AggregatorAgent(self.config.get("aggregator", {}), toolkits)

    async def run(
        self,
        user_intent: str,
        tx_data: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        运行完整的分析流程

        Args:
            user_intent: 用户意图
            tx_data: 交易数据
            metadata: 额外的元数据

        Returns:
            完整的分析报告
        """
        # 创建上下文
        context = AgentContext(
            user_intent=user_intent,
            tx_data=tx_data or {},
            metadata=metadata or {},
            config=self.config,
        )

        try:
            # 1. Perception: 解析输入
            perception_result = await self.perception(context)
            if not perception_result.success:
                error_msg = perception_result.error or "Unknown error"
                return self._error_report(context, "perception", error_msg)

            # 2. 根据复杂度决定是否需要Planner
            if perception_result.next_step == "planner":
                planner_result = await self.planner(context)
                if not planner_result.success:
                    error_msg = planner_result.error or "Unknown error"
                    return self._error_report(context, "planner", error_msg)

            # 3. Executor: 执行分析
            executor_result = await self.executor(context)
            if not executor_result.success and not executor_result.data:
                error_msg = executor_result.error or "Unknown error"
                return self._error_report(context, "executor", error_msg)

            # 4. Reflection: 分析结果
            reflection_result = await self.reflection(context)

            # 5. 根据反思结果决定是否重试
            if reflection_result.next_step == "executor":
                logger.info("根据反思结果，重新执行...")
                executor_result = await self.executor(context)
                reflection_result = await self.reflection(context)

            # 6. Aggregator: 聚合最终结果
            aggregator_result = await self.aggregator(context)

            return aggregator_result.data

        except Exception as e:
            logger.error(f"Pipeline执行失败: {e}", exc_info=True)
            return self._error_report(context, "pipeline", str(e))

        finally:
            # 清理资源
            await self._cleanup()

    async def _cleanup(self) -> None:
        """清理资源"""
        # 停止Anvil
        anvil = self.toolkit_registry.get("anvil_simulator")
        if anvil:
            await anvil.cleanup()

        # 销毁TEE
        tee = self.toolkit_registry.get("tee_manager")
        if tee:
            await tee.cleanup()

    def _error_report(self, context: AgentContext, stage: str, error: str) -> dict[str, Any]:
        """生成错误报告"""
        return {
            "success": False,
            "error_stage": stage,
            "error_message": error,
            "user_intent": context.user_intent,
            "execution_history": context.step_history,
        }

    async def execute_tool(self, tool_name: str, action: str, **params) -> dict[str, Any]:
        """
        直接执行指定工具

        Args:
            tool_name: 工具名称
            action: 操作类型
            **params: 操作参数

        Returns:
            执行结果
        """
        result = await self.toolkit_registry.execute(tool_name, action=action, **params)
        return result.to_dict()

    def get_tool_schemas(self) -> list:
        """获取所有工具的Schema"""
        return self.toolkit_registry.get_all_schemas()

    async def health_check(self) -> dict[str, Any]:
        """健康检查"""
        return {
            "status": "healthy",
            "toolkits": self.toolkit_registry.list_tools(),
            "agents": ["perception", "planner", "executor", "reflection", "aggregator"],
        }
