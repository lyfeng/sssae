"""
Reasoning module - 推理层模块

支持多种推理引擎：
- IntentAnalyzer: 基于 OpenAI API 的传统推理
- ROMAIntentAnalyzer: 基于 ROMA 框架的递归推理
- Mock variants: 用于测试的 Mock 实现
"""

from .intent_analyzer import (
    IntentAnalyzer,
    MockIntentAnalyzer,
    IntentAnalysisResult,
)

from .roma_analyzer import (
    ROMAIntentAnalyzer,
    MockROMAAnalyzer,
)

from .prompts import (
    PromptTemplates,
    KnownRiskPatterns,
)


__all__ = [
    # 传统推理
    "IntentAnalyzer",
    "MockIntentAnalyzer",
    "IntentAnalysisResult",
    # ROMA 推理
    "ROMAIntentAnalyzer",
    "MockROMAAnalyzer",
    # 工具类
    "PromptTemplates",
    "KnownRiskPatterns",
]
