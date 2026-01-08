"""
ROMA Configuration Loader

支持从YAML文件加载ROMA配置，并提供环境变量替换。
"""

import logging
import os
from pathlib import Path
from typing import Any

try:
    from omegaconf import OmegaConf

    HAS_OMEGACONF = True
except ImportError:
    HAS_OMEGACONF = False


logger = logging.getLogger(__name__)


class ROMAConfig:
    """
    ROMA配置管理器

    支持多环境配置（dev/prod）和环境变量替换。
    """

    # 默认配置
    DEFAULTS: dict[str, Any] = {
        "pipeline": {
            "enabled_agents": ["perception", "executor", "reflection", "aggregator"],
            "skip_planner": True,
            "max_retries": 2,
            "timeout": 300,
        },
        "toolkits": {
            "anvil_simulator": {
                "enabled": True,
                "fork_url": "https://eth.llamarpc.com",
                "timeout": 30,
            },
            "tee_manager": {
                "enabled": True,
                "backend": "docker-sim",
            },
            "forensics_analyzer": {
                "enabled": True,
            },
        },
        "roma": {
            "enabled": True,
            "model": "openai/gpt-4o",
        },
    }

    def __init__(self, profile: str = "dev"):
        """
        初始化配置

        Args:
            profile: 配置环境 (dev, prod)
        """
        self.profile = profile
        self._config: dict[str, Any] | None = None

    def load(self) -> dict[str, Any]:
        """加载配置"""
        if self._config is None:
            self._config = self._load_config()
        return self._config

    def _load_config(self) -> dict[str, Any]:
        """加载配置文件"""
        # 尝试从YAML文件加载
        if HAS_OMEGACONF:
            yaml_config = self._load_yaml_config()
            if yaml_config:
                return self._merge_with_defaults(yaml_config)

        # 回退到默认配置 + 环境变量
        return self._load_from_env()

    def _load_yaml_config(self) -> dict[str, Any] | None:
        """从YAML文件加载配置"""
        config_dir = Path(__file__).parent / "profiles"
        config_file = config_dir / f"{self.profile}.yaml"

        if not config_file.exists():
            logger.warning(f"配置文件不存在: {config_file}")
            return None

        try:
            cfg = OmegaConf.load(config_file)
            # 替换环境变量
            cfg = self._substitute_env_vars(cfg)
            return OmegaConf.to_container(cfg, resolve=True)
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return None

    def _substitute_env_vars(self, config: Any) -> Any:
        """递归替换环境变量"""
        if isinstance(config, dict):
            return {k: self._substitute_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._substitute_env_vars(v) for v in config]
        elif isinstance(config, str):
            # 替换 ${VAR_NAME} 格式
            if config.startswith("${") and config.endswith("}"):
                var_name = config[2:-1]
                return os.getenv(var_name, config)
            return config
        else:
            return config

    def _merge_with_defaults(self, config: dict[str, Any]) -> dict[str, Any]:
        """与默认配置合并"""
        import copy

        merged = copy.deepcopy(self.DEFAULTS)

        def deep_update(base: dict, update: dict) -> dict:
            """递归更新字典"""
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    deep_update(base[key], value)
                else:
                    base[key] = value
            return base

        return deep_update(merged, config)

    def _load_from_env(self) -> dict[str, Any]:
        """从环境变量加载配置"""
        import copy

        config = copy.deepcopy(self.DEFAULTS)

        # LLM配置
        if os.getenv("ROMA_API_KEY"):
            config["roma"]["api_key"] = os.getenv("ROMA_API_KEY")
        if os.getenv("ROMA_MODEL"):
            config["roma"]["model"] = os.getenv("ROMA_MODEL")

        # Anvil配置
        if os.getenv("MAINNET_RPC_URL"):
            config["toolkits"]["anvil_simulator"]["fork_url"] = os.getenv("MAINNET_RPC_URL")

        # TEE配置
        if os.getenv("TEE_BACKEND"):
            config["toolkits"]["tee_manager"]["backend"] = os.getenv("TEE_BACKEND")

        return config

    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置值

        支持点分隔的路径，如 "roma.model"
        """
        config = self.load()
        keys = key.split(".")

        value = config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

        return value if value is not None else default


# 全局配置实例
_configs: dict[str, ROMAConfig] = {}


def get_roma_config(profile: str = "dev") -> ROMAConfig:
    """
    获取ROMA配置实例

    Args:
        profile: 配置环境

    Returns:
        ROMAConfig实例
    """
    if profile not in _configs:
        _configs[profile] = ROMAConfig(profile)
    return _configs[profile]


def load_profile(profile: str = "dev") -> dict[str, Any]:
    """
    加载指定profile的配置

    Args:
        profile: 配置环境 (dev, prod)

    Returns:
        配置字典
    """
    return get_roma_config(profile).load()
