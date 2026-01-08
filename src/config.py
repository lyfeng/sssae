"""
SSSEA Configuration Management

从环境变量和配置文件中读取配置，支持 .env 文件。
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """SSSEA 配置"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="",
        extra="ignore",
    )

    # API Server
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_reload: bool = Field(default=True, alias="API_RELOAD")

    # LLM Configuration (for ROMA Pipeline)
    openai_api_key: str = Field(default="", alias="OPENAI_API_KEY")
    openai_base_url: str = Field(default="https://api.openai.com/v1", alias="OPENAI_BASE_URL")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")

    # ROMA Configuration
    roma_provider: str = Field(
        default="openrouter", alias="ROMA_PROVIDER"
    )  # Options: "openrouter", "openai", "anthropic"
    roma_model: str = Field(default="openai/gpt-4o", alias="ROMA_MODEL")
    roma_api_key: str = Field(default="", alias="ROMA_API_KEY")

    # Web3 RPC Configuration
    mainnet_rpc_url: str = Field(default="https://eth.llamarpc.com", alias="MAINNET_RPC_URL")
    sepolia_rpc_url: str = Field(default="https://rpc.sepolia.org", alias="SEPOLIA_RPC_URL")

    # TEE/Anvil Configuration
    anvil_binary_path: str = Field(default="anvil", alias="ANVIL_BINARY_PATH")
    anvil_base_port: int = Field(default=8545, alias="ANVIL_BASE_PORT")
    anvil_fork_block: int | None = Field(default=None, alias="ANVIL_FORK_BLOCK")
    anvil_timeout_seconds: int = Field(default=30, alias="ANVIL_TIMEOUT_SECONDS")

    # OML Attestation
    oml_attestation_enabled: bool = Field(default=True, alias="OML_ATTESTATION_ENABLED")
    tee_hardware_fingerprint: str = Field(
        default="mock_tee_fp_0x5d2a", alias="TEE_HARDWARE_FINGERPRINT"
    )

    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")

    # Security
    allowed_callers: list[str] = Field(default=["*"], alias="ALLOWED_CALLERS")
    max_tx_size_bytes: int = Field(default=131072, alias="MAX_TX_SIZE_BYTES")

    @property
    def is_production(self) -> bool:
        """是否为生产环境"""
        return not self.api_reload

    @property
    def rpc_url(self, chain_id: int = 1) -> str:
        """根据 chain_id 获取 RPC URL"""
        if chain_id == 1:
            return self.mainnet_rpc_url
        elif chain_id == 11155111:  # Sepolia
            return self.sepolia_rpc_url
        else:
            return self.mainnet_rpc_url

    def get_rpc_url(self, chain_id: int = 1) -> str:
        """根据 chain_id 获取 RPC URL"""
        return self.rpc_url


# 全局配置实例
_settings: Settings | None = None


def get_settings() -> Settings:
    """获取全局配置实例"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """重新加载配置"""
    global _settings
    _settings = Settings()
    return _settings
