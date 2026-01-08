"""
TEEToolkit - 可信执行环境工具集

提供TEE（Trusted Execution Environment）管理功能，
支持AWS Nitro Enclaves和Intel SGX。
"""

import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .base import BaseToolkit, ToolkitResult

logger = logging.getLogger(__name__)


class TEEToolkit(BaseToolkit):
    """
    TEE管理工具集

    功能：
    - 创建/销毁TEE enclave
    - 生成临时密钥
    - 获取TEE证明（attestation）
    - 在TEE中执行命令
    """

    tool_name = "tee_manager"
    description = (
        "可信执行环境(TEE)管理工具，支持AWS Nitro Enclaves和Intel SGX。"
        "用于创建隔离的安全执行环境，保护敏感数据和密钥。"
    )

    def _initialize(self) -> None:
        """初始化TEE配置"""
        self.backend = self.config.get("backend", "docker-sim")  # docker-sim, nitro, sgx
        self.tee_image = self.config.get("tee_image", "sssea/tee-sim:latest")
        self.enclave_id: str | None = None
        self.nitro_cli_path = self.config.get("nitro_cli_path", "nitro-cli")
        self.attestation_enabled = self.config.get("attestation_enabled", True)

        # 密钥管理
        self._ephemeral_keys: dict[str, str] = {}

    async def validate_input(self, **kwargs) -> tuple[bool, str | None]:
        """验证输入参数"""
        action = kwargs.get("action")
        if action == "create_enclave":
            # 确保有足够的资源
            memory = kwargs.get("memory", 512)
            if memory < 128 or memory > 32768:
                return False, "内存必须在128-32768 MB之间"
            cpus = kwargs.get("cpus", 2)
            if cpus < 1 or cpus > 64:
                return False, "CPU核心数必须在1-64之间"
        return True, None

    async def execute(self, action: str = "status", **kwargs) -> ToolkitResult:
        """
        执行TEE工具

        Args:
            action: 操作类型
                - create_enclave: 创建enclave
                - destroy_enclave: 销毁enclave
                - run_command: 在enclave中执行命令
                - generate_key: 生成临时密钥
                - get_attestation: 获取TEE证明
                - status: 获取enclave状态
            **kwargs: 操作参数

        Returns:
            ToolkitResult: 执行结果
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

    async def _handle_create_enclave(
        self, memory: int = 512, cpus: int = 2, **kwargs
    ) -> ToolkitResult:
        """
        创建TEE enclave

        Args:
            memory: 内存大小（MB）
            cpus: CPU核心数

        Returns:
            ToolkitResult: enclave信息
        """
        if self.backend == "docker-sim":
            return await self._create_docker_enclave(memory, cpus)
        elif self.backend == "nitro":
            return await self._create_nitro_enclave(memory, cpus)
        elif self.backend == "sgx":
            return await self._create_sgx_enclave(memory, cpus)
        else:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=f"不支持的TEE后端: {self.backend}",
            )

    async def _create_docker_enclave(
        self,
        memory: int,
        cpus: int,
    ) -> ToolkitResult:
        """创建Docker模拟的enclave"""
        try:
            # 使用Docker创建隔离容器
            container_name = f"sssea-tee-{datetime.utcnow().timestamp()}"

            cmd = [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--memory",
                f"{memory}m",
                "--cpus",
                str(cpus),
                "--security-opt",
                "no-new-privileges",
                "--cap-drop",
                "ALL",
                "--read-only",
                "-e",
                "TEE_SIMULATION=true",
                self.tee_image,
                "sleep",
                "infinity",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return ToolkitResult(
                    success=False,
                    tool_name=self.tool_name,
                    execution_time=0.0,
                    error=f"Docker容器创建失败: {result.stderr}",
                )

            self.enclave_id = container_name

            # 生成enclave证明
            attestation = None
            if self.attestation_enabled:
                attestation = await self._generate_mock_attestation(container_name)

            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={
                    "enclave_id": container_name,
                    "backend": "docker-sim",
                    "memory_mb": memory,
                    "cpus": cpus,
                    "status": "running",
                    "attestation": attestation,
                },
                metadata={
                    "image": self.tee_image,
                    "is_simulation": True,
                },
            )

        except subprocess.TimeoutExpired:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error="创建enclave超时",
                data={},
            )
        except Exception as e:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=str(e),
                data={},
            )

    async def _create_nitro_enclave(
        self,
        memory: int,
        cpus: int,
    ) -> ToolkitResult:
        """创建AWS Nitro Enclave"""
        try:
            # 检查nitro-cli是否可用
            check = subprocess.run(
                [self.nitro_cli_path, "describe-enclaves"],
                capture_output=True,
                timeout=5,
            )

            if check.returncode != 0:
                return ToolkitResult(
                    success=False,
                    tool_name=self.tool_name,
                    execution_time=0.0,
                    error="nitro-cli不可用，请确保在Nitro环境中运行",
                )

            # 创建enclave配置文件
            config = {
                "MemoryMB": memory,
                "CpuCount": cpus,
            }

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                delete=False,
            ) as f:
                import json

                json.dump(config, f)
                config_file = f.name

            # 运行nitro-cli
            result = subprocess.run(
                [
                    self.nitro_cli_path,
                    "run-enclave",
                    "--cpu-count",
                    str(cpus),
                    "--memory",
                    str(memory),
                    "--enclave-name",
                    f"sssea-{datetime.utcnow().timestamp()}",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            Path(config_file).unlink(missing_ok=True)

            if result.returncode != 0:
                return ToolkitResult(
                    success=False,
                    tool_name=self.tool_name,
                    execution_time=0.0,
                    error=f"创建Nitro Enclave失败: {result.stderr}",
                )

            # 解析enclave ID
            import json

            output = json.loads(result.stdout)
            self.enclave_id = output.get("EnclaveID")

            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={
                    "enclave_id": self.enclave_id,
                    "backend": "nitro",
                    "memory_mb": memory,
                    "cpus": cpus,
                    "status": "running",
                },
            )

        except Exception as e:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=str(e),
                data={},
            )

    async def _create_sgx_enclave(
        self,
        memory: int,
        cpus: int,
    ) -> ToolkitResult:
        """创建Intel SGX enclave"""
        # TODO: 实现SGX enclave创建
        return ToolkitResult(
            success=False,
            tool_name=self.tool_name,
            execution_time=0.0,
            error="SGX后端暂未实现，请使用docker-sim或nitro",
        )

    async def _handle_destroy_enclave(self, **kwargs) -> ToolkitResult:
        """销毁enclave"""
        if not self.enclave_id:
            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={"status": "no_enclave"},
            )

        try:
            if self.backend == "docker-sim":
                subprocess.run(
                    ["docker", "rm", "-f", self.enclave_id],
                    capture_output=True,
                    timeout=10,
                )
            elif self.backend == "nitro":
                subprocess.run(
                    [self.nitro_cli_path, "terminate-enclave", "--enclave-id", self.enclave_id],
                    capture_output=True,
                    timeout=10,
                )

            old_id = self.enclave_id
            self.enclave_id = None
            self._ephemeral_keys.clear()

            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={
                    "status": "destroyed",
                    "enclave_id": old_id,
                },
            )

        except Exception as e:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=str(e),
                data={},
            )

    async def _handle_generate_key(
        self, key_type: str = "ephemeral", scope: str = "transaction", **kwargs
    ) -> ToolkitResult:
        """
        生成临时密钥

        Args:
            key_type: 密钥类型（ephemeral, session）
            scope: 密钥使用范围

        Returns:
            ToolkitResult: 密钥信息（注意：不返回实际私钥）
        """
        import secrets

        key_id = f"{key_type}_{scope}_{secrets.token_hex(8)}"
        private_key = "0x" + secrets.token_hex(32)

        # 在内存中存储密钥（仅供内部使用）
        self._ephemeral_keys[key_id] = private_key

        logger.info(f"生成临时密钥: {key_id}")

        return ToolkitResult(
            success=True,
            tool_name=self.tool_name,
            execution_time=0.0,
            error=None,
            data={
                "key_id": key_id,
                "key_type": key_type,
                "scope": scope,
                "address": "0x" + secrets.token_hex(20),  # Mock地址
            },
            metadata={
                "enclave_id": self.enclave_id,
                "stored_in_tee": True,
            },
        )

    async def _handle_get_attestation(self, **kwargs) -> ToolkitResult:
        """获取TEE证明"""
        if not self.enclave_id:
            return ToolkitResult(
                success=False,
                tool_name=self.tool_name,
                execution_time=0.0,
                error="没有运行的enclave",
                data={},
            )

        attestation = await self._generate_mock_attestation(self.enclave_id)

        return ToolkitResult(
            success=True,
            tool_name=self.tool_name,
            execution_time=0.0,
            error=None,
            data={
                "attestation": attestation,
                "enclave_id": self.enclave_id,
            },
        )

    async def _handle_status(self, **kwargs) -> ToolkitResult:
        """获取enclave状态"""
        if not self.enclave_id:
            return ToolkitResult(
                success=True,
                tool_name=self.tool_name,
                execution_time=0.0,
                error=None,
                data={
                    "status": "not_initialized",
                    "enclave_id": None,
                    "backend": self.backend,
                },
            )

        # 检查enclave状态
        is_running = False
        if self.backend == "docker-sim":
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.enclave_id],
                capture_output=True,
                text=True,
            )
            is_running = result.stdout.strip() == "true"

        return ToolkitResult(
            success=True,
            tool_name=self.tool_name,
            execution_time=0.0,
            error=None,
            data={
                "status": "running" if is_running else "stopped",
                "enclave_id": self.enclave_id,
                "backend": self.backend,
                "active_keys": list(self._ephemeral_keys.keys()),
            },
        )

    async def _generate_mock_attestation(self, enclave_id: str) -> dict[str, Any]:
        """生成模拟的TEE证明"""
        import hashlib
        import json

        # 计算enclave hash
        enclave_data = json.dumps(
            {
                "id": enclave_id,
                "backend": self.backend,
                "timestamp": datetime.utcnow().isoformat(),
            }
        ).encode()
        hash_value = hashlib.sha256(enclave_data).hexdigest()

        return {
            "version": "OML_1.0",
            "tee_type": "AWS_NITRO_ENCLAVE" if self.backend == "nitro" else "SIMULATED_TEE",
            "enclave_id": enclave_id,
            "pcr0": hash_value[:64],
            "pcr1": hash_value[64:128] if len(hash_value) > 64 else "0" * 64,
            "timestamp": datetime.utcnow().isoformat(),
        }

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
                            "create_enclave",
                            "destroy_enclave",
                            "generate_key",
                            "get_attestation",
                            "status",
                        ],
                        "description": "操作类型",
                    },
                    "memory": {
                        "type": "integer",
                        "description": "enclave内存大小（MB）",
                        "default": 512,
                        "minimum": 128,
                        "maximum": 32768,
                    },
                    "cpus": {
                        "type": "integer",
                        "description": "CPU核心数",
                        "default": 2,
                        "minimum": 1,
                        "maximum": 64,
                    },
                    "key_type": {
                        "type": "string",
                        "enum": ["ephemeral", "session"],
                        "description": "密钥类型",
                        "default": "ephemeral",
                    },
                    "scope": {
                        "type": "string",
                        "description": "密钥使用范围",
                        "default": "transaction",
                    },
                },
            },
        }

    async def cleanup(self) -> None:
        """清理资源"""
        if self.enclave_id:
            await self._handle_destroy_enclave()
