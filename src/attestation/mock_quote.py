"""
OML Attestation Mock Implementation

MVP 阶段提供符合 OML 1.0 规范的 Mock 证明。
生产环境应替换为真实的 AWS Nitro Enclaves 或 Intel SGX SDK。
"""

import base64
import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger(__name__)


class OMLAttestationQuote:
    """
    OML 1.0 证明结构

    参考规范：
    - PCR0: 代码度量（hash of running code）
    - PCR1: 配置度量
    - User Data: 自定义数据
    - Signature: 硬件签名
    """

    def __init__(
        self,
        pcr0: str,
        pcr1: str,
        user_data: str,
        tee_fingerprint: str,
        timestamp: datetime,
    ):
        self.pcr0 = pcr0
        self.pcr1 = pcr1
        self.user_data = user_data
        self.tee_fingerprint = tee_fingerprint
        self.timestamp = timestamp

    def to_dict(self) -> dict[str, Any]:
        """转换为字典格式"""
        return {
            "version": "OML_1.0",
            "tee_type": "AWS_NITRO_ENCLAVE",  # 或 INTEL_SGX
            "pcr0": self.pcr0,
            "pcr1": self.pcr1,
            "user_data": self.user_data,
            "tee_fingerprint": self.tee_fingerprint,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_base64(self) -> str:
        """转换为 Base64 编码的字符串（用于 API 响应）"""
        data = json.dumps(self.to_dict()).encode()
        return base64.b64encode(data).decode()

    @classmethod
    def from_simulation_result(
        cls,
        result: dict[str, Any],
        tee_fingerprint: str,
    ) -> "OMLAttestationQuote":
        """
        从模拟结果创建证明

        Args:
            result: 模拟执行结果
            tee_fingerprint: TEE 硬件指纹
        """
        # 计算 PCR0（基于模拟结果的 hash）
        result_hash = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()

        return cls(
            pcr0=result_hash[:64],  # 模拟结果 hash
            pcr1="0" * 64,  # 配置 hash（mock）
            user_data=json.dumps({"risk_level": result.get("risk_level", "SAFE")}),
            tee_fingerprint=tee_fingerprint,
            timestamp=datetime.now(UTC),
        )


class MockAttestationProvider:
    """
    Mock 证明提供者

    MVP 阶段使用预设的证明数据。
    生产环境应集成真实硬件：
    - AWS Nitro Enclaves: nsms get-attestation-document
    - Intel SGX: sgx_create_attestation
    """

    # Mock 硬件指纹（模拟真实 TEE）
    MOCK_TEE_FINGERPRINT = "mock_nitro_fp_0x5d2a9c8e7b6f4a3d2e1f0a9b8c7d6e5f"

    # Mock PCR 值（模拟已验证的代码）
    MOCK_PCR0 = "a1b2c3d4e5f6" * 8  # 64 字符
    MOCK_PCR1 = "f6e5d4c3b2a1" * 8  # 64 字符

    def __init__(self, tee_fingerprint: str | None = None):
        """
        初始化 Mock 证明提供者

        Args:
            tee_fingerprint: TEE 硬件指纹（None 则使用 mock 值）
        """
        self.tee_fingerprint = tee_fingerprint or self.MOCK_TEE_FINGERPRINT
        self._signature_key = self._generate_mock_key()

    def _generate_mock_key(self) -> rsa.RSAPrivateKey:
        """生成 Mock 签名密钥"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

    def generate_attestation(
        self,
        simulation_result: dict[str, Any],
    ) -> OMLAttestationQuote:
        """
        生成 OML 证明

        Args:
            simulation_result: 模拟执行结果

        Returns:
            OMLAttestationQuote: 证明对象
        """
        return OMLAttestationQuote.from_simulation_result(
            result=simulation_result,
            tee_fingerprint=self.tee_fingerprint,
        )

    def sign_quote(self, quote: OMLAttestationQuote) -> str:
        """
        对证明进行签名（Mock）

        生产环境应使用硬件私钥签名。
        """
        quote_data = json.dumps(quote.to_dict(), sort_keys=True).encode()
        signature = self._signature_key.sign(
            quote_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode()

    def generate_full_attestation(
        self,
        simulation_result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        生成完整的证明数据（包含签名）

        Args:
            simulation_result: 模拟执行结果

        Returns:
            完整的证明数据
        """
        quote = self.generate_attestation(simulation_result)
        signature = self.sign_quote(quote)

        return {
            "quote": quote.to_base64(),
            "signature": signature,
            "public_key": self._get_public_key_pem(),
        }

    def _get_public_key_pem(self) -> str:
        """获取公钥 PEM 格式"""
        public_key = self._signature_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode()

    def verify_quote(self, quote_b64: str, signature_b64: str) -> bool:
        """
        验证证明签名（Mock）

        生产环境应使用 OML 协议的验证流程。
        """
        try:
            quote_data = base64.b64decode(quote_b64)
            signature = base64.b64decode(signature_b64)
            public_key = self._signature_key.public_key()

            public_key.verify(
                signature,
                quote_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            logger.error(f"证明验证失败: {e}")
            return False


class SystemFingerprint:
    """
    系统指纹生成器

    用于生成 system_fingerprint 字段，标识运行环境。
    """

    @staticmethod
    def generate(
        model_name: str,
        tee_fingerprint: str,
        additional_info: dict[str, Any] | None = None,
    ) -> str:
        """
        生成系统指纹

        格式: {model_name}@{tee_fingerprint[:8]}_{hash}
        """
        info = {
            "model": model_name,
            "tee": tee_fingerprint[:8],
            **(additional_info or {}),
        }
        hash_part = hashlib.sha256(json.dumps(info, sort_keys=True).encode()).hexdigest()[:8]
        return f"{model_name}@{tee_fingerprint[:8]}_{hash_part}"

    @staticmethod
    def parse(fingerprint: str) -> dict[str, str]:
        """
        解析系统指纹
        """
        if "@" not in fingerprint:
            return {"raw": fingerprint}

        model, rest = fingerprint.split("@", 1)
        if "_" in rest:
            tee, hash_part = rest.rsplit("_", 1)
            return {"model": model, "tee": tee, "hash": hash_part}
        return {"model": model, "rest": rest}


# 全局 Mock 证明提供者实例
_mock_provider: MockAttestationProvider | None = None


def get_attestation_provider(
    tee_fingerprint: str | None = None,
) -> MockAttestationProvider:
    """获取全局证明提供者实例"""
    global _mock_provider
    if _mock_provider is None:
        _mock_provider = MockAttestationProvider(tee_fingerprint)
    return _mock_provider


def generate_attestation_metadata(
    simulation_result: dict[str, Any],
    model_name: str = "sssea-v1-mock",
) -> dict[str, Any]:
    """
    生成用于 API 响应的 attestation 元数据

    Args:
        simulation_result: 模拟执行结果
        model_name: 模型名称

    Returns:
        包含 attestation 和 system_fingerprint 的元数据
    """
    provider = get_attestation_provider()
    attestation = provider.generate_full_attestation(simulation_result)
    system_fp = SystemFingerprint.generate(
        model_name=model_name,
        tee_fingerprint=provider.tee_fingerprint,
    )

    return {
        "oml_attestation": attestation["quote"],
        "oml_signature": attestation["signature"],
        "system_fingerprint": system_fp,
    }
