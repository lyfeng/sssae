# SSSEA Agent - 技术文档

**Sentient Security Sandbox Execution Agent**

基于 TEE 的 Web3 安全审计智能体，为 Sentient GRID 网络提供意图对齐审计服务。

---

## 项目概述

SSSEA 是一个**自主型安全代理 (Autonomous Security Agent)**，能够：

1. **接收其他 Agent 的请求**：通过 OpenAI 兼容接口接收 `[用户意图 + 交易数据]`
2. **TEE 沙盒模拟**：在 Anvil 分叉环境中执行交易模拟
3. **意图对齐审计**：通过 LLM 推理判断交易结果是否符合用户意图
4. **返回 OML 证明**：输出带硬件签名的安全报告

---

## 快速开始

### 1. 环境要求

- Python 3.12+
- Foundry/Anvil（用于主网分叉模拟）
- 可选：AWS Nitro Enclaves（生产环境）

### 2. 安装依赖

```bash
# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 3. 配置环境变量

```bash
# 复制配置模板
cp .env.example .env

# 编辑配置（可选，使用默认值也可）
# 主要配置项：
# - OPENAI_API_KEY: LLM API Key
# - MAINNET_RPC_URL: 以太坊主网 RPC
# - ANVIL_BINARY_PATH: anvil 可执行文件路径
```

### 4. 启动服务

```bash
# 开发模式（热重载）
python src/main.py

# 或使用 uvicorn
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. 运行 E2E Demo

```bash
# 确保 SSSEA 服务已启动，然后运行
python scripts/demo_client.py

# 运行特定场景
python scripts/demo_client.py --scenario safe_swap
```

---

## 项目结构

```
sssea/
├── doc/                    # 项目文档
│   ├── Agent规范技术白皮书.md
│   ├── Agent-prd.md
│   ├── Agent2Ageng协作.md
│   └── 一个具体的流程.md
├── src/
│   ├── main.py             # FastAPI 主入口
│   ├── config.py           # 配置管理
│   ├── simulation/         # 模拟引擎层
│   │   ├── models.py       # 数据模型
│   │   └── anvil_screener.py  # Anvil 模拟引擎
│   ├── reasoning/          # 推理层 (LLM Brain)
│   │   ├── prompts.py      # ROMA Prompt 模板
│   │   └── intent_analyzer.py  # 意图分析器
│   ├── attestation/        # OML 证明层
│   │   └── mock_quote.py   # Mock 证明生成器
│   └── api/                # API 层
│       └── openai_compat.py  # OpenAI 兼容接口
├── scripts/
│   ├── check_env.py        # 环境检查脚本
│   └── demo_client.py      # E2E Demo 客户端
├── tests/                  # 单元测试
├── .env.example            # 环境变量模板
├── requirements.txt        # Python 依赖
└── README.md               # 本文档
```

---

## API 接口

### OpenAI 兼容接口

**端点**: `POST /v1/chat/completions`

**请求示例**:
```json
{
  "model": "sssea-v1-mock",
  "messages": [
    {"role": "user", "content": "请审计以下交易"}
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "simulate_tx",
        "arguments": {
          "user_intent": "Swap 1 ETH to USDC",
          "tx_from": "0x...",
          "tx_to": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
          "tx_value": "1000000000000000000"
        }
      }
    }
  ]
}
```

**响应示例**:
```json
{
  "id": "chatcmpl-xxx",
  "choices": [...],
  "system_fingerprint": "sssea-v1-mock@mock_nit_xxx",
  "metadata": {
    "oml_attestation": "eyJ2ZXJzaW9uIjogIk9NTF8xLjAi...",
    "risk_level": "SAFE",
    "risk_score": 80
  }
}
```

### 简化模拟接口

**端点**: `POST /api/v1/simulate`

**请求示例**:
```json
{
  "user_intent": "Swap 1 ETH to USDC",
  "tx_from": "0x...",
  "tx_to": "0xE592427A0AEce92De3Edee1F18E0157C05861564",
  "tx_value": "1000000000000000000"
}
```

---

## 核心组件

### 1. Simulation Engine (模拟引擎)

**文件**: `src/simulation/anvil_screener.py`

- 动态启动 Anvil 分叉节点
- 执行交易并捕获资产变动
- 解析调用栈和事件日志

```python
from src.simulation.anvil_screener import AnvilScreener

screener = AnvilScreener(fork_url="https://eth.llamarpc.com")
with screener:
    result = await screener.simulate(request)
```

### 2. Reasoning Layer (推理层)

**文件**: `src/reasoning/intent_analyzer.py`

- 基于规则的快速检查
- LLM 深度意图分析
- 风险评级和建议

```python
from src.reasoning.intent_analyzer import MockIntentAnalyzer

analyzer = MockIntentAnalyzer()
analysis = await analyzer.analyze(request, result)
```

### 3. OML Attestation (证明层)

**文件**: `src/attestation/mock_quote.py`

- 生成符合 OML 1.0 规范的证明
- Mock 硬件签名（MVP 阶段）

```python
from src.attestation.mock_quote import generate_attestation_metadata

attestation = generate_attestation_metadata(simulation_result)
```

---

## 测试

### 运行单元测试

```bash
# 所有测试
pytest

# 特定模块
pytest tests/test_simulation.py
pytest tests/test_reasoning.py
```

### 环境检查

```bash
python scripts/check_env.py
```

---

## Agent 协作流程

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   User      │─────▶│ Swap Agent  │─────▶│   SSSEA     │
│             │      │             │      │   (TEE)     │
└─────────────┘      └─────────────┘      └─────────────┘
                            │                      │
                            ▼                      ▼
                      构建 Tx              沙盒模拟 + LLM
                            │                      │
                            ◀──────────────────────┘
                            │
                     返回安全报告
                            │
                            ▼
┌─────────────┐      ┌─────────────┐
│   User      │◀─────│ Swap Agent  │
│  (确认执行)  │      │             │
└─────────────┘      └─────────────┘
```

---

## 下一步 (MVP 后)

1. **真实 Anvil 集成**：替换 Mock 模拟为真实的主网分叉
2. **LLM 集成**：接入真实 OpenAI/Claude API
3. **TEE 部署**：打包为 AWS Nitro Enclaves EIF
4. **OML 注册**：在 Sentient Spark 阶段注册 Agent

---

## 许可证

MIT License
