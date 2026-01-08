#!/usr/bin/env python3
"""
SSSEA Environment Check Script

检查运行 SSSEA 所需的环境依赖：
1. Python 版本 >= 3.12
2. Foundry/Anvil 是否安装
3. 网络连接性（RPC 可达性）
4. 必要的 Python 包
"""

import sys
import subprocess
import importlib.util
from pathlib import Path
from typing import Tuple, List


class Colors:
    """终端颜色输出"""
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_header(text: str) -> None:
    print(f"\n{Colors.BLUE}{Colors.BOLD}=== {text} ==={Colors.RESET}")


def print_success(text: str) -> None:
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")


def print_error(text: str) -> None:
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")


def print_warning(text: str) -> None:
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")


def check_python_version() -> Tuple[bool, str]:
    """检查 Python 版本"""
    version = sys.version_info
    if version >= (3, 12):
        return True, f"Python {version.major}.{version.minor}.{version.micro}"
    return False, f"Python {version.major}.{version.minor}.{version.micro} (需要 >= 3.12)"


def check_command_exists(command: str) -> Tuple[bool, str]:
    """检查命令是否存在"""
    try:
        result = subprocess.run(
            ["which", command],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # 获取版本信息
            try:
                version_result = subprocess.run(
                    [command, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                version = version_result.stdout.strip().split("\n")[0]
                return True, f"{command}: {version}"
            except Exception:
                return True, f"{command}: 已安装"
        return False, f"{command}: 未找到"
    except Exception:
        return False, f"{command}: 检查失败"


def check_python_package(package: str, import_name: str = None) -> Tuple[bool, str]:
    """检查 Python 包是否已安装"""
    if import_name is None:
        import_name = package

    spec = importlib.util.find_spec(import_name)
    if spec is not None:
        try:
            mod = importlib.import_module(import_name)
            version = getattr(mod, "__version__", "unknown")
            return True, f"{package}: {version}"
        except Exception:
            return True, f"{package}: 已安装"
    return False, f"{package}: 未安装"


def check_rpc_connectivity(rpc_url: str) -> Tuple[bool, str]:
    """检查 RPC 连接性"""
    try:
        import httpx
        response = httpx.post(
            rpc_url,
            json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if "result" in data:
                block_num = int(data["result"], 16)
                return True, f"RPC 连接成功 (区块: {block_num})"
            return True, "RPC 连接成功"
        return False, f"RPC 返回错误: {response.status_code}"
    except ImportError:
        return False, "httpx 未安装，跳过 RPC 检查"
    except Exception as e:
        return False, f"RPC 连接失败: {e}"


def main():
    print_header("SSSEA 环境检查")
    print()

    all_passed = True
    results: List[Tuple[bool, str]] = []

    # 1. 检查 Python 版本
    print_header("1. Python 版本检查")
    passed, msg = check_python_version()
    results.append((passed, msg))
    if passed:
        print_success(msg)
    else:
        print_error(msg)
        all_passed = False

    # 2. 检查 Foundry/Anvil
    print_header("2. Foundry/Anvil 检查")
    for cmd in ["anvil", "cast", "forge"]:
        passed, msg = check_command_exists(cmd)
        results.append((passed, msg))
        if passed:
            print_success(msg)
        else:
            print_error(msg)
            if cmd == "anvil":
                all_passed = False

    # 3. 检查 Python 依赖
    print_header("3. Python 依赖检查")
    packages = [
        ("fastapi", "fastapi"),
        ("web3", "web3"),
        ("pydantic", "pydantic"),
        ("openai", "openai"),
        ("httpx", "httpx"),
    ]
    for package, import_name in packages:
        passed, msg = check_python_package(package, import_name)
        results.append((passed, msg))
        if passed:
            print_success(msg)
        else:
            print_warning(msg)

    # 4. 检查 RPC 连接
    print_header("4. RPC 连接检查")
    rpc_urls = [
        "https://eth.llamarpc.com",
        "https://rpc.ankr.com/eth",
    ]
    for rpc in rpc_urls:
        passed, msg = check_rpc_connectivity(rpc)
        results.append((passed, msg))
        if passed:
            print_success(f"{rpc[:30]}... - {msg}")
        else:
            print_warning(f"{rpc[:30]}... - {msg}")

    # 5. 检查项目结构
    print_header("5. 项目结构检查")
    required_dirs = [
        "src/simulation",
        "src/agents",
        "src/toolkits",
        "src/attestation",
        "src/api",
    ]
    for dir_path in required_dirs:
        path = Path(__file__).parent.parent / dir_path
        if path.exists():
            print_success(f"{dir_path}/ 存在")
        else:
            print_error(f"{dir_path}/ 不存在")
            all_passed = False

    # 总结
    print_header("检查总结")
    passed_count = sum(1 for p, _ in results if p)
    total_count = len(results)

    if all_passed:
        print_success(f"所有核心检查通过! ({passed_count}/{total_count})")
        print()
        print("下一步:")
        print("  1. 复制 .env.example 到 .env 并配置")
        print("  2. 运行: pip install -r requirements.txt")
        print("  3. 启动服务: python src/main.py")
        return 0
    else:
        print_error(f"部分检查失败 ({passed_count}/{total_count})")
        print()
        print("请安装缺失的依赖:")
        print("  - Foundry: curl -L https://foundry.paradigm.xyz | bash")
        print("  - Python 包: pip install -r requirements.txt")
        return 1


if __name__ == "__main__":
    sys.exit(main())
