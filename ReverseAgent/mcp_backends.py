"""逆向分析 MCP 后端。

两套后端，对应两类取证文件：
- IDA Pro（静态样本 exe/dll/sys/…）：IDA **本体** 与 **ida-pro-mcp.exe** 是两个
  **独立进程**。正确顺序：先拉起 ida.exe 以无界面自动模式分析样本 → 等待分析完成
  → 再拉起 ida-pro-mcp.exe（它通过 IDA 的 RPC 连上已分析的实例并对外暴露 SSE）
  → 连 SSE 端点。端口固定（默认 13337），同一时刻只能有一个 IDA 实例，
  用全局锁串行化。
- mcp-windbg（崩溃转储 .dmp）：标准 stdio MCP 服务器，直接
  `mcp-windbg --transport stdio` 起进程即可，可并发多个实例。
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import AsyncIterator, List, Optional

from agents.mcp import MCPServerSse, MCPServerStdio

from config import AgentConfig

# ida-pro-mcp 监听固定端口，且依赖单实例 IDA，全局串行
_IDA_LOCK = asyncio.Lock()

# 任何一步失败都抛这个，由调用方转成子 Agent 报告里的错误说明
class BackendError(RuntimeError):
    pass


# ─────────────────────────── IDA Pro ────────────────────────────────────
def _kill_ida() -> None:
    if sys.platform != "win32":
        return
    for image in ("ida.exe", "ida64.exe", "idat.exe", "idat64.exe"):
        with contextlib.suppress(Exception):
            subprocess.run(
                ["taskkill", "/F", "/IM", image],
                capture_output=True,
                timeout=20,
                check=False,
            )


def _kill_ida_mcp() -> None:
    with contextlib.suppress(Exception):
        subprocess.run(
            ["taskkill", "/F", "/IM", "ida-pro-mcp.exe"],
            capture_output=True,
            timeout=20,
            check=False,
        )


def _spawn_ida(cfg: AgentConfig, sample: Path) -> subprocess.Popen:
    """拉起 IDA 本体，自动分析样本。

    stdout/stderr 写入样本目录下的日志文件，便于失败时排查（不再丢进 DEVNULL）。
    """
    ida = Path(cfg.ida_path)
    if not ida.exists():
        raise BackendError(f"未找到 IDA 可执行文件：{ida}")
    # -A 无提示自动分析；-c 重建数据库；-Opdb:fallback 避免 PDB 下载卡死
    args = [str(ida), "-A", "-c", "-Opdb:fallback", str(sample)]
    env = dict(os.environ)
    env.setdefault("IDA_NO_HISTORY", "1")
    log_path = sample.parent / f"_ida_{sample.name}.log"
    out = open(log_path, "wb", buffering=0)
    print(f"[IDA] 启动 IDA 本体：{ida}（日志 -> {log_path}）")
    try:
        proc = subprocess.Popen(
            args,
            cwd=str(sample.parent),
            env=env,
            stdout=out,
            stderr=out,
        )
    except Exception as exc:
        out.close()
        raise BackendError(f"拉起 IDA 失败：{exc}")
    return proc


def _spawn_ida_mcp(cfg: AgentConfig) -> subprocess.Popen:
    """拉起 ida-pro-mcp.exe 这个**独立 MCP 服务器进程**。

    通过 `cmd /c start` 启动，会弹出一个独立的 cmd 窗口，方便你直接看到
    ida-pro-mcp 是否启动、是否发现了本地 IDA 实例。它自己发现 IDA 并暴露 SSE
    端点（默认 127.0.0.1:13337）。
    """
    cmd = cfg.ida_mcp_command
    exe = shutil.which(cmd) or cmd
    if not Path(exe).exists() and shutil.which(cmd) is None:
        raise BackendError(
            f"未找到 ida-pro-mcp 可执行文件：{cmd}（请确认它在 PATH 中或配置 IdaMcpCommand）"
        )
    print(f"[IDA] 启动 ida-pro-mcp.exe（独立窗口）：{exe}")
    # 用 start 弹独立 cmd 窗口；/MIN 可改为 /NORMAL 保持可见，这里保持可见
    return subprocess.Popen(
        ["cmd", "/c", "start", "", exe],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


async def _wait_ida_mcp(cfg: AgentConfig, ida_proc: subprocess.Popen) -> MCPServerSse:
    """轮询直到 ida-pro-mcp 的 SSE 端点可用且能列出工具。"""
    deadline = time.monotonic() + cfg.ida_ready_timeout_seconds
    last_err: Optional[Exception] = None
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        if ida_proc.poll() is not None:
            raise BackendError(f"IDA 进程在分析阶段提前退出（exit={ida_proc.returncode}）")
        server = MCPServerSse(
            name="ida-pro-mcp",
            params={
                "url": cfg.ida_mcp_url,
                "timeout": 30.0,
                "sse_read_timeout": 900.0,
            },
            cache_tools_list=True,
            client_session_timeout_seconds=180.0,
        )
        try:
            await server.connect()
            tools = await server.list_tools()
            if tools:
                print(f"[IDA] MCP 就绪，可用工具 {len(tools)} 个（第 {attempt} 次探测）")
                return server
            raise BackendError("ida-pro-mcp 已连接但未暴露任何工具")
        except Exception as exc:
            last_err = exc
            with contextlib.suppress(Exception):
                await server.cleanup()
            await asyncio.sleep(3.0)
    raise BackendError(f"等待 ida-pro-mcp 就绪超时：{last_err}")


@contextlib.asynccontextmanager
async def ida_backend(cfg: AgentConfig, sample: Path) -> AsyncIterator[MCPServerSse]:
    """为单个静态样本：IDA 自动分析 → 起 ida-pro-mcp.exe → 连 SSE。退出时清理。"""
    async with _IDA_LOCK:
        _kill_ida()
        _kill_ida_mcp()
        await asyncio.sleep(1.0)
        print(f"[IDA] 启动分析：{sample.name}")

        ida_proc = _spawn_ida(cfg, sample)
        try:
            # 等 IDA 自动分析样本完成（无界面模式需要时间）
            print(f"[IDA] 等待自动分析完成（约 {cfg.ida_analysis_wait_seconds}s）…")
            await asyncio.sleep(cfg.ida_analysis_wait_seconds)
            if ida_proc.poll() is not None:
                raise BackendError(
                    f"IDA 在自动分析阶段退出（exit={ida_proc.returncode}），"
                    f"日志见样本目录 _ida_{sample.name}.log"
                )

            # 再拉起独立的 MCP 服务器
            _kill_ida_mcp()  # 清掉可能残留的旧实例
            await asyncio.sleep(5.0)  # 等 ida-pro-mcp 窗口启动并发现 IDA 实例
            mcp_proc = _spawn_ida_mcp(cfg)
            try:
                server = await _wait_ida_mcp(cfg, ida_proc)
                yield server
            finally:
                with contextlib.suppress(Exception):
                    await server.cleanup()
                with contextlib.suppress(Exception):
                    mcp_proc.terminate()
                _kill_ida_mcp()
        finally:
            with contextlib.suppress(Exception):
                ida_proc.terminate()
            await asyncio.sleep(0.5)
            _kill_ida()
            _kill_ida_mcp()
            print(f"[IDA] 已关闭：{sample.name}")


# ─────────────────────────── mcp-windbg ─────────────────────────────────
def _resolve_windbg_command(cfg: AgentConfig) -> tuple[str, List[str]]:
    """定位 mcp-windbg 可执行文件；找不到就退回 `python -m mcp_windbg`。"""
    args = list(cfg.windbg_mcp_args or ["--transport", "stdio"])
    if "--transport" not in args:
        args += ["--transport", "stdio"]
    if cfg.cdb_path and "--cdb-path" not in args:
        args += ["--cdb-path", cfg.cdb_path]
    if cfg.symbol_path and "--symbols-path" not in args:
        args += ["--symbols-path", cfg.symbol_path]

    exe = shutil.which(cfg.windbg_mcp_command)
    if exe:
        return exe, args
    return sys.executable, ["-m", "mcp_windbg", *args]


@contextlib.asynccontextmanager
async def windbg_backend(cfg: AgentConfig, dump: Path) -> AsyncIterator[MCPServerStdio]:
    """为单个崩溃转储拉起 mcp-windbg（stdio），无需任何手工步骤。"""
    command, args = _resolve_windbg_command(cfg)
    env = dict(os.environ)
    if cfg.symbol_path:
        env.setdefault("_NT_SYMBOL_PATH", cfg.symbol_path)

    print(f"[WinDbg] 启动 mcp-windbg 分析：{dump.name}")
    server = MCPServerStdio(
        name="mcp-windbg",
        params={
            "command": command,
            "args": args,
            "env": env,
            "cwd": str(dump.parent),
        },
        cache_tools_list=True,
        client_session_timeout_seconds=300.0,
    )
    try:
        await server.connect()
        tools = await server.list_tools()
        print(f"[WinDbg] MCP 就绪，可用工具 {len(tools)} 个")
        yield server
    finally:
        with contextlib.suppress(Exception):
            await server.cleanup()
        print(f"[WinDbg] 已关闭：{dump.name}")
