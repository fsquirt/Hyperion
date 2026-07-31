"""Hyperion 逆向分析 Agent —— 配置加载。

优先级：环境变量 > appsettings.json > 内置默认值。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, List

from pydantic import BaseModel, ConfigDict, Field

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "appsettings.json"


class AgentConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # ── 服务端 ────────────────────────────────────────────────────────
    server_url: str = Field(default="http://localhost:5000", alias="ServerUrl")
    credential_token: str = Field(default="", alias="CredentialToken")
    work_dir: str = Field(default=r"C:\ReverseAgentWork", alias="WorkDir")

    # ── IDA Pro（静态样本，SSE MCP）──────────────────────────────────
    # 注意：IDA 本体 与 ida-pro-mcp.exe 是两个**独立进程**。
    # 流程：先拉起 ida.exe 自动分析样本 → 等待分析完成 →
    # 再拉起 ida-pro-mcp.exe（它通过 IDA 的 RPC 连上已分析的实例）→ 连 SSE。
    ida_path: str = Field(default=r"C:\IDA Professional 9.4\ida.exe", alias="IdaPath")
    ida_mcp_command: str = Field(default="ida-pro-mcp.exe", alias="IdaMcpCommand")
    ida_mcp_url: str = Field(default="http://127.0.0.1:13337/sse", alias="IdaMcpUrl")
    ida_analysis_wait_seconds: int = Field(default=10, alias="IdaAnalysisWaitSeconds")
    ida_ready_timeout_seconds: int = Field(default=120, alias="IdaReadyTimeoutSeconds")

    # ── WinDbg / CDB（崩溃转储，stdio MCP，直接起进程）────────────────
    windbg_mcp_command: str = Field(default="mcp-windbg", alias="WinDbgMcpCommand")
    windbg_mcp_args: List[str] = Field(
        default_factory=lambda: ["--transport", "stdio"], alias="WinDbgMcpArgs"
    )
    cdb_path: str = Field(default="", alias="CdbPath")
    symbol_path: str = Field(
        default="SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
        alias="SymbolPath",
    )

    # ── Agent 行为 ────────────────────────────────────────────────────
    max_parallel_subagents: int = Field(default=2, alias="MaxParallelSubagents")
    main_agent_max_turns: int = Field(default=120, alias="MainAgentMaxTurns")
    sub_agent_max_turns: int = Field(default=80, alias="SubAgentMaxTurns")
    history_keep_items: int = Field(default=80, alias="HistoryKeepItems")

    # ── 轮询 / 超时 ───────────────────────────────────────────────────
    heartbeat_interval_seconds: int = Field(default=5, alias="HeartbeatIntervalSeconds")
    no_task_wait_seconds: int = Field(default=30, alias="NoTaskWaitSeconds")
    request_timeout_seconds: int = Field(default=600, alias="RequestTimeoutSeconds")
    shell_timeout_seconds: int = Field(default=120, alias="ShellTimeoutSeconds")
    enable_shell_tool: bool = Field(default=True, alias="EnableShellTool")

    # ── 派生路径 ──────────────────────────────────────────────────────
    @property
    def samples_dir(self) -> Path:
        return Path(self.work_dir) / "samples"

    @property
    def scratch_dir(self) -> Path:
        """Agent 可自由读写的工作区（脚本、中间产物、子 Agent 报告）。"""
        return Path(self.work_dir) / "scratch"

    @property
    def memory_dir(self) -> Path:
        return Path(self.work_dir) / "memory"


def _coerce(default_value: Any, raw: str) -> Any:
    if isinstance(default_value, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default_value, int):
        return int(raw)
    if isinstance(default_value, list):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else [raw]
        except json.JSONDecodeError:
            return [p for p in raw.split() if p]
    return raw


def load_config() -> AgentConfig:
    cfg = AgentConfig()

    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
            cfg = AgentConfig(**data)
        except Exception as exc:  # 配置损坏时不阻断启动
            print(f"[配置] 解析 {CONFIG_PATH.name} 失败({exc})，改用默认配置。")
    else:
        CONFIG_PATH.write_text(
            cfg.model_dump_json(indent=4, by_alias=True), encoding="utf-8"
        )
        print(f"[配置] 未找到配置文件，已生成示例: {CONFIG_PATH}")

    # 环境变量覆盖：HYPERION_<ALIAS 大写> 或 <ALIAS 大写>
    for name, field in AgentConfig.model_fields.items():
        alias = (field.alias or name).upper()
        raw = os.getenv(f"HYPERION_{alias}") or os.getenv(alias) or os.getenv(name.upper())
        if raw:
            try:
                setattr(cfg, name, _coerce(getattr(cfg, name), raw))
            except Exception:
                pass

    cfg.server_url = cfg.server_url.rstrip("/")
    for d in (Path(cfg.work_dir), cfg.samples_dir, cfg.scratch_dir, cfg.memory_dir):
        d.mkdir(parents=True, exist_ok=True)
    return cfg
