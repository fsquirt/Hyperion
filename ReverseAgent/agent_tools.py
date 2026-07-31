"""Agent 通用工具集 + 运行上下文 + 记忆压缩。

这里放的是「是个 Agent 就该有」的能力（文件读写、跑 Python、跑命令、
任务清单、记忆）以及 Hyperion 特有的取证上下文查询 / 取证文件下载 /
会话报告提交。逆向相关能力全部由 MCP（IDA / WinDbg）提供。
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import textwrap
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents import RunContextWrapper, SQLiteSession, function_tool

from config import AgentConfig
from hyperion_client import HyperionClient
from session_context import SessionContext, suggest_engine

MAX_TOOL_OUTPUT = 20000


def _truncate(text: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n\n…（输出共 {len(text)} 字符，中间已省略）…\n\n{text[-half:]}"


# ─────────────────────────── 运行上下文 ─────────────────────────────────
@dataclass
class AgentContext:
    cfg: AgentConfig
    client: HyperionClient
    session: SessionContext
    downloaded: Dict[str, str] = field(default_factory=dict)
    plan: List[Dict[str, str]] = field(default_factory=list)
    subagent_reports: Dict[str, str] = field(default_factory=dict)
    submitted: bool = False
    final_result: str = ""
    final_report: str = ""
    _sema: Optional[asyncio.Semaphore] = None

    @property
    def semaphore(self) -> asyncio.Semaphore:
        if self._sema is None:
            self._sema = asyncio.Semaphore(max(1, self.cfg.max_parallel_subagents))
        return self._sema

    def resolve_path(self, path: str) -> Path:
        """把相对路径限制在 scratch 工作区内，绝对路径仅允许工作目录下。"""
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = self.cfg.scratch_dir / p
        p = p.resolve()
        root = Path(self.cfg.work_dir).resolve()
        if root not in p.parents and p != root:
            raise ValueError(f"路径越界，仅允许访问 {root} 下的文件：{p}")
        return p


# ─────────────────────────── 取证上下文查询 ─────────────────────────────
@function_tool(strict_mode=False)
async def query_session_context(
    wrapper: RunContextWrapper[AgentContext],
    section: str,
    keyword: str = "",
    limit: int = 30,
    index: int = -1,
    include_xml: bool = False,
) -> str:
    """查询本次取证会话的上下文细节。

    Args:
        section: overview | events | ioctl | devices | process_tree | files | policy | raw_event
        keyword: 仅 events / raw_event 有效，按关键字过滤事件（匹配整条事件的任意字段）。
        limit: 仅 events 有效，返回条数上限；传 0 表示不限制。
        index: 仅 process_tree / raw_event 有效，取第几份快照 / 第几条事件（0 起，-1 为最后一条）。
        include_xml: 仅 events 有效，是否附带原始 EVTX XML（很长，慎用）。
    """
    ctx = wrapper.context
    sc = ctx.session
    s = (section or "overview").strip().lower()

    if s == "overview":
        return sc.render_overview()
    if s == "events":
        return _truncate(
            sc.render_events(
                limit=limit, detail_chars=600, keyword=keyword, include_xml=include_xml
            )
        )
    if s == "raw_event":
        pool = sc.events
        if keyword:
            k = keyword.lower()
            pool = [e for e in pool if k in json.dumps(e, ensure_ascii=False).lower()]
        if not pool:
            return "（无匹配事件）"
        i = index if 0 <= index < len(pool) else len(pool) - 1
        return _truncate(json.dumps(pool[i], ensure_ascii=False, indent=1))
    if s == "ioctl":
        return _truncate(sc.render_ioctl())
    if s == "devices":
        return _truncate(sc.render_devices())
    if s == "process_tree":
        return _truncate(sc.render_process_tree(index=index))
    if s == "files":
        return _truncate(sc.render_files())
    if s == "policy":
        return _truncate(sc.render_policy())
    return (
        f"未知的 section: {section}。可选："
        "overview / events / ioctl / devices / process_tree / files / policy / raw_event"
    )


@function_tool
async def download_forensic_file(
    wrapper: RunContextWrapper[AgentContext], file_name: str
) -> str:
    """下载一个取证文件到本地，返回本地绝对路径。派发子 Agent 前必须先下载。

    Args:
        file_name: 取证文件名（取证文件列表里的 name，或服务端落地名 storedName）。
    """
    ctx = wrapper.context
    entry = ctx.session.find_file(file_name)
    if entry is None:
        names = [f.get("name") for f in ctx.session.task_files]
        return f"未找到文件 `{file_name}`。当前会话待分析文件：{names}"

    stored = str(entry.get("storedName") or entry.get("stored_name") or "")
    display = str(entry.get("name") or stored)
    if not stored:
        return f"文件 `{display}` 缺少服务端落地名，无法下载。"

    if display in ctx.downloaded and Path(ctx.downloaded[display]).exists():
        return f"已存在本地副本：{ctx.downloaded[display]}"

    dest = ctx.cfg.samples_dir / ctx.session.session_id / display
    try:
        ctx.client.set_status(f"下载 {display}")
        path = await ctx.client.download(ctx.session.session_id, stored, dest)
    except Exception as exc:
        return f"下载 `{display}` 失败：{exc}"

    ctx.downloaded[display] = str(path)
    size = path.stat().st_size
    return (
        f"已下载 `{display}` → {path}（{size} 字节）。"
        f"建议分析引擎：{suggest_engine(display)}"
    )


# ─────────────────────────── 文件系统 ───────────────────────────────────
@function_tool(strict_mode=False)
async def read_file(
    wrapper: RunContextWrapper[AgentContext],
    path: str,
    offset: int = 0,
    limit: int = 2000,
) -> str:
    """读取工作区内的文本文件。

    Args:
        path: 相对 scratch 工作区的路径，或工作目录下的绝对路径。
        offset: 起始行号（0 起）。
        limit: 最多返回多少行。
    """
    try:
        p = wrapper.context.resolve_path(path)
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        return f"读取失败：{exc}"
    chunk = lines[offset : offset + limit] if limit > 0 else lines[offset:]
    body = "\n".join(f"{offset + i + 1:>6}: {ln}" for i, ln in enumerate(chunk))
    return _truncate(f"{p}（共 {len(lines)} 行）\n{body}")


@function_tool
async def write_file(
    wrapper: RunContextWrapper[AgentContext], path: str, content: str
) -> str:
    """把文本写入工作区文件（覆盖写）。用于保存脚本、中间结论、报告草稿。

    Args:
        path: 相对 scratch 工作区的路径。
        content: 完整文件内容。
    """
    try:
        p = wrapper.context.resolve_path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    except Exception as exc:
        return f"写入失败：{exc}"
    return f"已写入 {p}（{len(content)} 字符）"


@function_tool(strict_mode=False)
async def list_dir(wrapper: RunContextWrapper[AgentContext], path: str = ".") -> str:
    """列出工作区目录内容。

    Args:
        path: 相对 scratch 工作区的路径，默认当前工作区根。
    """
    try:
        p = wrapper.context.resolve_path(path)
        if not p.is_dir():
            return f"不是目录：{p}"
        rows = []
        for item in sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name)):
            kind = "DIR " if item.is_dir() else "FILE"
            size = item.stat().st_size if item.is_file() else 0
            rows.append(f"{kind} {size:>12} {item.name}")
    except Exception as exc:
        return f"列目录失败：{exc}"
    return f"{p}\n" + ("\n".join(rows) if rows else "（空目录）")


# ─────────────────────────── 执行能力 ───────────────────────────────────
async def _run_process(
    args: List[str], cwd: Path, timeout: int, env: Optional[Dict[str, str]] = None
) -> str:
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd),
        env=env or os.environ.copy(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return f"[超时] 超过 {timeout} 秒被终止。"
    text = (out or b"").decode("utf-8", errors="replace")
    return _truncate(
        f"[exit={proc.returncode} 用时 {time.monotonic() - started:.1f}s]\n{text or '（无输出）'}"
    )


@function_tool
async def run_python(wrapper: RunContextWrapper[AgentContext], code: str) -> str:
    """在工作区里执行一段 Python 代码并返回 stdout/stderr。

    适合做 PE 头解析、节区熵值计算、字节特征搜索、证书信息提取、数据统计等。
    代码会被落盘为脚本后执行，当前工作目录为 scratch 工作区。

    Args:
        code: 完整的 Python 源码。
    """
    ctx = wrapper.context
    script = ctx.cfg.scratch_dir / f"snippet_{uuid.uuid4().hex[:8]}.py"
    script.write_text(textwrap.dedent(code), encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return await _run_process(
        [sys.executable, "-X", "utf8", str(script)],
        ctx.cfg.scratch_dir,
        ctx.cfg.shell_timeout_seconds,
        env,
    )


@function_tool
async def run_shell(wrapper: RunContextWrapper[AgentContext], command: str) -> str:
    """在工作区里执行一条 shell/PowerShell 命令并返回输出。

    可用于 certutil 校验哈希、signtool 验签、file/strings 等外部工具。
    禁止执行会污染宿主机或长时间驻留的命令。

    Args:
        command: 完整命令行。
    """
    ctx = wrapper.context
    if not ctx.cfg.enable_shell_tool:
        return "shell 工具已在配置中禁用（EnableShellTool=false）。"
    if sys.platform == "win32":
        args = ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
    else:
        args = ["/bin/sh", "-c", command]
    return await _run_process(args, ctx.cfg.scratch_dir, ctx.cfg.shell_timeout_seconds)


# ─────────────────────────── 任务清单 ───────────────────────────────────
@function_tool
async def update_plan(
    wrapper: RunContextWrapper[AgentContext], steps: List[str], current: int = 0
) -> str:
    """维护分析任务清单，把长流程拆成可推进的步骤。

    Args:
        steps: 步骤描述列表（按顺序）。
        current: 当前正在执行的步骤下标（0 起）。
    """
    ctx = wrapper.context
    ctx.plan = [
        {
            "step": s,
            "status": "进行中" if i == current else ("已完成" if i < current else "待办"),
        }
        for i, s in enumerate(steps)
    ]
    rendered = "\n".join(
        f"{i + 1}. [{p['status']}] {p['step']}" for i, p in enumerate(ctx.plan)
    )
    ctx.client.log("info", f"任务清单更新：\n{rendered}")
    return rendered


# ─────────────────────────── 提交报告 ───────────────────────────────────
@function_tool
async def submit_session_report(
    wrapper: RunContextWrapper[AgentContext], result: str, content: str
) -> str:
    """提交本次取证会话的**总结报告**（一个会话只提交一次，提交后立即结束）。

    Args:
        result: 判定结论，只能是 normal / suspicious / cheat 之一。
        content: Markdown 格式的完整会话总结报告。
    """
    ctx = wrapper.context
    verdict = (result or "").strip().lower()
    if verdict not in ("normal", "suspicious", "cheat"):
        return "result 非法，只能是 normal / suspicious / cheat 之一。"
    if not (content or "").strip():
        return "报告内容为空，拒绝提交。"

    ok = await ctx.client.submit_report(ctx.session.session_id, verdict, content)
    if not ok:
        return "报告提交失败（网络或服务端错误），请稍后重试一次。"
    ctx.submitted = True
    ctx.final_result = verdict
    ctx.final_report = content
    return f"会话级总结报告已提交，判定 = {verdict}。任务结束，请不要再调用任何工具。"


def base_tools(cfg: AgentConfig) -> List[Any]:
    """子 Agent 也能用的通用工具。"""
    tools = [read_file, write_file, list_dir, run_python]
    if cfg.enable_shell_tool:
        tools.append(run_shell)
    return tools


def main_tools(cfg: AgentConfig) -> List[Any]:
    """主 Agent 的工具集。

    关键设计：主 Agent **故意不持有** run_python / run_shell / read_file /
    write_file / list_dir 这类「亲手分析」的能力——它只能读懂上下文、下载文件、
    派发子 Agent、提交总结。逆向本身（PE 解析、反编译、熵值统计等）必须由子 Agent
    通过 IDA/WinDbg MCP 完成，否则主 Agent 会倾向于自己跑脚本、迟迟不派发，既浪费
    上下文又绕过了配套的逆向引擎。

    get_subagent_report 例外保留：上下文被压缩后，主 Agent 用它找回某文件的子报告。
    """
    from subagents import analyze_samples, get_subagent_report

    return [
        query_session_context,
        download_forensic_file,
        update_plan,
        analyze_samples,
        get_subagent_report,
        submit_session_report,
    ]


# ─────────────────────────── 记忆 / 上下文压缩 ──────────────────────────
class CompactingSession(SQLiteSession):
    """带上下文压缩的会话记忆。

    历史条目超过 `keep` 后，只把最近 `keep` 条喂给模型，并在最前面补一条
    结构化的历史摘要，避免上下文窗口被 IDA / WinDbg 的大段输出撑爆。
    截断时会跳过开头的孤儿 `function_call_output`，防止破坏工具调用配对。
    """

    def __init__(self, session_id: str, db_path: str, keep: int = 80) -> None:
        super().__init__(session_id, db_path)
        self._keep = max(8, keep)

    async def get_items(self, limit: int | None = None) -> List[Any]:  # type: ignore[override]
        items = await super().get_items(limit)
        if limit is not None or len(items) <= self._keep:
            return items

        dropped = items[: len(items) - self._keep]
        kept = items[len(items) - self._keep :]

        # 丢弃开头的孤儿工具输出，避免 tool_call / tool_output 配对断裂
        while kept and _item_type(kept[0]) in ("function_call_output", "computer_call_output"):
            dropped.append(kept.pop(0))
        if not kept:
            return items

        digest = _digest(dropped)
        return [{"role": "user", "content": digest}, *kept]


def _item_type(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("type") or "")
    return str(getattr(item, "type", "") or "")


def _digest(items: List[Any]) -> str:
    calls: List[str] = []
    texts: List[str] = []
    for it in items:
        d = it if isinstance(it, dict) else getattr(it, "__dict__", {})
        t = _item_type(it)
        if t == "function_call":
            name = d.get("name", "?")
            args = str(d.get("arguments", ""))[:180]
            calls.append(f"- 调用 {name}({args})")
        elif d.get("role") == "assistant":
            content = d.get("content")
            if isinstance(content, str) and content.strip():
                texts.append(content.strip()[:400])
    lines = [
        "【历史上下文摘要（早期对话已压缩，以下为要点，请勿重复已完成的操作）】",
        f"已省略 {len(items)} 条历史条目。",
    ]
    if calls:
        lines.append("已执行过的工具调用：")
        lines.extend(calls[-40:])
    if texts:
        lines.append("早期分析要点：")
        lines.extend(f"- {t}" for t in texts[-10:])
    return "\n".join(lines)
