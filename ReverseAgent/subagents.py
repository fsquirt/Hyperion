"""子 Agent：一个取证文件一个子 Agent，出报告即退出。

父子分工是整套设计的关键：
- 父 Agent 掌握**宿主机行为证据**（IOCTL 控制码、附着设备、进程树、事件日志），
  它知道「该往哪儿看」，因此**子 Agent 的任务提示词由父 Agent 现场撰写**
  （`SampleTask.instructions`），本地只补上引擎操作手册与报告格式。
- 子 Agent 只面对**一个文件 + 一套逆向 MCP**（IDA 或 WinDbg），
  上下文干净，不会被其他文件的噪声污染，分析完直接交报告然后销毁。

并发上限由 `MaxParallelSubagents`（默认 2）控制；由于 ida-pro-mcp 监听固定端口，
IDA 类子 Agent 之间还会被 `mcp_backends._IDA_LOCK` 再串行一次。
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, List, Optional

from agents import Agent, RunContextWrapper, function_tool
from pydantic import BaseModel, Field

from agent_tools import AgentContext, base_tools
from mcp_backends import ida_backend, windbg_backend
from prompts import build_subagent_instructions
from runtime import LlmProfile, stream_run
from session_context import ioctl_brief, suggest_engine

# 由 Agent.py 在启动时注入，避免把模型配置层层透传
LLM: Optional[LlmProfile] = None


def bind_llm(profile: LlmProfile) -> None:
    global LLM
    LLM = profile


class SampleTask(BaseModel):
    """一个待派发的子 Agent 任务。"""

    file_name: str = Field(description="取证文件名（取证文件列表里的 name）")
    instructions: str = Field(
        description=(
            "由主 Agent 亲手撰写的、给这个子 Agent 的任务提示词。"
            "子 Agent 看不到会话上下文，只能看到这段话，所以必须把线索写进去："
            "涉及的 IOCTL 控制码与调用次数、设备名、调用方进程、事件日志异常、"
            "要验证的假设、必须回答的问题清单。"
            "不需要教它怎么用 IDA/WinDbg，运行时会自动附上引擎手册与报告格式。"
        )
    )
    engine: str = Field(
        default="auto",
        description="分析引擎：auto（按扩展名自动选）| ida（静态样本）| windbg（崩溃转储）",
    )


def _build_user_input(ctx: AgentContext, sample: Path, task: SampleTask, engine: str) -> str:
    return (
        f"# 分析目标\n"
        f"- 文件名：`{sample.name}`\n"
        f"- 本地路径：`{sample}`\n"
        f"- 大小：{sample.stat().st_size} 字节\n"
        f"- 分析引擎：{engine}\n\n"
        f"# 会话侧 IOCTL 概览（自动附带，供交叉验证）\n"
        f"{ioctl_brief(ctx.session)}\n\n"
        f"你的任务指令已经写在系统提示词的「本次任务」一节里，请逐条回应，"
        f"并按规定格式输出最终 Markdown 报告。"
    )


async def _run_one(ctx: AgentContext, task: SampleTask) -> str:
    if LLM is None:
        return "子 Agent 未绑定 LLM 配置。"

    name = task.file_name.strip()
    # 尚未下载则自动补下载，避免主 Agent 漏掉这一步
    local = ctx.downloaded.get(name)
    if not local or not Path(local).exists():
        entry = ctx.session.find_file(name)
        if entry is None:
            return f"## {name}\n\n派发失败：会话里不存在该取证文件。"
        stored = str(entry.get("storedName") or entry.get("stored_name") or "")
        display = str(entry.get("name") or stored)
        dest = ctx.cfg.samples_dir / ctx.session.session_id / display
        try:
            path = await ctx.client.download(ctx.session.session_id, stored, dest)
        except Exception as exc:
            return f"## {name}\n\n派发失败：下载出错 {exc}"
        ctx.downloaded[display] = str(path)
        local = str(path)
        name = display

    sample = Path(local)
    engine = (task.engine or "auto").strip().lower()
    if engine not in ("ida", "windbg"):
        engine = suggest_engine(sample.name)

    tag = f"子Agent:{sample.name}"
    ctx.client.set_status(f"分析 {sample.name}（{engine}）")
    ctx.client.log(
        "info",
        f"派发子 Agent（引擎 {engine}）分析 {sample.name}\n"
        f"主 Agent 下达的任务指令：\n{task.instructions.strip()}",
        sample.name,
    )

    backend = (
        windbg_backend(ctx.cfg, sample) if engine == "windbg" else ida_backend(ctx.cfg, sample)
    )
    try:
        async with backend as mcp_server:
            sub = Agent[AgentContext](
                name=f"reverse-subagent-{engine}",
                instructions=build_subagent_instructions(engine, task.instructions),
                model=LLM.model,
                model_settings=LLM.settings,
                tools=base_tools(ctx.cfg),
                mcp_servers=[mcp_server],
            )
            report = await stream_run(
                sub,
                _build_user_input(ctx, sample, task, engine),
                context=ctx,
                client=ctx.client,
                tag=tag,
                max_turns=ctx.cfg.sub_agent_max_turns,
                log_file=sample.name,
            )
    except Exception as exc:
        report = f"## {sample.name}\n\n子 Agent 执行失败（引擎 {engine}）：{exc}"

    report = (report or "").strip() or f"## {sample.name}\n\n子 Agent 未产出内容。"
    ctx.subagent_reports[sample.name] = report
    try:
        (ctx.cfg.scratch_dir / f"subreport_{sample.name}.md").write_text(report, encoding="utf-8")
    except Exception:
        pass
    ctx.client.log("info", f"子 Agent 完成：{sample.name}（{len(report)} 字符）", sample.name)

    # 把子 Agent 的最终报告完整打到控制台（这是真正要审阅的东西，不是中途工具返回）
    sep = "=" * 70
    print(f"\n{sep}\n[子Agent:{sample.name}] 📝 最终报告（{len(report)} 字符）\n{sep}\n")
    print(report)
    print(f"\n{sep}\n[子Agent:{sample.name}] 📝 报告结束\n{sep}")
    return report


async def _guarded(ctx: AgentContext, task: SampleTask) -> str:
    async with ctx.semaphore:
        return await _run_one(ctx, task)


@function_tool(strict_mode=False)
async def analyze_samples(
    wrapper: RunContextWrapper[AgentContext], tasks: List[SampleTask]
) -> str:
    """派发子 Agent 串行逆向分析取证文件，返回每个文件的完整分析报告。

    子 Agent 会独占一套逆向 MCP（静态样本用 IDA Pro，.dmp 崩溃转储用 WinDbg），
    分析完输出 Markdown 报告后立即销毁。**子 Agent 串行执行、一个一个跑**
    （便于逐份排查，且 IDA 实例同时最多一个）。

    子 Agent 的提示词由你撰写：instructions 字段就是它的任务简报，它看不到
    会话上下文，你写多少它就知道多少。

    Args:
        tasks: 任务列表。每项包含 file_name、instructions（你写给子 Agent 的
            任务提示词，必须含具体线索与问题清单）、engine。
    """
    ctx = wrapper.context
    if not tasks:
        return "tasks 为空，没有可派发的任务。"

    print(f"\n[主Agent] 派发 {len(tasks)} 个子 Agent（串行执行）")
    blocks: List[str] = []
    for i, task in enumerate(tasks, 1):
        print(f"\n[主Agent] ▶ 子 Agent {i}/{len(tasks)}：{task.file_name}")
        try:
            res = await _guarded(ctx, task)
        except BaseException as exc:
            res = f"执行异常：{exc}"
        blocks.append(f"---\n### 子 Agent 报告：{task.file_name}\n\n{res}")
    ctx.client.set_status("汇总子 Agent 报告")
    return "\n\n".join(blocks)


@function_tool
async def get_subagent_report(
    wrapper: RunContextWrapper[AgentContext], file_name: str
) -> str:
    """重新取回某个文件的子 Agent 分析报告全文（历史被压缩后可用它找回）。

    Args:
        file_name: 取证文件名。
    """
    reports = wrapper.context.subagent_reports
    if file_name in reports:
        return reports[file_name]
    return f"没有 `{file_name}` 的子 Agent 报告。已有：{list(reports.keys())}"
