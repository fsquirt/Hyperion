"""Hyperion 逆向分析 Agent —— 主入口。

基于 openai-agents-python 的父子 Agent 架构：

  第一步  用访问凭据登记 → 领取集群 LLM API → 领取逆向任务
          → 拉取会话完整上下文（Windows 事件 / IOCTL 通信记录 / 附着设备
            / 进程树快照 / 取证文件列表）→ 启动主 Agent。
  第二步  主 Agent 下载取证文件，结合宿主机行为证据**亲手撰写**每个子 Agent
          的任务提示词，并发派发（上限受配置控制，默认 2 个）。
          静态样本走 IDA Pro MCP，.dmp 崩溃转储走 mcp-windbg。
          子 Agent 出具 Markdown 报告后立即销毁。
  第三步  主 Agent 汇总所有子报告 + 会话行为证据，出具**一个会话一份**的
          总结报告并回传服务端。

主 Agent 的系统提示词来自服务端（管理后台可改），本地只追加运行时附录；
子 Agent 的任务提示词由主 Agent 现场撰写。
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any, Dict, List

from agents import Agent, set_tracing_disabled

from agent_tools import AgentContext, CompactingSession, main_tools
from config import AgentConfig, load_config
from hyperion_client import HyperionClient, human_size
from mcp_backends import _kill_ida
from prompts import build_main_instructions
from runtime import LlmProfile, build_llm, stream_run
from session_context import SessionContext, suggest_engine
from subagents import bind_llm

set_tracing_disabled(True)

BANNER = r"""
==============================================================
  Hyperion Reverse Agent  ·  openai-agents-python 架构
  父 Agent 统筹会话，子 Agent 逆向取证文件（IDA / WinDbg MCP）
==============================================================
"""


# ─────────────────────────── 首轮输入 ──────────────────────────────────
def build_kickoff(ctx: AgentContext) -> str:
    """给主 Agent 的第一条用户消息：会话上下文摘要 + 待办文件 + 行动指令。"""
    sc = ctx.session
    files: List[str] = []
    for f in sc.task_files:
        name = str(f.get("name") or f.get("storedName") or "")
        size = human_size(int(f.get("size") or 0))
        files.append(f"- {name}（{size}，建议引擎：{suggest_engine(name)}）")
    file_block = "\n".join(files) if files else "（本次任务没有可逆向的取证文件）"

    return (
        f"# 新的逆向任务\n"
        f"会话 ID：{sc.session_id}\n"
        f"来源主机：{sc.machine_name or '未知'}\n\n"
        f"{sc.render_overview()}\n\n"
        f"# 本次需要逆向的取证文件\n{file_block}\n\n"
        f"# 你现在要做的事\n"
        f"1. 先用 `query_session_context` 把 IOCTL 记录、附着设备、进程树、"
        f"Windows 事件挖清楚，形成对这台机器上发生了什么的判断。\n"
        f"2. 用 `download_forensic_file` 下载上面列出的取证文件。\n"
        f"3. 用 `analyze_samples` 派发子 Agent。**每个子 Agent 的 instructions "
        f"由你撰写**：把它需要知道的控制码、设备名、调用方进程、事件线索和"
        f"待验证假设全部写进去，并列出它必须回答的问题。\n"
        f"4. 收齐子报告后，用 `submit_session_report` 提交**一份**会话级总结报告。\n"
        f"未提交报告前不要结束。"
    )


def build_fallback_report(ctx: AgentContext, final_text: str) -> str:
    """主 Agent 没走 submit_session_report 时的兜底报告。"""
    sc = ctx.session
    parts = [
        f"# 取证会话分析报告（兜底生成）\n",
        f"- 会话 ID：{sc.session_id}",
        f"- 来源主机：{sc.machine_name or '未知'}",
        f"- 说明：主 Agent 未通过 `submit_session_report` 提交，"
        f"以下内容由运行时拼装（最终回复 + 各子 Agent 报告）。\n",
        "## 主 Agent 最终输出\n",
        (final_text or "（无）").strip(),
    ]
    for name, report in ctx.subagent_reports.items():
        parts.append(f"\n## 子 Agent 报告：{name}\n")
        parts.append(report.strip())
    if not ctx.subagent_reports:
        parts.append("\n## 子 Agent 报告\n\n（无）")
    return "\n".join(parts)


# ─────────────────────────── 单个任务 ──────────────────────────────────
async def handle_task(
    cfg: AgentConfig, client: HyperionClient, llm: LlmProfile, task: Dict[str, Any]
) -> None:
    session_id = str(task.get("session_id") or "")
    machine = str(task.get("machine_name") or "")
    task_files: List[Dict[str, Any]] = list(task.get("files") or [])

    client.session_id = session_id
    client.set_status(f"分析会话 {session_id}")
    print(f"\n[任务] 会话 {session_id} · 主机 {machine} · 取证文件 {len(task_files)} 个")
    client.log("info", f"领取任务：会话 {session_id}（{machine}），取证文件 {len(task_files)} 个")

    # 第一步：拉取会话完整上下文
    payload = await client.session_context(session_id)
    if payload is None:
        client.log("info", "会话上下文获取失败，仅凭取证文件继续分析。")
        payload = {}
    sc = SessionContext(
        session_id=session_id,
        machine_name=machine or str(payload.get("machineName") or ""),
        raw=payload,
        task_files=task_files,
    )
    print(
        f"[上下文] 事件 {len(sc.events)} 条 · IOCTL 控制码 {len(sc.ioctl_counts)} 种 · "
        f"附着设备 {len(sc.devices)} 个 · 进程树快照 {len(sc.snapshots)} 份 · "
        f"取证文件 {len(sc.file_entries)} 个"
    )

    ctx = AgentContext(cfg=cfg, client=client, session=sc)

    # 主 Agent 系统提示词：服务端下发 + 本地运行时附录
    server_prompt = await client.system_prompt("exe")
    if server_prompt:
        print(f"[提示词] 服务端下发 {len(server_prompt)} 字符")
    else:
        print("[提示词] 服务端未返回，使用本地兜底提示词")
    instructions = build_main_instructions(server_prompt, cfg.max_parallel_subagents)

    agent: Agent[AgentContext] = Agent[AgentContext](
        name="hyperion-main-agent",
        instructions=instructions,
        model=llm.model,
        model_settings=llm.settings,
        tools=[*main_tools(cfg)],
    )

    memory = CompactingSession(
        session_id=f"main-{session_id}",
        db_path=str(cfg.memory_dir / f"{session_id}.db"),
        keep=cfg.history_keep_items,
    )

    final_text = ""
    try:
        final_text = await stream_run(
            agent,
            build_kickoff(ctx),
            context=ctx,
            client=client,
            tag="主Agent",
            max_turns=cfg.main_agent_max_turns,
            session=memory,
        )
    except Exception as exc:
        print(f"[主Agent] 运行异常: {exc}")
        client.log("info", f"主 Agent 运行异常：{exc}")
        final_text = f"主 Agent 运行异常：{exc}"

    # 第三步：确保有且仅有一份会话级报告回传
    if ctx.submitted:
        print(f"[报告] 已提交（结论：{ctx.final_result}）")
    else:
        print("[报告] 主 Agent 未主动提交，走兜底提交流程")
        # 服务端只接受 normal / suspicious / cheat，兜底一律按可疑上报，交人工复核
        ok = await client.submit_report(
            session_id, "suspicious", build_fallback_report(ctx, final_text), ""
        )
        client.log("info", "兜底报告提交" + ("成功" if ok else "失败"))

    client.session_id = ""
    client.set_status("空闲")


# ─────────────────────────── 主循环 ────────────────────────────────────
async def main() -> int:
    print(BANNER)
    cfg = load_config()
    print(f"[配置] 服务端 {cfg.server_url} · 工作目录 {cfg.work_dir} · "
          f"子 Agent 并发上限 {cfg.max_parallel_subagents}")

    if not cfg.credential_token:
        print("[配置] 缺少访问凭据 CredentialToken，请在 appsettings.json 中填写。")
        return 2

    client = HyperionClient(cfg)
    if not await client.connect():
        print("[连接] 无法登记到服务端，退出。")
        await client.aclose()
        return 3
    print(f"[连接] agent_id={client.agent_id} · 集群 LLM API {len(client.llm_apis)} 个")
    client.start_background()

    try:
        llm = build_llm(client.llm_apis)
    except Exception as exc:
        print(f"[LLM] {exc}")
        await client.aclose()
        return 4
    bind_llm(llm)  # 子 Agent 复用同一套模型配置

    print("[就绪] 开始轮询逆向任务…（Ctrl+C 退出）")
    try:
        while True:
            task = await client.next_task()
            if not task:
                await asyncio.sleep(cfg.no_task_wait_seconds)
                continue
            try:
                await handle_task(cfg, client, llm, task)
            except Exception as exc:
                print(f"[任务] 处理异常: {exc}")
                client.log("info", f"任务处理异常：{exc}")
                client.session_id = ""
                client.set_status("空闲")
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[退出] 收到中断信号，正在收尾…")
    finally:
        _kill_ida()
        await client.aclose()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(0)
