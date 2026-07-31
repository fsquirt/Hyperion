"""模型工厂 + 流式执行器。

- 模型来自服务端集群下发的 LLM API 配置（OpenAI 兼容协议），
  用 `AsyncOpenAI` + `OpenAIChatCompletionsModel` 接入 openai-agents。
- 执行统一走 `Runner.run_streamed`，把工具调用 / 工具输出 / 模型消息
  实时打到控制台并回放到服务端 `/api/reverse-agent/log`。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from agents import (
    Agent,
    ItemHelpers,
    ModelSettings,
    RunConfig,
    Runner,
    set_default_openai_api,
    set_tracing_disabled,
)
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from hyperion_client import HyperionClient

set_tracing_disabled(True)
set_default_openai_api("chat_completions")

_PREVIEW = 1500


@dataclass
class LlmProfile:
    label: str
    model: OpenAIChatCompletionsModel
    settings: ModelSettings


def build_llm(llm_apis: List[Dict[str, Any]]) -> LlmProfile:
    """按服务端给出的优先级挑一个可用 API（priority 数值小者优先）。"""
    usable = [
        a for a in llm_apis if (a.get("base_url") and a.get("api_key") and a.get("model_name"))
    ]
    if not usable:
        raise RuntimeError("服务端未下发任何可用的 LLM API 配置。")
    api = sorted(usable, key=lambda a: int(a.get("priority") or 100))[0]

    client = AsyncOpenAI(
        base_url=str(api["base_url"]).rstrip("/"),
        api_key=str(api["api_key"]),
        max_retries=3,
        timeout=600.0,
    )
    model = OpenAIChatCompletionsModel(model=str(api["model_name"]), openai_client=client)

    max_tokens = int(api.get("max_tokens") or 0)
    settings = ModelSettings(
        temperature=float(api.get("temperature") if api.get("temperature") is not None else 0.2),
        max_tokens=max_tokens if max_tokens > 0 else None,
    )
    label = f"{api.get('name') or api.get('provider') or 'llm'}::{api['model_name']}"
    print(f"[LLM] 使用 {label} @ {api['base_url']}")
    return LlmProfile(label=label, model=model, settings=settings)


def _tool_name(item: Any) -> str:
    raw = getattr(item, "raw_item", None)
    return str(getattr(raw, "name", None) or (raw or {}).get("name", "") or "tool") if raw else "tool"


def _tool_args(item: Any) -> str:
    raw = getattr(item, "raw_item", None)
    args = getattr(raw, "arguments", None)
    if args is None and isinstance(raw, dict):
        args = raw.get("arguments")
    if args is None:
        return ""
    if isinstance(args, (dict, list)):
        args = json.dumps(args, ensure_ascii=False)
    return str(args)


def _tool_output(item: Any) -> str:
    out = getattr(item, "output", None)
    if out is None:
        raw = getattr(item, "raw_item", None)
        out = (raw or {}).get("output") if isinstance(raw, dict) else None
    if isinstance(out, (dict, list)):
        out = json.dumps(out, ensure_ascii=False)
    return str(out or "")


async def stream_run(
    agent: Agent[Any],
    user_input: str,
    context: Any,
    client: HyperionClient,
    *,
    tag: str,
    max_turns: int,
    session: Any = None,
    log_file: Optional[str] = None,
) -> str:
    """跑一个 Agent 并把过程流式打印 + 回放到服务端，返回 final_output 文本。"""
    run_config = RunConfig(workflow_name=tag, tracing_disabled=True)
    result = Runner.run_streamed(
        agent,
        input=user_input,
        context=context,
        max_turns=max_turns,
        session=session,
        run_config=run_config,
    )

    async for event in result.stream_events():
        if event.type == "raw_response_event":
            continue
        if event.type == "agent_updated_stream_event":
            print(f"\n[{tag}] → 切换到 Agent: {event.new_agent.name}")
            continue
        if event.type != "run_item_stream_event":
            continue

        item = event.item
        kind = getattr(item, "type", "")
        if kind == "tool_call_item":
            name, args = _tool_name(item), _tool_args(item)
            print(f"\n[{tag}] ⚙ 调用 {name} {args[:400]}")
            client.log("tool_call", f"[{tag}] {name}\n{args[:_PREVIEW]}", log_file)
        elif kind == "tool_call_output_item":
            out = _tool_output(item)
            preview = out[:600].replace("\n", " ")
            print(f"[{tag}] ⇢ 返回 {len(out)} 字符：{preview}")
            client.log("tool_result", f"[{tag}] {out[:_PREVIEW]}", log_file)
        elif kind == "message_output_item":
            text = ItemHelpers.text_message_output(item)
            if text.strip():
                print(f"\n[{tag}] 💬 {text[:800]}")
                client.log("llm", f"[{tag}] {text[:_PREVIEW]}", log_file)
        elif kind == "reasoning_item":
            client.log("info", f"[{tag}] （模型推理中）", log_file)

    return str(result.final_output or "")
