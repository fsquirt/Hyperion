"""Hyperion ReverseAgent - 流式对话 Demo (支持思考链)

通过 OpenRouter 专用集成 ChatOpenRouter 接入大模型:
- 流式输出:逐 token 打印正文
- 思考链(reasoning):实时显示模型推理过程(用 [思考]/[回答] 区分)
- 多轮对话:维护历史上下文
- reasoning tokens 统计:每轮显示思考 token 数

后续可扩展为多 Agent 逆向分析工作流。
"""
import os
import sys

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openrouter import ChatOpenRouter

# OpenRouter 配置
API_KEY = os.environ.get(
    "OPENROUTER_API_KEY",
    "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",
)
MODEL = "tencent/hy3:free"

SYSTEM_PROMPT = (
    "你是 Hyperion ReverseAgent,一个专注于软件逆向分析的 AI 助手。"
    "你能帮助分析反汇编、伪代码、PE 结构、shellcode、注入手法等。"
    "回答尽量精炼、可操作。"
)


def build_llm() -> ChatOpenRouter:
    """构造 ChatOpenRouter,开启 reasoning 深度思考。

    reasoning 参数(来自官方文档):
      - effort: 思考深度,可选 xhigh/high/medium/low/minimal/none
      - summary: 思考摘要详细度,可选 auto/concise/detailed
    max_tokens 要设大,否则 reasoning 占的 token 会挤掉正文。
    """
    return ChatOpenRouter(
        model=MODEL,
        api_key=API_KEY,
        temperature=0.7,
        max_tokens=16384,
        reasoning={"effort": "max", "summary": "auto"},
    )


def stream_one_turn(model: ChatOpenRouter, history: list) -> AIMessage:
    """流式跑一轮对话,实时打印 [思考] 和 [回答],返回完整 AIMessage。

    使用 ChatOpenRouter 推荐的 stream_events(version="v3") 新 API:
      - stream.reasoning: 思考 token 迭代器
      - stream.text:      正文 token 迭代器
      - stream.output:    迭代完毕后可取完整 AIMessage(含 usage_metadata)

    对简单模型调用直接用 stream_events(list_of_dicts) 传入消息列表即可,
    和 LangGraph agent 的 stream_events API 一致但更轻量。
    """
    # 将 LangChain message 对象转成 OpenRouter 接受的 dict 列表
    msg_dicts = []
    for m in history:
        if isinstance(m, SystemMessage):
            msg_dicts.append({"role": "system", "content": m.content})
        elif isinstance(m, HumanMessage):
            msg_dicts.append({"role": "user", "content": m.content})
        elif isinstance(m, AIMessage):
            msg_dicts.append({"role": "assistant", "content": m.content})
        else:
            msg_dicts.append({"role": "user", "content": str(m.content)})

    stream = model.stream_events(msg_dicts, version="v3")

    # 先流式输出思考过程(reasoning 投影),再流式输出正文(text 投影)
    # stream_events(version="v3") 的 .reasoning 和 .text 是两个独立生成器,
    # 底层 SSE 事件中 reasoning 事件先于 text 事件到达,顺序消费即可正确流式显示。
    reasoning_started = False
    for token in stream.reasoning:
        if not reasoning_started:
            print("\033[90m[思考] ", end="", flush=True)
            reasoning_started = True
        print(token, end="", flush=True)
    if reasoning_started:
        print("\033[0m")

    print("[回答] ", end="", flush=True)
    text_started = False
    for token in stream.text:
        text_started = True
        print(token, end="", flush=True)
    if not text_started:
        print("(无正文输出)", end="")
    print()

    # 取完整 AIMessage(含 usage_metadata)
    full: AIMessage = stream.output
    return full


def main() -> int:
    llm = build_llm()
    history: list = [SystemMessage(content=SYSTEM_PROMPT)]

    print("=" * 60)
    print("Hyperion ReverseAgent 流式对话 Demo")
    print(f"模型: {MODEL}  (via OpenRouter ChatOpenRouter)")
    print(f"思考深度: reasoning.effort=high, summary=auto")
    print("灰色 [思考] 为模型推理过程,[回答] 为最终回复")
    print("输入 'exit' / 'quit' / '退出' 结束对话")
    print("=" * 60 + "\n")

    while True:
        try:
            user_input = input("你 > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "退出"):
            print("再见。")
            break

        history.append(HumanMessage(content=user_input))
        try:
            ai_msg = stream_one_turn(llm, history)
        except Exception as e:
            print(f"\n[错误] 调用模型失败: {e}\n")
            history.pop()
            continue

        # 显示 token 统计
        um = ai_msg.usage_metadata
        details = um.get("output_token_details", {}) if um else {}
        reasoning_tokens = details.get("reasoning", 0)
        if um:
            print(
                f"\033[90m[tokens] 输入 {um.get('input_tokens','?')} / "
                f"输出 {um.get('output_tokens','?')} "
                f"(其中思考 {reasoning_tokens}) / "
                f"总计 {um.get('total_tokens','?')}\033[0m\n"
            )

        history.append(ai_msg)

    return 0


if __name__ == "__main__":
    sys.exit(main())
