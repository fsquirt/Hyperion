import os
import json
import asyncio
import subprocess
import traceback
from typing import List, Dict, Any, Optional
from contextlib import AsyncExitStack
from pydantic import BaseModel, Field, ConfigDict
import httpx
from openai import AsyncOpenAI
from mcp.client.sse import sse_client
from mcp import ClientSession

# 强制绕过本地代理，防止 127.0.0.1 流量被拦截
os.environ["NO_PROXY"] = "127.0.0.1,localhost"
os.environ["no_proxy"] = "127.0.0.1,localhost"

# ── 1. 配置管理 ────────────────────────────────────────────────────────
class AgentConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    server_url: str = Field(default="http://localhost:5000", alias="ServerUrl")
    credential_token: str = Field(default="", alias="CredentialToken")
    ida_path: str = Field(default=r"C:\IDA Professional 9.4\ida.exe", alias="IdaPath")
    win_dbg_path: str = Field(default="", alias="WinDbgPath")
    work_dir: str = Field(default=r"C:\ReverseAgentWork", alias="WorkDir")
    ida_mcp_endpoint: str = Field(default="http://127.0.0.1:13337/sse", alias="IdaMcpEndpoint")
    ida_analysis_wait_seconds: int = Field(default=15, alias="IdaAnalysisWaitSeconds")
    heartbeat_interval_seconds: int = Field(default=5, alias="HeartbeatIntervalSeconds")
    no_task_wait_seconds: int = Field(default=30, alias="NoTaskWaitSeconds")

def load_config() -> AgentConfig:
    config_path = "appsettings.json"
    cfg = AgentConfig()
    
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            cfg = AgentConfig(**data) 
    else:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(cfg.model_dump_json(indent=4, by_alias=True))
        print(f"[配置] 未找到配置文件，已创建示例: {config_path}")
    
    for key, field_info in AgentConfig.model_fields.items():
        env_val = os.getenv(field_info.alias.upper()) or os.getenv(key.upper())
        if env_val:
            setattr(cfg, key, type(getattr(cfg, key))(env_val))
            
    os.makedirs(cfg.work_dir, exist_ok=True)
    return cfg

# ── 2. 核心状态与全局变量 ──────────────────────────────────────────────
class AppState:
    def __init__(self):
        self.status: str = "空闲"
        self.agent_id: str = ""
        self.llm_api: dict = {}
        self.running: bool = True

state = AppState()
cfg = load_config()

# ── 3. 辅助函数 ────────────────────────────────────────────────────────
def format_size(bytes_size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} TB"

async def kill_process_by_name(name: str):
    try:
        subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass

# ── 4. 网络通信模块 ────────────────────────────────────────────────────
async def connect_server(client: httpx.AsyncClient) -> bool:
    try:
        headers = {"Authorization": f"Bearer {cfg.credential_token}"}
        resp = await client.post(f"{cfg.server_url}/api/reverse-agent/connect", headers=headers, json={})
        resp.raise_for_status()
        data = resp.json()
        state.agent_id = data.get("agent_id", "")
        apis = data.get("llm_apis", [])
        if not state.agent_id or not apis:
            print("[错误] 服务器返回的信息不完整。")
            return False
        state.llm_api = apis[0]
        print(f"[连接] 与服务器建立会话，Agent ID: {state.agent_id}")
        print(f"[连接] 使用 LLM API: {state.llm_api['name']} ({state.llm_api['model_name']})")
        return True
    except Exception as e:
        print(f"[错误] 连接失败: {e}")
        return False

async def heartbeat_loop(client: httpx.AsyncClient):
    headers = {"Authorization": f"Bearer {cfg.credential_token}"}
    while state.running:
        try:
            payload = {"agent_id": state.agent_id, "current_status": state.status}
            await client.post(f"{cfg.server_url}/api/reverse-agent/heartbeat", headers=headers, json=payload)
        except Exception:
            pass
        await asyncio.sleep(cfg.heartbeat_interval_seconds)

async def submit_report(client: httpx.AsyncClient, session_id: str, file_name: str, result: str, markdown: str) -> str:
    try:
        headers = {"Authorization": f"Bearer {cfg.credential_token}"}
        data = {
            "session_id": session_id,
            "agent_id": state.agent_id,
            "file_name": f"报告_{session_id}_{os.path.splitext(file_name)[0]}.md",
            "result": result
        }
        files = {"content": (None, markdown)}
        resp = await client.post(f"{cfg.server_url}/api/reverse-agent/report", headers=headers, data=data, files=files)
        resp.raise_for_status()
        print("[报告] 报告已提交")
        return "报告已提交成功"
    except Exception as e:
        return f"报告提交失败: {e}"

def execute_python(code: str) -> str:
    try:
        process = subprocess.Popen(
            ["python", "-"], 
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        stdout, stderr = process.communicate(input=code, timeout=30)
        return stdout + stderr
    except subprocess.TimeoutExpired:
        process.kill()
        return "[执行超时]"
    except Exception as e:
        return f"执行失败: {e}"

# ── 5. AI 与工具调用循环 (完全基于官方流式解析重写) ────────────────────
async def run_ai_analysis(http_client: httpx.AsyncClient, mcp_session: ClientSession, session_id: str, file_name: str):
    print("[AI] 开始智能分析 (官方 OpenAI 协议驱动)...")
    
    # 构造原生的 AsyncOpenAI 客户端
    ai_client = AsyncOpenAI(
        api_key=state.llm_api["api_key"],
        base_url=state.llm_api["base_url"],
        timeout=120.0
    )
    
    local_tools = [
        {
            "type": "function",
            "function": {
                "name": "submit_report",
                "description": "提交逆向分析报告。在完成所有文件分析后调用此工具。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "markdown": {"type": "string", "description": "Markdown格式的报告正文"},
                        "result": {"type": "string", "enum": ["normal", "cheat", "suspicious"]}
                    },
                    "required": ["markdown", "result"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "execute_python",
                "description": "执行 Python 代码用于偏移值计算等辅助分析。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Python 代码字符串"}
                    },
                    "required": ["code"]
                }
            }
        }
    ]

    mcp_tools_raw = []
    if mcp_session:
        mcp_tools_resp = await mcp_session.list_tools()
        for t in mcp_tools_resp.tools:
            mcp_tools_raw.append({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.inputSchema
                }
            })
    
    all_tools = local_tools + mcp_tools_raw

    instructions = f"""
    你是一名反作弊逆向分析专家。当前正在分析会话 {session_id} 的文件 {file_name}。
    ## 重点检测项
    1. 驱动 IAT 表是否为空或异常精简。
    2. 是否调用 MmCopyMemory 或类似函数。
    3. 任意内存读写能力判定。
    ## 判定规则
    - 具备任意内存读写能力 → cheat
    - IAT为空但无任意读写 → suspicious
    - 无异常 → normal
    分析完成后必须调用 submit_report 提交报告。回答用中文。
    """

    messages = [
        {"role": "system", "content": instructions},
        {"role": "user", "content": f"请分析文件 {file_name}，查找可疑的作弊行为特征。分析完成后请调用 submit_report 函数提交。"}
    ]

    # 自主交互大循环
    while True:
        try:
            print("\n[AI] 模型思考中...", end="", flush=True)
            # 采用你验证过的流式请求，彻底规避整体 JSON 解析的 Bug
            resp_stream = await ai_client.chat.completions.create(
                model=state.llm_api["model_name"],
                messages=messages,
                tools=all_tools,
                tool_choice="auto",
                stream=True
            )

            final_content = ""
            final_reasoning = ""
            tool_calls_dict = {}

            is_reasoning_printed = False
            is_content_printed = False

            # 手工拼装流式返回的 Chunk（支持深度思考模型）
            async for chunk in resp_stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                
                # 1. 处理思考内容 (Hy3 的特色)
                if hasattr(delta, 'reasoning_content') and delta.reasoning_content:
                    if not is_reasoning_printed:
                        print("\n\033[90m[思考过程]\033[0m\n\033[90m", end="")
                        is_reasoning_printed = True
                    print(delta.reasoning_content, end="", flush=True)
                    final_reasoning += delta.reasoning_content

                # 2. 处理最终文本回复
                if delta.content:
                    if is_reasoning_printed and not is_content_printed:
                        print("\033[0m\n\n\033[36m[执行决策]\033[0m\n\033[36m", end="")
                        is_content_printed = True
                    elif not is_reasoning_printed and not is_content_printed:
                        print("\n\033[36m[执行决策]\033[0m\n\033[36m", end="")
                        is_content_printed = True
                    print(delta.content, end="", flush=True)
                    final_content += delta.content

                # 3. 处理流式返回的工具调用参数 (可能分片到达)
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in tool_calls_dict:
                            tool_calls_dict[idx] = {
                                "id": tc.id or "",
                                "type": "function",
                                "function": {"name": tc.function.name or "", "arguments": tc.function.arguments or ""}
                            }
                        else:
                            if tc.function.name:
                                tool_calls_dict[idx]["function"]["name"] += tc.function.name
                            if tc.function.arguments:
                                tool_calls_dict[idx]["function"]["arguments"] += tc.function.arguments

            # 恢复终端颜色
            print("\033[0m", end="")

            # 构建并追加 Assistant 的回复到历史记录
            assistant_msg = {"role": "assistant"}
            if final_content:
                assistant_msg["content"] = final_content
            if tool_calls_dict:
                assistant_msg["tool_calls"] = [tool_calls_dict[k] for k in sorted(tool_calls_dict.keys())]
            messages.append(assistant_msg)

            # 如果没有工具调用，说明分析提前结束了
            if not tool_calls_dict:
                print("\n[AI 分析结束] 未调用后续工具。")
                break

            # 依次回传并执行工具
            for tc in assistant_msg["tool_calls"]:
                func_name = tc["function"]["name"]
                args_str = tc["function"]["arguments"]
                print(f"\n[工具调用] \033[33m{func_name}\033[0m")
                
                try:
                    args = json.loads(args_str)
                except json.JSONDecodeError:
                    args = {}
                    
                tool_result_str = ""

                if func_name == "submit_report":
                    tool_result_str = await submit_report(http_client, session_id, file_name, args.get("result", "normal"), args.get("markdown", ""))
                elif func_name == "execute_python":
                    tool_result_str = execute_python(args.get("code", ""))
                elif mcp_session:
                    try:
                        mcp_result = await mcp_session.call_tool(func_name, args)
                        tool_result_str = "\n".join([c.text for c in mcp_result.content if getattr(c, 'type', '') == "text" or hasattr(c, 'text')])
                    except Exception as e:
                        tool_result_str = f"MCP 工具执行失败: {e}"
                else:
                    tool_result_str = "工具未找到"

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": tool_result_str[:2000]
                })
                
                if func_name == "submit_report":
                    print("\n[AI 分析流程已完成]")
                    return

        except Exception as e:
            print(f"\n[AI 交互异常] {e}")
            traceback.print_exc()
            break

# ── 6. 单个文件分析流程 ────────────────────────────────────────────────
async def analyze_file(http_client: httpx.AsyncClient, session_id: str, file_name: str, file_index: int, total: int):
    print(f"\n[分析] 文件 {file_index}/{total}: {file_name}")
    state.status = f"分析 {file_name}"
    file_path = os.path.join(cfg.work_dir, file_name)
    ida_proc = None

    try:
        print(f"[IDA] 启动 IDA 分析: {file_path}")
        try:
            ida_proc = subprocess.Popen([cfg.ida_path, "-A", "-c", "-Opdb:fallback", file_path])
        except Exception as e:
            print(f"[IDA] 启动失败: {e}")
            return

        print(f"[IDA] 等待自动分析完成... {cfg.ida_analysis_wait_seconds}秒")
        await asyncio.sleep(cfg.ida_analysis_wait_seconds)

        async with AsyncExitStack() as stack:
            mcp_session_obj = None
            max_retries = 5
            
            for r in range(1, max_retries + 1):
                print(f"[MCP] 尝试启动并连接 MCP 服务 (第 {r}/{max_retries} 次)...")
                await kill_process_by_name("ida-pro-mcp.exe")
                
                try:
                    subprocess.Popen("cmd.exe /c start ida-pro-mcp", shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                except Exception:
                    pass
                    
                await asyncio.sleep(2)
                
                try:
                    sse_ctx = sse_client(cfg.ida_mcp_endpoint)
                    read_stream, write_stream = await stack.enter_async_context(sse_ctx)
                    
                    mcp_session_obj = ClientSession(read_stream, write_stream)
                    await stack.enter_async_context(mcp_session_obj)
                    await mcp_session_obj.initialize()
                    
                    print("[MCP] 连接成功！")
                    break
                except Exception as e:
                    print(f"[MCP] 连接失败: {e}")
                    if r == max_retries:
                        print("[错误] MCP 彻底连不上，放弃 MCP 工具分析。")

            await run_ai_analysis(http_client, mcp_session_obj, session_id, file_name)

    finally:
        print("[清理] 清理 IDA 和 MCP 进程")
        if ida_proc:
            try: ida_proc.kill()
            except: pass
        await kill_process_by_name("ida.exe")
        await kill_process_by_name("ida-pro-mcp.exe")

# ── 7. 主任务循环 ──────────────────────────────────────────────────────
async def main_loop(http_client: httpx.AsyncClient):
    headers = {"Authorization": f"Bearer {cfg.credential_token}"}
    analyzable_exts = {".exe", ".dll", ".sys", ".pyd", ".ocx"}

    while state.running:
        try:
            url = f"{cfg.server_url}/api/reverse-agent/next-task?agent_id={state.agent_id}"
            resp = await http_client.get(url, headers=headers)
            if resp.status_code == 200:
                task = resp.json()
                if task.get("has_task"):
                    session_id = task.get("session_id")
                    files = task.get("files", [])
                    print(f"\n[任务] 领取到任务 - 会话ID: {session_id}, 机器名: {task.get('machine_name')}")
                    
                    state.status = "下载文件"
                    to_analyze = []
                    for f in files:
                        ext = os.path.splitext(f["name"])[1].lower()
                        if ext in analyzable_exts:
                            to_analyze.append(f)
                            
                        download_url = f.get("download_url")
                        if download_url:
                            if not download_url.startswith("http"):
                                download_url = f"{cfg.server_url.rstrip('/')}/{download_url.lstrip('/')}"
                            dl_resp = await http_client.get(download_url, headers=headers)
                            dl_resp.raise_for_status()
                            with open(os.path.join(cfg.work_dir, f["name"]), "wb") as file_obj:
                                file_obj.write(dl_resp.content)
                    
                    for idx, f in enumerate(to_analyze):
                        await analyze_file(http_client, session_id, f["name"], idx + 1, len(to_analyze))
                    
                    state.status = "空闲"
                    continue
        except Exception:
            pass
            
        await asyncio.sleep(cfg.no_task_wait_seconds)

async def main():
    print(f"[配置] 工作目录: {cfg.work_dir}")
    print(f"[配置] 服务器: {cfg.server_url}")
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        if not await connect_server(client):
            return

        asyncio.create_task(heartbeat_loop(client))

        try:
            await main_loop(client)
        except KeyboardInterrupt:
            print("\n[退出] 收到退出信号")
            state.running = False

if __name__ == "__main__":
    asyncio.run(main())