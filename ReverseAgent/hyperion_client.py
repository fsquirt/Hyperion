"""Hyperion 服务端通信客户端。

对应服务端 `Server/Api/ReverseAgentEndpoints.cs` 的 9 个端点：
    POST /api/reverse-agent/connect
    POST /api/reverse-agent/heartbeat
    GET  /api/reverse-agent/next-task
    GET  /api/reverse-agent/session-context/{sessionId}
    GET  /api/reverse-agent/download/{sessionId}/{storedName}
    POST /api/reverse-agent/report
    POST /api/reverse-agent/disconnect
    GET  /api/reverse-agent/system-prompt
    POST /api/reverse-agent/log
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from config import AgentConfig

_LOG_MAX_CHARS = 8000


class HyperionClient:
    """与 Hyperion Server 交互；内部维护一个日志上报队列，避免阻塞分析主流程。"""

    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg
        self.agent_id: str = ""
        self.llm_apis: List[Dict[str, Any]] = []
        self.current_status: str = "空闲"
        self.session_id: str = ""

        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(cfg.request_timeout_seconds, connect=15.0),
            follow_redirects=True,
        )
        self._log_queue: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=2048)
        self._tasks: List[asyncio.Task] = []
        self._closing = False

    # ── 生命周期 ──────────────────────────────────────────────────────
    @property
    def _auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.cfg.credential_token}"}

    async def connect(self) -> bool:
        """用访问凭据登记 Agent，换取 agent_id 与集群 LLM API 列表。"""
        try:
            r = await self._http.post(
                f"{self.cfg.server_url}/api/reverse-agent/connect",
                headers=self._auth_headers,
                json={},
            )
            r.raise_for_status()
            data = r.json()
            self.agent_id = data.get("agent_id") or ""
            self.llm_apis = data.get("llm_apis") or []
            if not self.agent_id or not self.llm_apis:
                print("[连接] 服务端返回信息不完整（缺少 agent_id 或 llm_apis）。")
                return False
            return True
        except Exception as exc:
            print(f"[连接] 失败: {exc}")
            return False

    def start_background(self) -> None:
        self._tasks.append(asyncio.create_task(self._heartbeat_loop()))
        self._tasks.append(asyncio.create_task(self._log_worker()))

    async def aclose(self) -> None:
        self._closing = True
        try:
            await self._log_queue.join()
        except Exception:
            pass
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        if self.agent_id:
            try:
                await self._http.post(
                    f"{self.cfg.server_url}/api/reverse-agent/disconnect",
                    json={"agent_id": self.agent_id},
                    timeout=10.0,
                )
            except Exception:
                pass
        await self._http.aclose()

    # ── 心跳 ──────────────────────────────────────────────────────────
    async def _heartbeat_loop(self) -> None:
        while not self._closing:
            try:
                await self._http.post(
                    f"{self.cfg.server_url}/api/reverse-agent/heartbeat",
                    headers=self._auth_headers,
                    json={"agent_id": self.agent_id, "current_status": self.current_status},
                    timeout=15.0,
                )
            except Exception:
                pass
            await asyncio.sleep(self.cfg.heartbeat_interval_seconds)

    def set_status(self, status: str) -> None:
        self.current_status = status

    # ── 任务 ──────────────────────────────────────────────────────────
    async def next_task(self) -> Optional[Dict[str, Any]]:
        try:
            r = await self._http.get(
                f"{self.cfg.server_url}/api/reverse-agent/next-task",
                params={"agent_id": self.agent_id},
                timeout=30.0,
            )
            r.raise_for_status()
            data = r.json()
            return data if data.get("has_task") else None
        except Exception as exc:
            print(f"[任务] 领取失败: {exc}")
            return None

    async def session_context(self, session_id: str) -> Optional[Dict[str, Any]]:
        """获取会话完整上下文：Windows 事件 / IOCTL 记录 / 附着设备 / 进程树 / 取证文件。"""
        try:
            r = await self._http.get(
                f"{self.cfg.server_url}/api/reverse-agent/session-context/{quote(session_id)}",
                params={"agent_id": self.agent_id},
                timeout=120.0,
            )
            if r.status_code != 200:
                print(f"[上下文] 获取失败 HTTP {r.status_code}: {r.text[:200]}")
                return None
            return r.json()
        except Exception as exc:
            print(f"[上下文] 获取异常: {exc}")
            return None

    async def system_prompt(self, kind: str = "exe") -> str:
        try:
            r = await self._http.get(
                f"{self.cfg.server_url}/api/reverse-agent/system-prompt",
                params={"agent_id": self.agent_id, "kind": kind},
                timeout=20.0,
            )
            if r.status_code == 200:
                return (r.json().get("prompt") or "").strip()
        except Exception as exc:
            print(f"[提示词] 拉取失败: {exc}")
        return ""

    async def download(self, session_id: str, stored_name: str, dest: Path) -> Path:
        """下载取证文件到本地；已存在同名且非空文件时直接复用。"""
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.stat().st_size > 0:
            return dest
        url = (
            f"{self.cfg.server_url}/api/reverse-agent/download/"
            f"{quote(session_id)}/{quote(stored_name, safe='')}"
        )
        tmp = dest.with_suffix(dest.suffix + ".part")
        async with self._http.stream("GET", url, timeout=None) as resp:
            resp.raise_for_status()
            with tmp.open("wb") as fp:
                async for chunk in resp.aiter_bytes(1 << 20):
                    fp.write(chunk)
        tmp.replace(dest)
        return dest

    async def submit_report(
        self, session_id: str, result: str, content: str, file_name: str = ""
    ) -> bool:
        """提交报告。file_name 留空即为会话级总结报告（服务端记为 session_summary）。"""
        try:
            r = await self._http.post(
                f"{self.cfg.server_url}/api/reverse-agent/report",
                headers=self._auth_headers,
                data={
                    "session_id": session_id,
                    "agent_id": self.agent_id,
                    "file_name": file_name,
                    "result": result,
                },
                files={"content": (None, content)},
                timeout=120.0,
            )
            r.raise_for_status()
            return True
        except Exception as exc:
            print(f"[报告] 提交失败: {exc}")
            return False

    # ── 终端日志回放 ──────────────────────────────────────────────────
    def log(self, level: str, text: str, file: Optional[str] = None) -> None:
        """非阻塞投递日志。level: info | llm | tool_call | tool_result"""
        text = (text or "").strip()
        if not text or not self.session_id:
            return
        if len(text) > _LOG_MAX_CHARS:
            text = text[:_LOG_MAX_CHARS] + "\n...(输出过长已截断)"
        payload = {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "file": file,
            "level": level,
            "text": text,
        }
        try:
            self._log_queue.put_nowait(payload)
        except asyncio.QueueFull:
            pass

    async def _log_worker(self) -> None:
        while True:
            payload = await self._log_queue.get()
            try:
                await self._http.post(
                    f"{self.cfg.server_url}/api/reverse-agent/log",
                    json=payload,
                    timeout=20.0,
                )
            except Exception:
                pass
            finally:
                self._log_queue.task_done()


def human_size(n: int) -> str:
    size = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def now_ms() -> int:
    return int(time.time() * 1000)
