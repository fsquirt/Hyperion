"""会话取证上下文。

对应服务端 `GET /api/reverse-agent/session-context/{sessionId}` 返回的
TrackerSessionDetail：Windows 事件、IOCTL 通信记录、附着设备列表、
进程树快照、取证文件列表。

设计要点：
- 整份上下文可能非常大（事件带原始 EVTX XML、进程树快照是完整 JSON），
  直接塞进提示词会撑爆上下文窗口。
- 因此这里只把**摘要**注入主 Agent 的首轮输入，细节通过工具按需查询。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

ANALYZABLE_EXTS = (".exe", ".dll", ".sys", ".pyd", ".ocx", ".dmp")
DUMP_EXTS = (".dmp", ".mdmp", ".hdmp")


def _clip(text: Optional[str], limit: int) -> str:
    s = (text or "").strip()
    if len(s) <= limit:
        return s
    return s[:limit] + f"…(共{len(s)}字符，已截断)"


def _size(n: Any) -> str:
    try:
        size = float(n or 0)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}TB"


@dataclass
class SessionContext:
    """一次取证会话的全部上下文，主 Agent 与工具共享同一实例。"""

    session_id: str
    machine_name: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    task_files: List[Dict[str, Any]] = field(default_factory=list)

    # ── 分片访问 ──────────────────────────────────────────────────────
    @property
    def events(self) -> List[Dict[str, Any]]:
        return self.raw.get("events") or []

    @property
    def ioctl_counts(self) -> Dict[str, Any]:
        return ((self.raw.get("ioctlStats") or {}).get("IoctlCounts")) or {}

    @property
    def ioctl_modules(self) -> List[str]:
        return ((self.raw.get("ioctlStats") or {}).get("Modules")) or []

    @property
    def devices(self) -> List[Dict[str, Any]]:
        return self.raw.get("attachedDevices") or []

    @property
    def file_entries(self) -> List[Dict[str, Any]]:
        return self.raw.get("fileEntries") or []

    @property
    def snapshots(self) -> List[str]:
        return self.raw.get("snapshots") or []

    @property
    def policy(self) -> Dict[str, Any]:
        return self.raw.get("policy") or {}

    def find_file(self, name: str) -> Optional[Dict[str, Any]]:
        """按显示名或落地名匹配取证文件（优先 task_files，其次全量 fileEntries）。"""
        key = (name or "").strip().lower()
        if not key:
            return None
        for pool in (self.task_files, self.file_entries):
            for f in pool:
                if key in (
                    str(f.get("name", "")).lower(),
                    str(f.get("storedName", "")).lower(),
                    str(f.get("stored_name", "")).lower(),
                ):
                    return f
        return None

    # ── 摘要渲染 ──────────────────────────────────────────────────────
    def render_overview(self) -> str:
        r = self.raw
        lines: List[str] = []
        lines.append("# 取证会话上下文")
        lines.append("")
        lines.append(f"- 会话 ID：`{self.session_id}`")
        lines.append(f"- 机器名：{r.get('machineName') or self.machine_name or '未知'}")
        lines.append(f"- 被监控进程 PID：{r.get('pid', '未知')}")
        lines.append(f"- 采集起止：{r.get('startedAt', '?')} → {r.get('endedAt') or '进行中'}")
        lines.append(f"- 会话状态：{r.get('status', '?')}")
        lines.append(
            f"- 规模：事件 {len(self.events)} 条 / IOCTL 控制码 {len(self.ioctl_counts)} 种 / "
            f"附着设备 {len(self.devices)} 个 / 进程树快照 {len(self.snapshots)} 份 / "
            f"取证文件 {len(self.file_entries)} 个"
        )
        lines.append("")
        lines.append(self.render_ioctl())
        lines.append("")
        lines.append(self.render_devices())
        lines.append("")
        lines.append(self.render_events(limit=25, detail_chars=200))
        lines.append("")
        lines.append(self.render_files())
        lines.append("")
        lines.append(
            "> 以上为摘要。完整 Windows 事件（含原始 EVTX XML）、完整 IOCTL 表、"
            "完整进程树快照请调用 `query_session_context` 工具按需获取。"
        )
        return "\n".join(lines)

    def render_ioctl(self) -> str:
        counts = self.ioctl_counts
        if not counts:
            return "## IOCTL 通信记录\n\n（本会话未捕获到 IOCTL 通信）"
        ordered = sorted(counts.items(), key=lambda kv: _as_int(kv[1]), reverse=True)
        lines = ["## IOCTL 通信记录", "", "| 控制码 | 调用次数 |", "| --- | --- |"]
        for code, cnt in ordered:
            lines.append(f"| `{code}` | {cnt} |")
        mods = self.ioctl_modules
        if mods:
            lines.append("")
            lines.append("发起 IOCTL 的模块：")
            lines.extend(f"- `{m}`" for m in mods)
        return "\n".join(lines)

    def render_devices(self) -> str:
        devs = self.devices
        if not devs:
            return "## 附着设备列表\n\n（无附着设备记录）"
        lines = [
            "## 附着设备列表",
            "",
            "| AttachId | 设备名 | 目标路径 |",
            "| --- | --- | --- |",
        ]
        for d in devs:
            lines.append(
                f"| {d.get('attachId', '')} | `{d.get('deviceName', '')}` | `{d.get('targetPath', '')}` |"
            )
        return "\n".join(lines)

    def render_events(
        self,
        limit: int = 25,
        detail_chars: int = 200,
        keyword: str = "",
        include_xml: bool = False,
    ) -> str:
        evts: Iterable[Dict[str, Any]] = self.events
        if keyword:
            k = keyword.lower()
            evts = [
                e
                for e in self.events
                if k in json.dumps(e, ensure_ascii=False).lower()
            ]
        evts = list(evts)
        total = len(evts)
        shown = evts[:limit] if limit > 0 else evts

        head = f"## Windows 事件（命中 {total} 条，展示 {len(shown)} 条）"
        if not shown:
            return head + "\n\n（无匹配事件）"
        lines = [head, ""]
        for i, e in enumerate(shown, 1):
            lines.append(
                f"{i}. [{e.get('level', 'INFO')}] {e.get('timestamp', '')} "
                f"<{e.get('source', '')}/{e.get('type', '')}> {e.get('title', '')}"
            )
            det = _clip(e.get("detail"), detail_chars)
            if det:
                lines.append(f"   - detail: {det}")
            if include_xml and e.get("xml"):
                lines.append(f"   - xml: {_clip(e.get('xml'), 4000)}")
        if total > len(shown):
            lines.append("")
            lines.append(f"（另有 {total - len(shown)} 条未展示，可调整 limit / keyword 继续查询）")
        return "\n".join(lines)

    def render_process_tree(self, index: int = -1, max_chars: int = 12000) -> str:
        snaps = self.snapshots
        if not snaps:
            return "## 进程树快照\n\n（无快照）"
        idx = index if 0 <= index < len(snaps) else len(snaps) - 1
        raw = snaps[idx]
        try:
            parsed = json.loads(raw)
            pretty = json.dumps(parsed, ensure_ascii=False, indent=1)
        except Exception:
            pretty = raw
        return (
            f"## 进程树快照 #{idx + 1}/{len(snaps)}\n\n```json\n"
            f"{_clip(pretty, max_chars)}\n```"
        )

    def render_files(self) -> str:
        entries = self.file_entries
        task = {
            str(f.get("stored_name") or f.get("storedName") or "").lower()
            for f in self.task_files
        }
        if not entries and not self.task_files:
            return "## 取证文件列表\n\n（无取证文件）"

        lines = [
            "## 取证文件列表",
            "",
            "| 文件名 | 类型 | 大小 | 采集时间 | 原始路径 | 可分析 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        pool = entries or self.task_files
        for f in pool:
            name = f.get("name", "")
            stored = str(f.get("storedName") or f.get("stored_name") or "")
            analyzable = "是" if (stored.lower() in task or _is_analyzable(name)) else "否"
            lines.append(
                f"| `{name}` | {f.get('kind', '')} | {_size(f.get('size'))} | "
                f"{f.get('time', '')} | `{f.get('path', '')}` | {analyzable} |"
            )
        lines.append("")
        lines.append("待分析文件（服务端已筛出，可直接用 `download_forensic_file` 下载）：")
        if self.task_files:
            for f in self.task_files:
                lines.append(
                    f"- `{f.get('name')}`（{_size(f.get('size'))}，kind={f.get('kind', '')}，"
                    f"引擎建议={suggest_engine(f.get('name', ''))}）"
                )
        else:
            lines.append("- （无）")
        return "\n".join(lines)

    def render_policy(self) -> str:
        p = self.policy
        if not p:
            return "## 客户端策略\n\n（无）"
        lines = ["## 客户端策略", ""]
        kf = p.get("kernelFuncs") or []
        if kf:
            lines.append(f"- 受监控内核函数（{len(kf)}）：" + ", ".join(f"`{x}`" for x in kf[:80]))
        certs = p.get("whitelistCertSubjects") or []
        if certs:
            lines.append(f"- 白名单证书主体（{len(certs)}）：" + ", ".join(certs[:40]))
        hashes = p.get("whitelistHashes") or []
        if hashes:
            lines.append(f"- 白名单哈希：{len(hashes)} 条")
        return "\n".join(lines)


def _as_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _is_analyzable(name: str) -> bool:
    return str(name or "").lower().endswith(ANALYZABLE_EXTS)


def suggest_engine(file_name: str) -> str:
    """按扩展名推断应使用的分析引擎。"""
    return "windbg" if str(file_name or "").lower().endswith(DUMP_EXTS) else "ida"


def ioctl_brief(ctx: SessionContext, max_codes: int = 24) -> str:
    """给子 Agent 的极简 IOCTL/设备线索，避免子 Agent 上下文过载。"""
    parts: List[str] = []
    codes = sorted(ctx.ioctl_counts.items(), key=lambda kv: _as_int(kv[1]), reverse=True)
    if codes:
        parts.append(
            "本会话捕获到的 IOCTL 控制码（按调用次数降序）："
            + "、".join(f"{c}(x{n})" for c, n in codes[:max_codes])
        )
    if ctx.ioctl_modules:
        parts.append("发起 IOCTL 的模块：" + "、".join(ctx.ioctl_modules[:20]))
    if ctx.devices:
        parts.append(
            "被附着的设备："
            + "、".join(
                f"{d.get('deviceName', '')}→{d.get('targetPath', '')}" for d in ctx.devices[:20]
            )
        )
    return "\n".join(parts) if parts else "（本会话未捕获到 IOCTL / 设备附着记录）"
