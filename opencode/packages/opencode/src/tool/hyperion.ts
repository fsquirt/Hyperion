/**
 * Hyperion 取证逆向工具集。
 *
 * 魔改点：让 opencode 从外部取证服务器领取任务、自主分析样本、提交报告。
 * - 任务由 TUI 首页调度领取（/api/reverse-agent/next-task），落盘运行时状态后派发
 * - swap_sample   切换当前分析的取证文件：下载样本 → 重启逆向引擎
 *                 （IDA 单实例：kill 旧实例 → 起新实例 → 动态刷新 MCP server）
 *                 → 会话下一步循环自动看到新 MCP 工具
 * - submit_report 提交会话级总结报告
 *
 * 配置独立于 opencode 配置系统：直接读工作目录下的 `appsettings.json`
 * （字段与 ReverseAgent 保持一致），可用 HYPERION_CONFIG 环境变量覆盖路径。
 * 工具不调用 ctx.ask，全程自动，不打断工作模式。
 */
import { execSync, spawn, type ChildProcess } from "node:child_process"
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import path from "node:path"
import { Effect, Schema } from "effect"
import type { ConfigMCPV1 } from "@opencode-ai/core/v1/config/mcp"
import { MCP } from "@/mcp"
import * as Tool from "./tool"

/** 工具 metadata：键值宽松，便于各分支返回不同字段。 */
type HyperionMeta = { [key: string]: any }

// ─────────────────────────── 配置加载 ──────────────────────────────────

export interface HyperionSettings {
  ServerUrl: string
  CredentialToken: string
  WorkDir: string
  IdaPath?: string
  IdaMcpCommand?: string
  IdaMcpUrl?: string
  IdaAnalysisWaitSeconds?: number
  IdaReadyTimeoutSeconds?: number
  WinDbgMcpCommand?: string
  WinDbgMcpArgs?: string[]
  SymbolPath?: string
}

const DEFAULTS = {
  WorkDir: path.join(process.cwd(), ".hyperion"),
  IdaMcpCommand: "ida-pro-mcp.exe",
  IdaMcpUrl: "http://127.0.0.1:13337/sse",
  IdaAnalysisWaitSeconds: 10,
  IdaReadyTimeoutSeconds: 120,
  WinDbgMcpCommand: "mcp-windbg",
  WinDbgMcpArgs: ["--transport", "stdio"],
  SymbolPath: "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
}

export type LoadResult = { ok: true; value: HyperionSettings } | { ok: false; error: string }

/** 从指定目录向上逐级查找 appsettings.json（含当前目录）。 */
export function findConfigUpward(startDir: string): string | undefined {
  let dir = path.resolve(startDir)
  for (;;) {
    const candidate = path.join(dir, "appsettings.json")
    if (existsSync(candidate)) return candidate
    const parent = path.dirname(dir)
    if (parent === dir) return undefined
    dir = parent
  }
}

export function loadSettings(): LoadResult {
  const candidates = [
    process.env.HYPERION_CONFIG,
    findConfigUpward(process.cwd()),
  ].filter((x): x is string => Boolean(x))
  const file = candidates.find((c) => existsSync(c))
  if (!file) {
    return {
      ok: false,
      error:
        "未找到 appsettings.json（已在当前目录及其上级目录查找；可用 HYPERION_CONFIG 环境变量指定路径）。",
    }
  }
  try {
    const raw = JSON.parse(readFileSync(file, "utf-8")) as Record<string, unknown>
    const value: HyperionSettings = { ...DEFAULTS, ...raw } as HyperionSettings
    if (!value.ServerUrl || !value.CredentialToken) {
      return { ok: false, error: `appsettings.json（${file}）缺少 ServerUrl 或 CredentialToken。` }
    }
    return { ok: true, value }
  } catch (err) {
    return { ok: false, error: `解析 appsettings.json（${file}）失败：${String(err)}` }
  }
}

// ─────────────────────────── 运行时状态 ────────────────────────────────

export const runtime = {
  agentId: "",
  agentToken: "",
  sessionId: "",
  machineName: "",
  taskFiles: [] as Array<Record<string, unknown>>,
  idaProc: null as ChildProcess | null,
  idaMcpProc: null as ChildProcess | null,
}

// ── 运行时状态持久化（文件媒介）──────────────────────────────────────
// TUI 首页（packages/tui）与工具（packages/opencode）同进程但不同包，
// 无法直接 import 彼此的内部单例。首页领到任务后把 sessionId/files 写入
// 该文件，工具执行 swap_sample / submit_report 时从此恢复 runtime，
// 从而不再依赖已被删除的 hyperion-worker 注入（现由 TUI 首页落盘注入）。

const RUNTIME_FILE = ".hyperion-runtime.json"

function runtimeFilePath(): string {
  const candidates = [
    process.env.HYPERION_CONFIG,
    findConfigUpward(process.cwd()),
  ].filter((x): x is string => Boolean(x))
  const cfg = candidates.find((c) => existsSync(c))
  const dir = cfg ? path.dirname(cfg) : process.cwd()
  return path.join(dir, RUNTIME_FILE)
}

/**
 * 工具执行前调用：从 .hyperion-runtime.json 恢复当前轮次的任务上下文。
 * 连续任务模式下 TUI 会开启新一轮（新 session + 新 agent token）：
 * 若磁盘上的 sessionId 与内存不一致，以磁盘为准整体覆盖，
 * 防止上一轮的 sessionId / agentToken / 任务文件残留导致下载旧样本、报告提交到旧会话。
 * 返回是否拿到了 sessionId。
 */
export function hydrateRuntimeFromDisk(): boolean {
  try {
    const p = runtimeFilePath()
    if (!existsSync(p)) return !!runtime.sessionId
    const data = JSON.parse(readFileSync(p, "utf-8")) as {
      sessionId?: string
      machineName?: string
      agentId?: string
      agentToken?: string
      taskFiles?: Array<Record<string, unknown>>
    }

    // 磁盘没有任务记录（TUI 已清空/尚未领到任务）：保留内存现状
    if (!data.sessionId) return !!runtime.sessionId

    // 同一轮任务：内存已是最新，避免无谓读盘
    if (runtime.sessionId && runtime.sessionId === data.sessionId) return true

    // 新轮次（连续模式）：以磁盘为准整体覆盖，清除上一轮残留
    runtime.sessionId = data.sessionId
    runtime.machineName = data.machineName ?? ""
    runtime.agentId = data.agentId ?? runtime.agentId
    runtime.agentToken = data.agentToken ?? runtime.agentToken
    runtime.taskFiles = Array.isArray(data.taskFiles) ? data.taskFiles : []
    return true
  } catch {
    // 磁盘读取失败：保留内存现状，按现有值判断是否可用
    return !!runtime.sessionId
  }
}

// ─────────────────────────── 分析日志回传 ─────────────────────────────
// 由 opencode 会话处理器（session/processor.ts）在会话进行中实时调用，
// 把 LLM 消息 / 工具调用 / 工具结果动态上报到服务端，供 Web 端研判回放。
// 非 Hyperion 工作会话（runtime.sessionId 为空）时静默跳过。

export function postAnalysisLog(level: string, text: string, file?: string): void {
  // 确保运行时状态已从首页落盘恢复（tool-call 事件可能早于 swap_sample 触发）
  if (!runtime.sessionId) {
    try {
      if (!hydrateRuntimeFromDisk()) return
    } catch {
      return
    }
  }
  if (!runtime.sessionId || !runtime.agentId) return
  const cfg = loadSettings()
  if (!cfg.ok) return
  const trimmed = (text ?? "").slice(0, 60000)
  if (!trimmed.trim()) return
  void apiFetch(cfg.value.ServerUrl, cfg.value.CredentialToken, "/api/reverse-agent/log", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      agent_id: runtime.agentId,
      session_id: runtime.sessionId,
      file: file ?? "",
      level,
      text: trimmed,
    }),
  }).catch(() => {})
}

export const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

export async function apiFetch(
  base: string,
  token: string,
  pathname: string,
  init?: RequestInit,
): Promise<Response> {
  const res = await fetch(base + pathname, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      // 已 connect 拿到 agent token 后，后续所有 Agent 端点用它做身份凭据
      ...(runtime.agentToken ? { "X-Agent-Token": runtime.agentToken } : {}),
      ...(init?.headers ?? {}),
    },
  })
  if (!res.ok) {
    const body = (await res.text().catch(() => "")).slice(0, 300)
    throw new Error(`HTTP ${res.status} ${pathname}: ${body}`)
  }
  return res
}

export async function ensureAgent(s: HyperionSettings): Promise<string> {
  if (runtime.agentId && runtime.agentToken) return runtime.agentId
  const res = await apiFetch(s.ServerUrl, s.CredentialToken, "/api/reverse-agent/connect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  })
  const data = (await res.json()) as Record<string, unknown>
  const id = String(data.agent_id ?? "")
  const token = String(data.agent_token ?? "")
  if (!id || !token) throw new Error("connect 未返回 agent_id/agent_token")
  runtime.agentId = id
  runtime.agentToken = token
  return id
}

export function humanSize(n: unknown): string {
  let size = Number(n || 0)
  if (!Number.isFinite(size) || size < 0) return "?"
  for (const unit of ["B", "KB", "MB", "GB"]) {
    if (size < 1024) return `${size.toFixed(1)}${unit}`
    size /= 1024
  }
  return `${size.toFixed(1)}TB`
}

export function suggestEngine(name: string): string {
  return /\.(dmp|mdmp|hdmp)$/i.test(name) ? "windbg" : "ida"
}

// ─────────────────────────── 进程管理（IDA 单实例）─────────────────────

function killProc(proc: ChildProcess | null): void {
  if (!proc || proc.exitCode !== null) return
  try {
    execSync(`taskkill /F /T /PID ${proc.pid}`, { stdio: "ignore", windowsHide: true })
  } catch {
    // ignore
  }
}

function killIdaMcp(): void {
  try {
    execSync("taskkill /F /IM ida-pro-mcp.exe", { stdio: "ignore", windowsHide: true })
  } catch {
    // ignore
  }
}

// ─────────────────────────── 任务简报（调度器注入用）────────────────────

/** 把任务渲染成给 agent 的首轮 prompt（任务信息由 TUI 首页写入 .hyperion-runtime.json 供工具恢复）。 */
export function buildTaskBrief(sessionId: string, machineName: string, taskFiles: Array<Record<string, unknown>>): string {
  const files = (taskFiles || [])
    .map((f) => {
      const name = String(f.name ?? f.storedName ?? "?")
      const size = humanSize(f.size)
      const engine = suggestEngine(name)
      return `- ${name}（${size}，引擎：${engine}）`
    })
    .join("\n")

  return [
    `# 新的取证任务`,
    `- 会话 ID：${sessionId}`,
    `- 来源主机：${machineName || "未知"}`,
    ``,
    `## 待分析取证文件`,
    files || "（无）",
    ``,
    `## 工作流`,
    `1. 用 swap_sample 逐个加载上面的文件（自动下载 + 启动分析引擎）。`,
    `2. 用引擎 MCP 工具（ida_* / windbg_*）对每个样本做反作弊向逆向分析。`,
    `3. 所有文件分析完成后，用 submit_report 提交会话级总结报告，然后结束。`,
    ``,
    `## 纪律`,
    `- 任务由调度器自动分配，你**不要**尝试领取或等待新任务，只处理本会话。`,
    `- 提交报告后停止，等待调度器分配下一个任务。`,
  ].join("\n")
}

// ─────────────────────────── submit_report ─────────────────────────────

const SUBMIT_DESCRIPTION = `提交当前取证会话的总结报告（一个会话只提交一次）。

Args:
- result: 判定结论，只能是 normal / suspicious / cheat 三者之一：
  - normal：未发现作弊相关行为；
  - suspicious：存在可疑行为但证据不足以定性；
  - cheat：证实存在作弊 / 内核作弊 / 反作弊对抗行为。
- content: Markdown 格式的完整会话总结报告（结论、宿主机行为证据、
  样本逐个分析、攻击链还原、判定依据、残留疑点）。

提交成功即表示该会话处理完毕；停止当前会话，等待 TUI 调度下一个任务。`

export const SubmitReportParameters = Schema.Struct({
  result: Schema.String.annotate({ description: "判定结论：normal / suspicious / cheat" }),
  content: Schema.String.annotate({ description: "Markdown 格式的会话总结报告" }),
})

export const SubmitReportTool = Tool.define<typeof SubmitReportParameters, HyperionMeta, never>(
  "submit_report",
  Effect.gen(function* () {
    return {
      description: SUBMIT_DESCRIPTION,
      parameters: SubmitReportParameters,
      execute: (params) =>
        Effect.gen(function* () {
          if (!hydrateRuntimeFromDisk()) {
            return { title: "submit_report 失败", output: "尚未领取任务（任务由 TUI 调度器分配）。", metadata: {} }
          }
          const cfg = loadSettings()
          if (!cfg.ok) return { title: "submit_report 失败", output: cfg.error, metadata: {} }
          const s = cfg.value
          yield* Effect.tryPromise(() => ensureAgent(s))

          const verdict = params.result.trim().toLowerCase()
          if (!["normal", "suspicious", "cheat"].includes(verdict)) {
            return {
              title: "submit_report 失败",
              output: "result 非法，只能是 normal / suspicious / cheat 之一。",
              metadata: {},
            }
          }
          if (!params.content.trim()) {
            return { title: "submit_report 失败", output: "报告内容为空，拒绝提交。", metadata: {} }
          }

          yield* Effect.tryPromise(async () => {
            const form = new FormData()
            form.append("session_id", runtime.sessionId)
            form.append("file_name", "")
            form.append("result", verdict)
            form.append("content", params.content)
            await apiFetch(s.ServerUrl, s.CredentialToken, "/api/reverse-agent/report", {
              method: "POST",
              headers: { Accept: "*/*" },
              body: form,
            })
          })

          return {
            title: `报告已提交（${verdict}）`,
            output: `会话 ${runtime.sessionId} 的总结报告已提交，判定 = ${verdict}。请停止当前会话，等待 TUI 调度下一个任务。`,
            metadata: { verdict, sessionId: runtime.sessionId },
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ─────────────────────────── swap_sample ───────────────────────────────

const SWAP_DESCRIPTION = `切换当前分析的取证文件：下载样本到本地，重启对应的逆向分析引擎，
并把引擎的 MCP server 动态挂载到当前会话（下一步循环即可使用其工具）。

IDA 实例全局唯一：分析静态样本（exe/dll/sys/…）时会先终止上一个 IDA
与 ida-pro-mcp 进程，再启动新实例加载目标文件，因此逐个调用、串行分析。

Args:
- file_name: 取证文件名（来自调度器分配的任务文件列表）。

返回加载结果与可用的 MCP 工具命名空间（ida_* 或 windbg_*）。

注意：
- 分析 .dmp 崩溃转储走 mcp-windbg（stdio，可并发多实例，文件名会生成唯一 server 名）；
- 其他文件走 IDA Pro（SSE，固定 server 名 ida-pro-mcp）。
- 引擎启动需要时间（IDA 自动分析约 10s，首次更久），如果返回 failed 状态，
  可稍后重试一次。`

export const SwapSampleParameters = Schema.Struct({
  file_name: Schema.String.annotate({ description: "取证文件名（任务文件列表中的 name）" }),
})

export const SwapSampleTool = Tool.define<typeof SwapSampleParameters, HyperionMeta, MCP.Service>(
  "swap_sample",
  Effect.gen(function* () {
    const mcp = yield* MCP.Service
    return {
      description: SWAP_DESCRIPTION,
      parameters: SwapSampleParameters,
      execute: (params) =>
        Effect.gen(function* () {
          if (!hydrateRuntimeFromDisk()) {
            return { title: "swap_sample 失败", output: "尚未领取任务（任务由 TUI 调度器分配）。", metadata: {} }
          }
          const cfg = loadSettings()
          if (!cfg.ok) return { title: "swap_sample 失败", output: cfg.error, metadata: {} }
          const s = cfg.value
          yield* Effect.tryPromise(() => ensureAgent(s))

          const wanted = params.file_name.trim()
          const entry = runtime.taskFiles.find(
            (f) =>
              String(f.name ?? "") === wanted ||
              String(f.storedName ?? f.stored_name ?? "") === wanted,
          )
          if (!entry) {
            const names = runtime.taskFiles.map((f) => String(f.name ?? "?")).join("、")
            return {
              title: "swap_sample 失败",
              output: `任务文件列表中没有 "${wanted}"。已有：${names || "（空）"}`,
              metadata: {},
            }
          }

          const name = String(entry.name ?? wanted)
          const stored = String(entry.storedName ?? entry.stored_name ?? name)

          // 1. 下载样本
          const sampleDir = path.join(s.WorkDir, "samples", runtime.sessionId)
          const dest = path.join(sampleDir, name)
          yield* Effect.tryPromise(async () => {
            mkdirSync(sampleDir, { recursive: true })
            if (!existsSync(dest) || readFileSync(dest).length === 0) {
              const res = await apiFetch(
                s.ServerUrl,
                s.CredentialToken,
                `/api/reverse-agent/download/${encodeURIComponent(runtime.sessionId)}/${encodeURIComponent(stored)}`,
              )
              writeFileSync(dest, Buffer.from(await res.arrayBuffer()))
            }
          })

          const isDump = /\.(dmp|mdmp|hdmp)$/i.test(name)

          if (isDump) {
            // 2a. WinDbg：stdio MCP，可并发，唯一命名
            const serverName = `windbg-${name.replace(/[^a-zA-Z0-9_-]/g, "_")}`
            yield* mcp.disconnect(serverName).pipe(Effect.catchCause(() => Effect.void))
            const config: ConfigMCPV1.Info = {
              type: "local",
              command: [s.WinDbgMcpCommand ?? "mcp-windbg", ...(s.WinDbgMcpArgs ?? [])],
              cwd: sampleDir,
              environment: s.SymbolPath ? { _NT_SYMBOL_PATH: s.SymbolPath } : undefined,
              timeout: 300_000,
            }
            const result = yield* mcp.add(serverName, config)
            const st = "status" in result ? result.status : result
            const map = (typeof st === "object" && st !== null ? st : {}) as Record<string, { status?: string }>
            const ok = map[serverName]?.status === "connected"
            return {
              title: ok ? `WinDbg 已加载：${name}` : `WinDbg 加载失败：${name}`,
              output: ok
                ? `已下载 ${name} → ${dest}，并挂载 mcp-windbg（server: ${serverName}）。\n`
                  + `可用工具前缀：${serverName}_*（!analyze -v / k / lm / !drvobj 等）。\n`
                  + `注意：${name} 是 .dmp 崩溃转储，取证价值通常较低，只做快速核验即可`
                  + `（崩溃模块/异常地址、已加载的可疑驱动与模块、注入迹象），不要深挖线程栈或做全面内存遍历。`
                : `已下载 ${name}，但 mcp-windbg 连接失败：${JSON.stringify(st)}。可稍后重试。`,
              metadata: { file: name, server: serverName, engine: "windbg" },
            }
          }

          // 2b. IDA：单实例，kill 旧的 → 起新的 → 刷新 MCP
          const idaExe = s.IdaPath
          if (!idaExe || !existsSync(idaExe)) {
            return {
              title: "swap_sample 失败",
              output: `未配置有效的 IdaPath（${idaExe ?? "空"}），无法分析静态样本。`,
              metadata: {},
            }
          }

          killProc(runtime.idaProc)
          killProc(runtime.idaMcpProc)
          killIdaMcp()
          runtime.idaProc = null
          runtime.idaMcpProc = null
          yield* Effect.promise(() => sleep(1000))

          // 起 IDA 本体自动分析
          runtime.idaProc = yield* Effect.tryPromise(
            () =>
              new Promise<ChildProcess>((resolve, reject) => {
                const proc = spawn(idaExe, ["-A", "-c", "-Opdb:fallback", dest], {
                  cwd: sampleDir,
                  stdio: "ignore",
                  windowsHide: true,
                })
                proc.once("error", reject)
                resolve(proc)
              }),
          )
          yield* Effect.promise(() => sleep((s.IdaAnalysisWaitSeconds ?? 10) * 1000))
          const idaExit = runtime.idaProc.exitCode
          if (idaExit !== null) {
            killProc(runtime.idaProc)
            runtime.idaProc = null
            return {
              title: "swap_sample 失败",
              output: `IDA 在自动分析阶段提前退出（exit=${idaExit}），样本可能损坏或不被支持。`,
              metadata: {},
            }
          }

          // 起 ida-pro-mcp（独立进程，暴露 SSE）
          runtime.idaMcpProc = yield* Effect.tryPromise(
            () =>
              new Promise<ChildProcess>((resolve, reject) => {
                const proc = spawn(s.IdaMcpCommand ?? "ida-pro-mcp.exe", [], {
                  cwd: sampleDir,
                  stdio: "ignore",
                  windowsHide: true,
                })
                proc.once("error", reject)
                resolve(proc)
              }),
          )
          yield* Effect.promise(() => sleep(5000))

          // 动态刷新会话 MCP：断开旧的 → 连接新的（agent 下一步循环即见新工具）
          const deadline = Date.now() + (s.IdaReadyTimeoutSeconds ?? 120) * 1000
          let connected = false
          let lastStatus = ""
          while (Date.now() < deadline) {
            yield* mcp.disconnect("ida-pro-mcp").pipe(Effect.catchCause(() => Effect.void))
            const result = yield* mcp.add("ida-pro-mcp", {
              type: "remote",
              url: s.IdaMcpUrl ?? "http://127.0.0.1:13337/sse",
              timeout: 900_000,
            })
            const st = "status" in result ? result.status : result
            const map = (typeof st === "object" && st !== null ? st : {}) as Record<string, { status?: string }>
            const self = map["ida-pro-mcp"] ?? map
            lastStatus = String((typeof self === "object" && self !== null ? self.status : self) ?? "")
            if (lastStatus === "connected") {
              connected = true
              break
            }
            yield* Effect.promise(() => sleep(3000))
          }

          if (!connected) {
            killProc(runtime.idaProc)
            killProc(runtime.idaMcpProc)
            killIdaMcp()
            runtime.idaProc = null
            runtime.idaMcpProc = null
            return {
              title: `IDA 加载失败：${name}`,
              output: `ida-pro-mcp 等待超时，最后状态：${lastStatus}。可稍后重试（检查 IDA 是否成功分析样本）。`,
              metadata: { file: name },
            }
          }

          return {
            title: `IDA 已加载：${name}`,
            output: [
              `已下载 ${name} → ${dest}，IDA 自动分析完成，ida-pro-mcp 已挂载（server: ida-pro-mcp）。`,
              ``,
              `可用工具前缀：ida_*（metadata / imports / decompile / disasm / get_bytes / find_regex 等）。`,
              `建议先看 metadata 与字符串，再按任务线索定位关键函数（DriverEntry、IRP 分发、控制码分支）。`,
              ``,
              `分析完这个文件后，用 swap_sample 加载下一个文件；全部完成后用 submit_report 提交报告。`,
              ``,
              `若需下载辅助工具（如脱壳器）或运行命令，中间产物一律写到 ${s.WorkDir}\\.tmp\\ 下，禁止写入系统临时目录。`,
            ].join("\n"),
            metadata: { file: name, server: "ida-pro-mcp", engine: "ida" },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
