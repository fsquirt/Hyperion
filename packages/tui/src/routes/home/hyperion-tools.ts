/**
 * Hyperion 首页 debug 测试工具（纯程序检测，不经过 LLM）。
 *
 * - testIda(filePath)：启动 IDA 自动分析 → 等 10s → 启动 ida-pro-mcp → 等 5s
 *   → 探测 SSE 端点确认 MCP 正常 → taskkill ida.exe / ida-pro-mcp.exe 清理。
 * - testWindbg()：启动 mcp-windbg（stdio）→ JSON-RPC initialize + tools/list
 *   → 确认 MCP 正常 → 终止进程。
 *
 * 所有检测都在 TUI 进程内完成（spawn 子进程 + HTTP/stdio 探测）。
 */
import { execSync, spawn, type ChildProcess } from "node:child_process"
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs"
import path from "node:path"

// ─────────────────────────── 配置 ──────────────────────────────────────

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

export function configPath(): string | undefined {
  const env = process.env.HYPERION_CONFIG
  if (env && existsSync(env)) return env
  return findConfigUpward(process.cwd())
}

export function readConfig(): Record<string, unknown> {
  const file = configPath()
  if (!file) throw new Error("未找到配置文件（已从当前目录向上查找，或用 HYPERION_CONFIG 指定）")
  try {
    return JSON.parse(readFileSync(file, "utf-8")) as Record<string, unknown>
  } catch (err) {
    throw new Error(`解析 ${file} 失败：${String(err)}`)
  }
}

export function maskToken(token: unknown): string {
  const t = String(token ?? "")
  if (!t) return "(未设置)"
  if (t.length <= 10) return "***"
  return `${t.slice(0, 6)}…${t.slice(-4)}`
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

function taskkillByName(name: string): void {
  try {
    execSync(`taskkill /F /IM ${name}`, { stdio: "ignore", windowsHide: true })
  } catch {
    // ignore
  }
}

// ─────────────────────────── 测试 IDA ──────────────────────────────────

export type TestResult = {
  ok: boolean
  steps: string[]
  error?: string
}

function configValue(key: string, fallback: string): string {
  try {
    const cfg = readConfig()
    return String(cfg[key] ?? fallback)
  } catch {
    return fallback
  }
}

/**
 * 测试 IDA 链路：ida.exe 启动样本 → 等 10s → ida-pro-mcp → 等 5s → 探测 SSE。
 * 无论成败最后 taskkill ida.exe / ida-pro-mcp.exe。
 */
export async function testIda(filePath: string): Promise<TestResult> {
  const steps: string[] = []
  const idaExe = configValue("IdaPath", "C:\\IDA Professional 9.4\\ida.exe")
  const idaMcpCmd = configValue("IdaMcpCommand", "ida-pro-mcp.exe")
  const idaMcpUrl = configValue("IdaMcpUrl", "http://127.0.0.1:13337/sse")

  if (!existsSync(idaExe)) {
    return { ok: false, steps: [`IDA 可执行文件不存在：${idaExe}`], error: "未找到 IDA（检查 appsettings.json 的 IdaPath）" }
  }
  if (!existsSync(filePath)) {
    return { ok: false, steps: [`样本文件不存在：${filePath}`], error: "文件不存在" }
  }

  let idaProc: ChildProcess | undefined
  let mcpProc: ChildProcess | undefined
  try {
    steps.push(`启动 IDA：${idaExe} -A -c ${path.basename(filePath)}`)
    idaProc = spawn(idaExe, ["-A", "-c", "-Opdb:fallback", filePath], {
      cwd: path.dirname(filePath),
      stdio: "ignore",
      windowsHide: true,
    })
    steps.push("等待 10 秒让 IDA 自动分析…")
    await sleep(10_000)
    if (idaProc.exitCode !== null) {
      return { ok: false, steps, error: `IDA 提前退出（exit=${idaProc.exitCode}），样本可能损坏` }
    }
    steps.push(`启动 ida-pro-mcp：${idaMcpCmd}`)
    mcpProc = spawn(idaMcpCmd, [], { cwd: path.dirname(filePath), stdio: "ignore", windowsHide: true })
    steps.push("等待 5 秒让 MCP 就绪…")
    await sleep(5_000)
    steps.push(`探测 MCP SSE：${idaMcpUrl}`)
    const probe = await probeSse(idaMcpUrl, 10_000)
    if (!probe.ok) {
      return { ok: false, steps, error: `IDA MCP 探测失败：${probe.error}` }
    }
    steps.push("✅ IDA MCP 正常（SSE 端点响应正常）")
    return { ok: true, steps }
  } catch (err) {
    return { ok: false, steps, error: String(err) }
  } finally {
    steps.push("清理：taskkill ida.exe / ida-pro-mcp.exe")
    taskkillByName("ida.exe")
    taskkillByName("ida64.exe")
    taskkillByName("idat.exe")
    taskkillByName("idat64.exe")
    taskkillByName("ida-pro-mcp.exe")
    try {
      if (idaProc && idaProc.exitCode === null) idaProc.kill()
      if (mcpProc && mcpProc.exitCode === null) mcpProc.kill()
    } catch {
      // ignore
    }
  }
}

async function probeSse(url: string, timeoutMs: number): Promise<{ ok: boolean; error?: string }> {
  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) })
    if (!resp.ok) return { ok: false, error: `HTTP ${resp.status}` }
    const ctype = resp.headers.get("content-type") ?? ""
    if (!ctype.includes("text/event-stream") && !ctype.includes("text/plain") && !ctype.includes("application/json")) {
      // 某些实现不返回标准 content-type，连接建立即视为存活
    }
    await resp.body?.getReader().cancel().catch(() => {})
    return { ok: true }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

// ─────────────────────────── 测试 WinDbg ───────────────────────────────

/**
 * 测试 WinDbg：启动 mcp-windbg（stdio）→ JSON-RPC initialize + tools/list。
 */
export async function testWindbg(): Promise<TestResult> {
  const steps: string[] = []
  const mcpCmd = configValue("WinDbgMcpCommand", "mcp-windbg")
  const symbolPath = configValue("SymbolPath", "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols")

  let proc: ChildProcess | undefined
  try {
    steps.push(`启动 mcp-windbg：${mcpCmd} --transport stdio`)
    const env = { ...process.env, _NT_SYMBOL_PATH: symbolPath }
    proc = spawn(mcpCmd, ["--transport", "stdio"], {
      stdio: ["pipe", "pipe", "pipe"],
      env,
      windowsHide: true,
    })

    const result = await stdioMcpProbe(proc, 20_000)
    if (!result.ok) {
      return { ok: false, steps, error: `WinDbg MCP 检查失败：${result.error ?? "未知错误"}` }
    }
    steps.push(`✅ WinDbg MCP 正常（initialize 成功，工具 ${result.tools ?? "?"} 个）`)
    return { ok: true, steps }
  } catch (err) {
    return { ok: false, steps, error: String(err) }
  } finally {
    steps.push("清理：终止 mcp-windbg")
    try {
      if (proc && proc.exitCode === null) proc.kill()
    } catch {
      // ignore
    }
  }
}

function stdioMcpProbe(
  proc: ChildProcess,
  timeoutMs: number,
): Promise<{ ok: boolean; error?: string; tools?: number }> {
  return new Promise((resolve) => {
    let buf = ""
    let settled = false
    let initialized = false
    const stderrBuf: string[] = []

    const finish = (result: { ok: boolean; error?: string; tools?: number }) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(result)
    }

    const timer = setTimeout(() => {
      finish({ ok: false, error: "等待响应超时" })
      try {
        proc.kill()
      } catch {
        // ignore
      }
    }, timeoutMs)

    proc.stdout?.on("data", (chunk: Buffer) => {
      buf += chunk.toString()
      let idx: number
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim()
        buf = buf.slice(idx + 1)
        if (!line) continue
        let msg: { id?: number; result?: unknown; error?: { message?: string }; method?: string }
        try {
          msg = JSON.parse(line) as typeof msg
        } catch {
          continue
        }
        if (msg.method === "notifications/initialized" || msg.method === "notifications/message") continue
        if (msg.id === 1 && msg.result) {
          initialized = true
          // 发 tools/list
          proc.stdin?.write(
            JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n",
          )
        } else if (msg.id === 2 && msg.result) {
          const tools = Array.isArray((msg.result as { tools?: unknown[] }).tools)
            ? (msg.result as { tools: unknown[] }).tools.length
            : 0
          finish({ ok: true, tools })
        } else if (msg.error) {
          finish({ ok: false, error: msg.error.message ?? "JSON-RPC 错误" })
        }
      }
    })

    proc.stderr?.on("data", (chunk: Buffer) => {
      const text = chunk.toString()
      stderrBuf.push(text)
      if (stderrBuf.join("").length > 2000) stderrBuf.shift()
    })

    proc.on("exit", (code) => {
      if (!settled) {
        finish({ ok: false, error: `进程提前退出（exit=${code}）：${stderrBuf.join("").slice(-500)}` })
      }
    })
    proc.on("error", (err) => {
      if (!settled) finish({ ok: false, error: `无法启动进程：${err.message}` })
    })

    // MCP initialize 握手
    proc.stdin?.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "hyperion-test", version: "1.0" },
        },
      }) + "\n",
    )
  })
}

// ─────────────────────────── 文件选择辅助 ──────────────────────────────

export type FileEntry = {
  name: string
  isDir: boolean
  size: number
}

/** 列出目录内容（目录在前，名称排序）。 */
export function listDir(dir: string): FileEntry[] {
  const entries: FileEntry[] = []
  try {
    for (const name of readdirSync(dir)) {
      try {
        const full = path.join(dir, name)
        const st = statSync(full)
        entries.push({ name, isDir: st.isDirectory(), size: st.size })
      } catch {
        // ignore unreadable
      }
    }
  } catch {
    return []
  }
  entries.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1
    return a.name.localeCompare(b.name)
  })
  return entries
}

// ─────────────────────────── 程序领取任务 ──────────────────────────────

let cachedAgentId = ""

function humanSize(n: unknown): string {
  let size = Number(n || 0)
  if (!Number.isFinite(size) || size < 0) return "?"
  for (const unit of ["B", "KB", "MB", "GB"]) {
    if (size < 1024) return `${size.toFixed(1)}${unit}`
    size /= 1024
  }
  return `${size.toFixed(1)}TB`
}

export type TaskResult =
  | { ok: true; prompt: string; sessionId: string }
  | { ok: false; reason: "no-task" | "error"; error?: string }

/** 程序领取任务：connect（缓存 agent_id）→ next-task。无任务/错误均结构化返回。 */
export async function fetchTaskBrief(): Promise<TaskResult> {
  const cfg = readConfig()
  const server = String(cfg.ServerUrl ?? "").replace(/\/+$/, "")
  const token = String(cfg.CredentialToken ?? "")
  if (!server || !token) {
    return { ok: false, reason: "error", error: "appsettings.json 缺少 ServerUrl 或 CredentialToken" }
  }
  const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }

  if (!cachedAgentId) {
    const conn = await fetch(`${server}/api/reverse-agent/connect`, {
      method: "POST",
      headers,
      body: "{}",
    })
    if (!conn.ok) return { ok: false, reason: "error", error: `connect HTTP ${conn.status}` }
    const agent = (await conn.json()) as { agent_id?: string }
    if (!agent.agent_id) return { ok: false, reason: "error", error: "connect 未返回 agent_id" }
    cachedAgentId = agent.agent_id
  }

  const taskRes = await fetch(
    `${server}/api/reverse-agent/next-task?agent_id=${encodeURIComponent(cachedAgentId)}`,
    { headers },
  )
  if (!taskRes.ok) return { ok: false, reason: "error", error: `next-task HTTP ${taskRes.status}` }
  const task = (await taskRes.json()) as {
    has_task?: boolean
    session_id?: string
    machine_name?: string
    files?: Array<Record<string, unknown>>
  }

  if (!task.has_task) return { ok: false, reason: "no-task" }
  const sessionId = String(task.session_id ?? "")
  if (!sessionId) return { ok: false, reason: "error", error: "任务缺少 session_id" }

  const files = (task.files ?? [])
    .map((f) => {
      const name = String(f.name ?? f.storedName ?? "?")
      const size = humanSize(f.size)
      const engine = /\.(dmp|mdmp|hdmp)$/i.test(name) ? "windbg" : "ida"
      return `- ${name}（${size}，引擎：${engine}）`
    })
    .join("\n")

  const prompt = [
    `# 新的取证任务`,
    `- 会话 ID：${sessionId}`,
    `- 来源主机：${String(task.machine_name ?? "") || "未知"}`,
    ``,
    `## 待分析取证文件`,
    files || "（无）",
    ``,
    `## 工作流`,
    `1. 用 swap_sample 逐个加载上面的文件（自动下载 + 启动分析引擎）。`,
    `2. 用引擎 MCP 工具（ida_* / windbg_*）做反作弊向逆向分析。`,
    `3. 全部完成用 submit_report 提交会话级总结报告，然后结束。`,
    ``,
    `## 纪律`,
    `- 任务由调度器分配，你**不要**尝试领取或等待新任务，只处理本会话。`,
    `- 提交报告后停止。`,
  ].join("\n")

  return { ok: true, prompt, sessionId }
}
