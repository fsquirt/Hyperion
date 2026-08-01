/**
 * Hyperion 首页（替换原 opencode 首页）：三菜单工作模式。
 *
 * ┌──────────────────────────────────────────┐
 * │  Hyperion Reverse Agent · opencode 工作模式 │
 * │  （配置摘要）                              │
 * │  ① 开始工作        ← 程序轮询领任务后进会话   │
 * │  ② 测试 IDA        ← 选文件，程序测 IDA+MCP  │
 * │  ③ 测试 WINDBG     ← 程序测 WinDbg MCP      │
 * └──────────────────────────────────────────┘
 *
 * 说明：
 * - 「开始工作」：程序轮询服务器领取任务，没拿到任务前停在本页（30 秒重试），
 *   拿到任务才创建会话进入工作界面；会话完成自动回到本页。
 * - 「测试 IDA / 测试 WINDBG」：纯程序检测 MCP 是否正常，不经过 LLM。
 */
import { TextAttributes, RGBA } from "@opentui/core"
import { useTerminalDimensions } from "@opentui/solid"
import { createSignal, For, Show } from "solid-js"
import path from "node:path"
import { useTheme } from "../../context/theme"
import { useBindings } from "../../keymap"
import { useRoute } from "../../context/route"
import { useSDK } from "../../context/sdk"
import { hyperionState } from "./hyperion-state"
import {
  configPath,
  listDir,
  maskToken,
  readConfig,
  fetchTaskBrief,
  testIda,
  testWindbg,
  type FileEntry,
  type TestResult,
} from "./hyperion-tools"

const MENU_ITEMS = ["开始工作", "测试 IDA", "测试 WINDBG"] as const
const POLL_INTERVAL_SECONDS = 30

type Phase = "menu" | "polling" | "file-pick" | "testing-ida" | "testing-windbg"

const PERMISSION_ALLOW_ALL: { permission: string; pattern: string; action: "allow" }[] = [
  { permission: "*", action: "allow", pattern: "*" },
]

function humanSize(n: number): string {
  let size = n
  for (const unit of ["B", "KB", "MB", "GB"]) {
    if (size < 1024) return `${size.toFixed(1)}${unit}`
    size /= 1024
  }
  return `${size.toFixed(1)}TB`
}

export function HyperionHome() {
  const { theme } = useTheme()
  const dimensions = useTerminalDimensions()
  const route = useRoute()
  const sdk = useSDK()

  const [phase, setPhase] = createSignal<Phase>("menu")
  const [selected, setSelected] = createSignal(0)
  const [configLines, setConfigLines] = createSignal<string[]>([])
  const [status, setStatus] = createSignal("")
  const [error, setError] = createSignal("")
  const [logLines, setLogLines] = createSignal<string[]>([])
  const [testResult, setTestResult] = createSignal<TestResult | null>(null)

  // 文件选择状态
  const [pickDir, setPickDir] = createSignal(process.cwd())
  const [pickEntries, setPickEntries] = createSignal<FileEntry[]>([])
  const [pickIndex, setPickIndex] = createSignal(0)
  const [pickFile, setPickFile] = createSignal("")

  let cancelled = false

  // 初始化：读配置
  if (configLines().length === 0) {
    try {
      const cfg = readConfig()
      setConfigLines([
        `ServerUrl：${String(cfg.ServerUrl ?? "(未设置)")}`,
        `CredentialToken：${maskToken(cfg.CredentialToken)}`,
        `WorkDir：${String(cfg.WorkDir ?? "(未设置)")}`,
        `IdaPath：${String(cfg.IdaPath ?? "(未设置)")}`,
        `轮询间隔：${POLL_INTERVAL_SECONDS} 秒`,
      ])
    } catch (err) {
      setConfigLines(["（配置读取失败，详见下方错误）"])
      setError(String(err))
    }
  }

  useBindings(() => ({
    enabled: true,
    bindings: [
      { key: "up", desc: "上一个选项", group: "Hyperion", cmd: () => move(-1) },
      { key: "down", desc: "下一个选项", group: "Hyperion", cmd: () => move(1) },
      {
        key: "return",
        desc: "确认",
        group: "Hyperion",
        cmd: () => {
          void confirm()
        },
      },
      {
        key: "escape",
        desc: "返回菜单",
        group: "Hyperion",
        cmd: () => backToMenu(),
      },
    ],
  }))

  function move(delta: number): void {
    const p = phase()
    if (p === "menu") {
      setSelected((selected() + delta + MENU_ITEMS.length) % MENU_ITEMS.length)
      return
    }
    if (p === "file-pick") {
      const total = pickEntries().length + 1 // +1 是 ..
      setPickIndex((pickIndex() + delta + total) % total)
    }
  }

  function backToMenu(): void {
    cancelled = true
    setPhase("menu")
    setStatus("")
    setError("")
    setLogLines([])
    setTestResult(null)
    setSelected(0)
  }

  async function confirm(): Promise<void> {
    const p = phase()
    if (p === "polling") {
      // 停止轮询回菜单
      cancelled = true
      backToMenu()
      return
    }
    if (p === "menu") {
      const item = MENU_ITEMS[selected()]
      if (item === "开始工作") {
        void startWorking()
      } else if (item === "测试 IDA") {
        startFilePick()
      } else if (item === "测试 WINDBG") {
        void startWindbgTest()
      }
      return
    }
    if (p === "file-pick") {
      confirmFilePick()
      return
    }
    if (p === "testing-ida" || p === "testing-windbg") {
      backToMenu()
    }
  }

  // ── 开始工作：程序轮询领任务 ───────────────────────────────────────
  async function startWorking(): Promise<void> {
    cancelled = false
    setError("")
    setLogLines([])
    setPhase("polling")
    setStatus("正在领取任务…")

    for (;;) {
      if (cancelled) return
      const result = await fetchTaskBrief().catch((err) => ({
        ok: false as const,
        reason: "error" as const,
        error: String(err),
      }))
      if (cancelled) return

      if (result.ok) {
        hyperionState.setActive(true)
        const created = await sdk.client.session.create({
          title: `hyperion-${result.sessionId}`,
          permission: PERMISSION_ALLOW_ALL,
        })
        const sid = created.data?.id
        if (!sid) {
          setPhase("menu")
          setError("创建 opencode 会话失败")
          return
        }
        await sdk.client.session.prompt({
          sessionID: sid,
          parts: [{ type: "text", text: result.prompt }],
        })
        route.navigate({ type: "session", sessionID: sid })
        return
      }

      setError(result.reason === "error" ? (result.error ?? "") : "")
      for (let i = POLL_INTERVAL_SECONDS; i > 0; i--) {
        if (cancelled) return
        setStatus(`暂无任务，${i} 秒后重试（回车停止）`)
        await new Promise((resolve) => setTimeout(resolve, 1000))
      }
    }
  }

  // ── 测试 IDA：选文件 ───────────────────────────────────────────────
  function startFilePick(): void {
    setPhase("file-pick")
    setError("")
    setStatus("选择一个样本文件（目录可进入，回车确认文件）")
    const dir = process.cwd()
    setPickDir(dir)
    setPickEntries(listDir(dir))
    setPickIndex(0)
  }

  function confirmFilePick(): void {
    const entries = pickEntries()
    const idx = pickIndex()
    // 最后一项是上级目录 ..
    if (idx >= entries.length) {
      const parent = path.dirname(pickDir())
      setPickDir(parent)
      setPickEntries(listDir(parent))
      setPickIndex(0)
      return
    }
    const entry = entries[idx]
    const full = path.join(pickDir(), entry.name)
    if (entry.isDir) {
      setPickDir(full)
      setPickEntries(listDir(full))
      setPickIndex(0)
      return
    }
    setPickFile(full)
    void startIdaTest(full)
  }

  async function startIdaTest(filePath: string): Promise<void> {
    setPhase("testing-ida")
    setLogLines([`样本：${filePath}`])
    setStatus("正在测试 IDA…")
    setTestResult(null)
    const result = await testIda(filePath)
    setLogLines(result.steps)
    setTestResult(result)
    setStatus(result.ok ? "✅ IDA 测试通过（回车返回菜单）" : "❌ IDA 测试失败（回车返回菜单）")
    setError(result.error ?? "")
  }

  // ── 测试 WINDBG ────────────────────────────────────────────────────
  async function startWindbgTest(): Promise<void> {
    setPhase("testing-windbg")
    setLogLines([])
    setStatus("正在测试 WinDbg…")
    setTestResult(null)
    const result = await testWindbg()
    setLogLines(result.steps)
    setTestResult(result)
    setStatus(result.ok ? "✅ WinDbg 测试通过（回车返回菜单）" : "❌ WinDbg 测试失败（回车返回菜单）")
    setError(result.error ?? "")
  }

  // ── 渲染 ───────────────────────────────────────────────────────────
  return (
    <box
      width="100%"
      height={dimensions().height}
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
    >
      <box
        width={Math.min(90, dimensions().width - 4)}
        flexDirection="column"
        gap={1}
        paddingTop={2}
        paddingBottom={2}
        paddingLeft={3}
        paddingRight={3}
        backgroundColor={theme.backgroundPanel}
      >
        <text attributes={TextAttributes.BOLD} fg={theme.text}>
          Hyperion Reverse Agent · opencode 工作模式
        </text>
        <text fg={theme.textMuted}>取证服务器任务自动调度 · IDA / WinDbg 逆向分析</text>

        <Show when={phase() === "menu" || phase() === "polling"}>
          <box height={1} />
          <text fg={theme.text}>配置文件：{configPath() ?? "未找到 appsettings.json"}</text>
          <box flexDirection="column">
            {configLines().map((line) => (
              <text fg={theme.textMuted}>{line}</text>
            ))}
          </box>
          <box height={1} />
          <For each={MENU_ITEMS}>
            {(item, i) => (
              <box
                flexDirection="row"
                gap={1}
                backgroundColor={selected() === i() && phase() === "menu" ? theme.primary : undefined}
              >
                <text fg={selected() === i() && phase() === "menu" ? theme.selectedListItemText : theme.text}>
                  {selected() === i() && phase() === "menu" ? "▶ " : "  "}
                  {item}
                </text>
              </box>
            )}
          </For>
        </Show>

        <Show when={phase() === "file-pick"}>
          <box height={1} />
          <text fg={theme.text}>选择测试文件：{pickDir()}</text>
          <box flexDirection="column">
            <box
              flexDirection="row"
              gap={1}
              backgroundColor={pickIndex() >= pickEntries().length ? theme.primary : undefined}
            >
              <text fg={pickIndex() >= pickEntries().length ? theme.selectedListItemText : theme.textMuted}>
                {pickIndex() >= pickEntries().length ? "▶ " : "  "}..（上级目录）
              </text>
            </box>
            <For each={pickEntries()}>
              {(entry, i) => (
                <box
                  flexDirection="row"
                  gap={1}
                  backgroundColor={pickIndex() === i() ? theme.primary : undefined}
                >
                  <text
                    fg={
                      pickIndex() === i()
                        ? theme.selectedListItemText
                        : entry.isDir
                          ? theme.text
                          : theme.textMuted
                    }
                  >
                    {pickIndex() === i() ? "▶ " : "  "}
                    {entry.isDir ? "[DIR] " : ""}
                    {entry.name}
                    {entry.isDir ? "" : `（${humanSize(entry.size)}）`}
                  </text>
                </box>
              )}
            </For>
          </box>
        </Show>

        <Show when={phase() === "testing-ida" || phase() === "testing-windbg"}>
          <box height={1} />
          <text fg={theme.text}>
            {phase() === "testing-ida" ? "IDA 链路测试" : "WinDbg MCP 测试"}
          </text>
          <box flexDirection="column">
            <For each={logLines()}>
              {(line) => (
                <text fg={line.includes("✅") || line.includes("清理") ? theme.textMuted : theme.textMuted}>
                  {line}
                </text>
              )}
            </For>
          </box>
          <Show when={testResult()}>
            <box height={1} />
            <text fg={testResult()?.ok ? theme.success : theme.error}>
              {testResult()?.ok ? "测试通过" : "测试失败"}
            </text>
          </Show>
        </Show>

        <box height={1} />
        <text fg={phase() === "testing-ida" || phase() === "testing-windbg" || phase() === "file-pick" ? theme.text : theme.primary}>
          {status()}
        </text>
        <Show when={error()}>
          <text fg={theme.error}>{error()}</text>
        </Show>
        <Show when={phase() !== "menu" && phase() !== "polling"}>
          <text fg={theme.textMuted}>（回车 / Esc 返回菜单）</text>
        </Show>
      </box>
    </box>
  )
}
