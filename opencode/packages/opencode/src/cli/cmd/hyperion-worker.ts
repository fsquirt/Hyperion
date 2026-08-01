/**
 * Hyperion 取证调度模式（`opencode hyperion-worker`）。
 *
 * 职责：**由程序**轮询取证服务器领取任务，把任务注入 opencode 会话驱动分析，
 * 而不是让 LLM 自己领任务。
 *
 * 循环：
 *   上报空闲 → 轮询 next-task → 无任务 sleep 重试
 *   → 有任务：上报"分析中" → 创建 opencode 会话并注入任务简报 → 等会话结束
 *     （agent 内部通过 swap_sample / submit_report 完成分析与报告提交）
 *   → 上报空闲 → 继续轮询
 *
 * 一次进程内循环处理任务，一个任务对应一个 opencode 会话，会话结束即处理完成。
 */
import { createOpencodeClient, type OpencodeClient } from "@opencode-ai/sdk/v2"
import { Effect } from "effect"
import { effectCmd } from "../effect-cmd"
import { ServerAuth } from "@/server/auth"
import {
  apiFetch,
  buildTaskBrief,
  ensureAgent,
  loadSettings,
  runtime,
  sleep,
  type HyperionSettings,
} from "../../tool/hyperion"

export const HyperionWorkerCommand = effectCmd({
  command: "hyperion-worker",
  describe: "Hyperion 取证调度：程序轮询服务器领取任务并驱动 opencode 分析",
  builder: (yargs) =>
    yargs
      .option("interval", {
        type: "number",
        describe: "无任务时的轮询间隔（秒）",
        default: 30,
      })
      .option("once", {
        type: "boolean",
        describe: "只处理一个任务后退出（调试用）",
        default: false,
      }),
  instance: () => true,
  directory: () => process.cwd(),
  handler: Effect.fn("Cli.hyperionWorker")(function* (args) {
    yield* Effect.promise(async () => {
      await runWorker({ interval: args.interval ?? 30, once: Boolean(args.once) })
    })
  }),
})

async function heartbeat(s: HyperionSettings, status: string): Promise<void> {
  try {
    await apiFetch(s.ServerUrl, s.CredentialToken, "/api/reverse-agent/heartbeat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: runtime.agentId, current_status: status }),
    })
  } catch (err) {
    console.error(`[hyperion-worker] heartbeat 失败：${err instanceof Error ? err.message : String(err)}`)
  }
}

async function nextTask(s: HyperionSettings): Promise<Record<string, unknown> | null> {
  const res = await apiFetch(
    s.ServerUrl,
    s.CredentialToken,
    `/api/reverse-agent/next-task?agent_id=${encodeURIComponent(runtime.agentId)}`,
  )
  const data = (await res.json()) as { has_task?: boolean }
  return data.has_task ? data : null
}

async function runWorker(args: { interval: number; once: boolean }): Promise<void> {
  const cfg = loadSettings()
  if (!cfg.ok) {
    console.error(`[hyperion-worker] ${cfg.error}`)
    process.exit(1)
  }
  const s = cfg.value
  const intervalMs = Math.max(5, (args.interval || 30) * 1000)

  await ensureAgent(s)
  console.log(`[hyperion-worker] agent=${runtime.agentId} · ${s.ServerUrl} · 开始轮询取证任务…`)

  // 进程内 server + SDK（与 `opencode run` 相同的驱动方式）
  const { Server } = await import("@/server/server")
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init)
    const headers = new Headers(request.headers)
    const auth = ServerAuth.header()
    if (auth) headers.set("Authorization", auth)
    return Server.Default().app.fetch(new Request(request, { headers }))
  }) as typeof globalThis.fetch
  const sdk = createOpencodeClient({
    baseUrl: "http://opencode.internal",
    fetch: fetchFn,
    directory: process.cwd(),
  })

  for (;;) {
    try {
      await heartbeat(s, "空闲")
      const task = await nextTask(s)
      if (!task) {
        console.log(`[hyperion-worker] 暂无任务，${Math.round(intervalMs / 1000)}s 后重试`)
        await sleep(intervalMs)
        continue
      }
      await handleTask(s, sdk, task)
      if (args.once) return
    } catch (err) {
      console.error(`[hyperion-worker] 循环异常：${err instanceof Error ? err.message : String(err)}`)
      runtime.sessionId = ""
      await sleep(intervalMs)
    }
  }
}

async function handleTask(
  s: HyperionSettings,
  sdk: OpencodeClient,
  task: Record<string, unknown>,
): Promise<void> {
  const sessionId = String(task.session_id ?? "")
  const files = Array.isArray(task.files) ? (task.files as Record<string, unknown>[]) : []
  if (!sessionId) throw new Error("任务缺少 session_id")

  // 注入运行时状态：swap_sample / submit_report 工具依赖
  runtime.sessionId = sessionId
  runtime.machineName = String(task.machine_name ?? "")
  runtime.taskFiles = files

  console.log(`[hyperion-worker] ⬇ 领取任务 ${sessionId}（文件 ${files.length} 个），标记工作中`)
  await heartbeat(s, `分析中 ${sessionId}`)

  const prompt = buildTaskBrief(sessionId, runtime.machineName, files)
  const created = await sdk.session.create({
    title: `hyperion-${sessionId}`,
    permission: [{ permission: "*", action: "allow", pattern: "*" }],
  })
  const sid = created.data?.id
  if (!sid) throw new Error("创建 opencode 会话失败")

  const events = await sdk.event.subscribe()
  console.log(`[hyperion-worker] ▶ opencode 会话 ${sid} 开始分析…`)
  await sdk.session.prompt({ sessionID: sid, parts: [{ type: "text", text: prompt }] })

  let error: string | undefined
  for await (const event of events.stream) {
    if (
      event.type === "session.error" &&
      event.properties.sessionID === sid &&
      event.properties.error
    ) {
      error = String(event.properties.error.name ?? "session error")
    }
    if (
      event.type === "session.status" &&
      event.properties.sessionID === sid &&
      event.properties.status.type === "idle"
    ) {
      break
    }
  }

  runtime.sessionId = ""
  console.log(
    `[hyperion-worker] ✅ 会话 ${sessionId} 处理完成${error ? `（会话错误：${error}）` : ""}，标记空闲`,
  )
}
