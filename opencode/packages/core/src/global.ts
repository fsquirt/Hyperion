import path from "path"
import fs from "fs/promises"
import { xdgData, xdgCache, xdgConfig, xdgState } from "xdg-basedir"
import os from "os"
import { Context, Effect, Layer } from "effect"
import { Flock } from "./util/flock"
import { Flag } from "./flag/flag"
import { makeGlobalNode } from "./effect/app-node"

const app = "opencode"

// Hyperion 魔改：当设置了 HYPERION_WORKDIR 时，把 opencode 的全部数据/配置/
// 缓存/状态/临时目录收口到该工作目录下（WorkDir\.opencode\...），从而：
//   - 分析机只往 WorkDir 写，不污染用户 profile（LOCALAPPDATA/APPDATA）
//   - 无需重定向 LOCALAPPDATA/APPDATA，避免污染引擎子进程（如 mcp-windbg 的 Python）
const hyperionWorkDir = process.env.HYPERION_WORKDIR?.trim()

const data = hyperionWorkDir
  ? path.join(hyperionWorkDir, ".opencode", "data")
  : path.join(xdgData!, app)
const cache = hyperionWorkDir
  ? path.join(hyperionWorkDir, ".opencode", "cache")
  : path.join(xdgCache!, app)
const config = hyperionWorkDir
  ? path.join(hyperionWorkDir, ".opencode", "config")
  : path.join(xdgConfig!, app)
const state = hyperionWorkDir
  ? path.join(hyperionWorkDir, ".opencode", "state")
  : path.join(xdgState!, app)
const tmp = hyperionWorkDir
  ? path.join(hyperionWorkDir, ".tmp")
  : path.join(os.tmpdir(), app)

const paths = {
  get home() {
    return process.env.OPENCODE_TEST_HOME ?? os.homedir()
  },
  data,
  bin: path.join(cache, "bin"),
  log: path.join(data, "log"),
  repos: path.join(data, "repos"),
  cache,
  config,
  state,
  tmp,
}

export const Path = paths

Flock.setGlobal({ state })

await Promise.all([
  fs.mkdir(Path.data, { recursive: true }),
  fs.mkdir(Path.config, { recursive: true }),
  fs.mkdir(Path.state, { recursive: true }),
  fs.mkdir(Path.tmp, { recursive: true }),
  fs.mkdir(Path.log, { recursive: true }),
  fs.mkdir(Path.bin, { recursive: true }),
  fs.mkdir(Path.repos, { recursive: true }),
])

export class Service extends Context.Service<Service, Interface>()("@opencode/Global") {}

export interface Interface {
  readonly home: string
  readonly data: string
  readonly cache: string
  readonly config: string
  readonly state: string
  readonly tmp: string
  readonly bin: string
  readonly log: string
  readonly repos: string
}

export function make(input: Partial<Interface> = {}): Interface {
  return {
    home: Path.home,
    data: Path.data,
    cache: Path.cache,
    config: Flag.OPENCODE_CONFIG_DIR ?? Path.config,
    state: Path.state,
    tmp: Path.tmp,
    bin: Path.bin,
    log: Path.log,
    repos: Path.repos,
    ...input,
  }
}

const layer = Layer.effect(
  Service,
  Effect.sync(() => Service.of(make())),
)

export const node = makeGlobalNode({ service: Service, layer: layer, deps: [] })

export const layerWith = (input: Partial<Interface>) =>
  Layer.effect(
    Service,
    Effect.sync(() => Service.of(make(input))),
  )

export * as Global from "./global"
