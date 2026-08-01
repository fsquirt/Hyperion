/**
 * opencode 首页（Hyperion 魔改）：直接渲染 Hyperion 三菜单工作模式页。
 *
 * 原 opencode 首页（Logo + Prompt 输入）被整体替换——不再有遮罩，
 * 首页本身就是：开始工作 / 测试 IDA / 测试 WINDBG。
 */
import { HyperionHome } from "./home/hyperion-home"

export function Home() {
  return <HyperionHome />
}
