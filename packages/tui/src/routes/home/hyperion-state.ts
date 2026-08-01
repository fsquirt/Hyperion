/**
 * Hyperion 工作模式会话状态（TUI 进程内共享）。
 *
 * hyperion 模式下：首屏领到任务自动进入的会话标记为 active，
 * 会话结束（status idle）时 session 视图据此自动导航回首屏待机页。
 */
let active = false

export const hyperionState = {
  get active(): boolean {
    return active
  },
  setActive(value: boolean): void {
    active = value
  },
}
