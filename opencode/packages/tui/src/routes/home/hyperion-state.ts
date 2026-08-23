/**
 * Hyperion 工作模式会话状态（TUI 进程内共享）。
 *
 * hyperion 模式下：首屏领到任务自动进入的会话标记为 active，
 * 会话结束（status idle）时 session 视图据此自动导航回首屏待机页。
 *
 * continuous：连续任务模式标志。开启后会话完成回到首屏时自动开始下一轮
 * （重开会话 → 领取任务 → 派发给 Agent），直到用户在轮询阶段回车停止。
 */
let active = false
let continuous = false

export const hyperionState = {
  get active(): boolean {
    return active
  },
  setActive(value: boolean): void {
    active = value
  },
  get continuous(): boolean {
    return continuous
  },
  setContinuous(value: boolean): void {
    continuous = value
  },
}
