// cmd.h — dumper 主入口 (原 HeuristicDumper.cpp)
//
// 监听被附着驱动的 ETW 通信, 从调用栈定位通信文件, 检查 RHS 属性,
// 异常红色输出, 并 dump 通信文件 / 对端驱动内存。

#pragma once

namespace das {

// 主入口: 解析参数并分发到 --handle 模式或 ETW 监控模式
int RunHeuristicDumper(int argc, wchar_t** argv);

} // namespace das