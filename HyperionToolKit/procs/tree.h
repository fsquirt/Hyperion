// tree.h — procs 树形打印模式 (默认模式)
//
// 打印进程树,支持 --pid / --depth / --json。输出统一走 das::Out。

#pragma once
#include "DataTypes.h"

namespace das {

// 树形打印模式入口
// pidFilter: 0 = 整树,非 0 = 只打印指定进程子树
// maxDepth: 0 = 不限制,正数 = 限制最大深度
// jsonOut: true = 输出扁平 JSON
int RunTreeMode(ULONG_PTR pidFilter, int maxDepth, bool jsonOut);

} // namespace das