// DriverClassify.h — 驱动签名证书链分类模块
//
// 分类逻辑:
//   INBOX              - 仅有目录签名(.cat),无内嵌签名 → 放过(inbox 驱动)
//   MICROSOFT          - 内嵌签名 + 厂商是微软 → 放过(微软自家软件驱动)
//   THIRD_PARTY_WHQL   - 内嵌签名 + WHQL + 第三方厂商 → 待附着(漏洞驱动候选)
//   UNTRUSTED          - 无签名或验证失败 → HVCI 下不会存在
//
// 证书链判定:
//   WHQL 签名者 Subject 含 "Microsoft Windows Hardware Compatibility Publisher"
//   厂商签名者 Subject 不含 "Microsoft" (如 "ACEVILLE PTE LTD" / "Realtek Semiconductor Corp")
//   嵌套签名(厂商签名)按 RFC 5652 在未认证属性 UnauthAttrs 里

#pragma once

#include <string>
#include "Common.h"

namespace das {

// 对单个驱动文件做签名分类
// filePath: 驱动文件全路径(.sys)
// 返回:ClassifyResult
ClassifyResult ClassifyDriver(const std::wstring& filePath);

} // namespace das
