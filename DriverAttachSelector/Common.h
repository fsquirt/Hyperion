// Common.h — DriverAttachSelector 公共头
// 收纳所有模块共享的类型、常量、输出函数。
//
// 拆分原则:
//   - 每个子模块(DriverClassify / LoadedDrivers / ObjectScanner)只暴露
//     必要的入口函数和共享类型,内部实现细节不外泄
//   - WriteOut 是全局输出函数,放公共头避免循环依赖
//   - 不在此处放 <windows.h> 等系统头,各模块按需包含

#pragma once

#include <string>
#include <vector>
#include <windows.h>

namespace das {

// ═══════════════════════════════════════════════════════════════════════
//  输出函数(UTF-8 输出,控制台和重定向都兼容)
// ═══════════════════════════════════════════════════════════════════════

void WriteOut(const std::wstring& s);

// ── 无输出工具函数 (供 FFI 数据导出使用) ──

// 设置静默模式 (true = WriteOut 不输出, false = 正常输出)
void SetSilentMode(bool enable);

// 查询当前是否处于静默模式
bool IsSilentMode();

// ═══════════════════════════════════════════════════════════════════════
//  共享类型定义
// ═══════════════════════════════════════════════════════════════════════

// 驱动分类(由 DriverClassify 模块产出)
enum class DriverClass {
    INBOX,                  // 仅有目录签名(.cat) → 放过
    MICROSOFT,              // 内嵌签名 + 厂商是微软 → 放过
    THIRD_PARTY_WHQL,       // 内嵌签名 + WHQL + 第三方厂商 → 待附着
    UNTRUSTED,              // 无签名或验证失败
};

const wchar_t* ClassToString(DriverClass c);

// 单个签名者信息
struct SignerInfo {
    std::wstring subject;       // 证书 Subject (e.g. "Microsoft Windows Hardware Compatibility Publisher")
    std::wstring issuer;        // 证书 Issuer
    bool isMicrosoft = false;   // 是否微软签名者 (Subject 含 "Microsoft")
    bool isWhql = false;        // 是否 WHQL 签名者
    bool isVendor = false;      // 是否第三方厂商签名者
};

// 分类结果
struct ClassifyResult {
    DriverClass klass = DriverClass::UNTRUSTED;
    std::vector<SignerInfo> signers;
    std::wstring vendorName;    // 第三方厂商名 (仅 THIRD_PARTY_WHQL 时有意义)
    std::wstring errorReason;   // 失败原因 (UNTRUSTED 时有意义)
    bool hasCatalog = false;    // 是否有目录签名
    bool hasEmbedded = false;   // 是否有内嵌签名
};

// 已加载内核驱动信息(由 LoadedDrivers 模块产出)
struct LoadedDriver {
    std::wstring name;
    std::wstring path;
    ULONGLONG baseAddr = 0;
    DWORD size = 0;
};

// 单条对象目录项(由 ObjectScanner 模块产出)
struct NtDirEntry {
    std::wstring name;       // 对象名 (e.g. "HarddiskVolume1" / "C:")
    std::wstring typeName;   // 对象类型 (e.g. "Device" / "SymbolicLink" / "Directory")
    std::wstring linkTarget; // 仅 SymbolicLink 有,目标路径 (e.g. "\Device\HarddiskVolume1")
};

} // namespace das
