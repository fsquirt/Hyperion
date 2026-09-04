using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace Hyperion.Server.Models;

// ═══════════════════════════════════════════════════════════════
//  危险内核函数列表 (Dangerous Kernel Function List)
// ═══════════════════════════════════════════════════════════════
//  场景:DriverAttachSelector 在 --ScanAndEnumDevices 整合模式下,
//        对每个待附着驱动扫 IAT,如果导入了这里的"危险内核函数",
//        就标记为高危驱动，即使签名 WHQL 也视为可疑。
//
//  默认自带 4 个，可在 Web 后台增删:
//    MmCopyMemory        — 跨进程读内核内存
//    MmMapIoSpace        — 映射物理内存到虚拟地址，用于直接硬件操作
//    ZwMapViewOfSection  — 映射 section 到进程，BYOVD 经典手法
//    MmCopyVirtualMemory — 跨进程读写虚拟内存，反作弊常用
//
//  以后可以往里加,如:
//    MmAllocateContiguousMemory / ZwSetSystemInformation /
//    MmProtectMdlSystemAddress / KeServiceDescriptorTable 等
// ═══════════════════════════════════════════════════════════════

/// <summary>严重程度</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum KernelFuncSeverity
{
    /// <summary>高危:经典 BYOVD / 反作弊常用内存操作</summary>
    High,
    /// <summary>中危:可被滥用但有合法用途</summary>
    Medium,
    /// <summary>低危:需关注但单独出现不构成强信号</summary>
    Low,
}

/// <summary>危险内核函数单条记录，用作 API 响应模型</summary>
public sealed record KernelFuncEntry
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    /// <summary>函数名，按精确匹配使用，如 "MmCopyMemory"</summary>
    [JsonPropertyName("func_name")] public string FuncName { get; init; } = "";
    /// <summary>显示名，可选，如 "跨进程内存拷贝"</summary>
    [JsonPropertyName("display_name")] public string DisplayName { get; init; } = "";
    /// <summary>分类，如 "内存操作" / "进程操作" / "注册表" / "对象管理"</summary>
    [JsonPropertyName("category")] public string Category { get; init; } = "";
    [JsonPropertyName("severity")] public KernelFuncSeverity Severity { get; init; }
    /// <summary>是否启用，禁用后不再参与 IAT 命中判定</summary>
    [JsonPropertyName("enabled")] public bool Enabled { get; init; }
    [JsonPropertyName("added_at")] public string AddedAt { get; init; } = "";
    [JsonPropertyName("notes")] public string? Notes { get; init; }
}

/// <summary>统计</summary>
public sealed record KernelFuncStats
{
    [JsonPropertyName("total")] public int Total { get; init; }
    [JsonPropertyName("enabled_count")] public int EnabledCount { get; init; }
    [JsonPropertyName("disabled_count")] public int DisabledCount { get; init; }
    [JsonPropertyName("high_count")] public int HighCount { get; init; }
    [JsonPropertyName("medium_count")] public int MediumCount { get; init; }
    [JsonPropertyName("low_count")] public int LowCount { get; init; }
}

/// <summary>添加请求</summary>
public sealed class KernelFuncAddRequest
{
    [JsonPropertyName("func_name")] public string FuncName { get; set; } = "";
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("category")] public string? Category { get; set; }
    [JsonPropertyName("severity")] public KernelFuncSeverity Severity { get; set; } = KernelFuncSeverity.High;
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

/// <summary>编辑请求，只允许改 display_name / category / severity / enabled / notes，
/// 不允许改 func_name — 改名请删了重加</summary>
public sealed class KernelFuncUpdateRequest
{
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("category")] public string? Category { get; set; }
    [JsonPropertyName("severity")] public KernelFuncSeverity? Severity { get; set; }
    [JsonPropertyName("enabled")] public bool? Enabled { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

/// <summary>添加/编辑操作结果</summary>
public sealed record KernelFuncOpResult
{
    [JsonPropertyName("success")] public bool Success { get; init; }
    [JsonPropertyName("id")] public string? Id { get; init; }
    [JsonPropertyName("error")] public string? Error { get; init; }
}

// ═══════════════════════════════════════════════════════════════
//  数据库实体
// ═══════════════════════════════════════════════════════════════

[Table("kernel_dangerous_funcs")]
public sealed class KernelDangerousFuncEntity
{
    [Key][Column("id")] public string Id { get; set; } = "";
    /// <summary>函数名，唯一，按精确匹配且大小写敏感 — 内核函数名本身大小写敏感</summary>
    [Column("func_name")] public string FuncName { get; set; } = "";
    [Column("display_name")] public string DisplayName { get; set; } = "";
    [Column("category")] public string Category { get; set; } = "";
    /// <summary>"High" / "Medium" / "Low"</summary>
    [Column("severity")] public string Severity { get; set; } = "High";
    [Column("enabled")] public bool Enabled { get; set; } = true;
    [Column("added_at")] public string AddedAt { get; set; } = "";
    [Column("notes")] public string? Notes { get; set; }
}
