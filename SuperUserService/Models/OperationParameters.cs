// OperationParameters — 复杂命令的参数容器
//
// 将原先散落在 RunEtw / RunComms / RunTree / RunSecurity / RunScanObjects
// 中的参数解析逻辑收敛为不可变的数据类, 由调用方构造后传入服务层。

using System.Collections.Generic;
using System.Linq;

namespace SuperUserService.Models;

/// <summary>ETW 实时订阅命令的参数。</summary>
internal sealed class EtwParameters
{
    /// <summary>订阅时长 (秒); 0 表示持续到 Ctrl+C。</summary>
    public uint DurationSec { get; }

    /// <summary>非空时事件同时落盘到该 .etl 文件。</summary>
    public string? EtlPath { get; }

    public EtwParameters(uint durationSec, string? etlPath = null)
    {
        DurationSec = durationSec;
        EtlPath = etlPath;
    }

    public override string ToString() => $"duration={DurationSec}s, etl=\"{EtlPath}\"";
}

/// <summary>ETW 通信监控命令的参数。</summary>
/// <summary>Dump 模式。</summary>
internal enum CommsDumpMode
{
    /// <summary>Raw 内存镜像 (默认, 体积小)。</summary>
    Raw = 0,
    /// <summary>MiniDump (体积中, 含线程/模块/堆栈)。</summary>
    Mini = 1,
    /// <summary>Full MiniDump (体积大, 含句柄表/线程上下文)。</summary>
    Full = 2,
}

internal sealed class CommsParameters
{
    /// <summary>监控时长 (秒); 0 表示持续到 Ctrl+C。</summary>
    public uint DurationSec { get; }

    /// <summary>是否启用 JSON 通信日志。</summary>
    public bool EnableJson { get; }

    /// <summary>Dump 模式 (默认 Raw)。</summary>
    public CommsDumpMode DumpMode { get; }

    public CommsParameters(uint durationSec, bool enableJson, CommsDumpMode dumpMode = CommsDumpMode.Raw)
    {
        DurationSec = durationSec;
        EnableJson = enableJson;
        DumpMode = dumpMode;
    }

    public override string ToString()
        => $"duration={DurationSec}s, json={EnableJson}, dump={DumpMode}";
}

/// <summary>进程树打印命令的参数。</summary>
internal sealed class TreeParameters
{
    /// <summary>目标 PID; 0 表示整树。</summary>
    public ulong Pid { get; }

    /// <summary>最大深度; 0 表示不限制。</summary>
    public int MaxDepth { get; }

    /// <summary>是否输出扁平 JSON。</summary>
    public bool JsonOutput { get; }

    public TreeParameters(ulong pid, int maxDepth, bool jsonOutput)
    {
        Pid = pid;
        MaxDepth = maxDepth;
        JsonOutput = jsonOutput;
    }

    public override string ToString() => $"pid={Pid}, depth={MaxDepth}, json={JsonOutput}";
}

/// <summary>安全采集命令的参数, 含 flags 位掩码分解。</summary>
internal sealed class SecurityParameters
{
    public ulong Pid { get; }
    public uint Flags { get; }

    public bool NoHandles => (Flags & 0x01) != 0;
    public bool NoMem     => (Flags & 0x02) != 0;
    public bool NoThreads => (Flags & 0x04) != 0;
    public bool NoModules => (Flags & 0x08) != 0;
    public bool NoToken   => (Flags & 0x10) != 0;

    public SecurityParameters(ulong pid, uint flags)
    {
        Pid = pid;
        Flags = flags;
    }

    public override string ToString() => $"pid={Pid}, flags=0x{Flags:X}";
}

/// <summary>对象管理器命名空间扫描命令的参数。</summary>
internal sealed class ScanObjectsParameters
{
    /// <summary>待扫描的对象目录列表 (如 \GLOBAL??, \Device)。</summary>
    public IReadOnlyList<string> Directories { get; }

    public ScanObjectsParameters(IEnumerable<string> directories)
    {
        Directories = directories.ToList();
    }

    /// <summary>转换为 CombinationNative 期望的逗号分隔宽字符串形式。</summary>
    public string ToNativeString() => string.Join(',', Directories);

    public override string ToString() => $"dirs=[{string.Join(", ", Directories)}]";
}
