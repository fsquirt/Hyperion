// NativeStructs.cs — 与 CombinationNativeData.h 一一对应的 C# Marshaling 结构体
//
// 设计原则:
//   - 所有结构体使用 [StructLayout(LayoutKind.Sequential)] 匹配 C++ 的 #pragma pack(push, 8)
//   - 定长 wchar_t[] → [MarshalAs(UnmanagedType.ByValTStr, SizeConst = N)] + CharSet.Unicode
//   - 定长 char[]    → [MarshalAs(UnmanagedType.ByValTStr, SizeConst = N)] + CharSet.Ansi (UTF-8 在 C++ 端处理)
//   - 嵌套数组使用 [MarshalAs(UnmanagedType.ByValArray, SizeConst = N)]
//   - 所有 int32_t → int, uint32_t → uint, int64_t → long, uint64_t → ulong

using System.Runtime.InteropServices;

namespace UserService.Native;

// ═══════════════════════════════════════════════════════════════════════
//  公共常量 (必须与 CBN_MAX_* 完全一致)
// ═══════════════════════════════════════════════════════════════════════

public static class CbnConstants
{
    public const int MaxPath = 260;
    public const int MaxName = 64;
    public const int MaxSubject = 256;
    public const int MaxReason = 256;
    public const int MaxStr = 128;

    public const int MaxDrivers = 512;
    public const int MaxDevices = 128;
    public const int MaxAttachments = 64;
    public const int MaxSigners = 8;
    public const int MaxIatDlls = 128;
    public const int MaxIatApis = 256;
    public const int MaxObjectEntries = 2048;
    public const int MaxHandles = 1024;
    public const int MaxProcesses = 1024;
    public const int MaxThreads = 64;
    public const int MaxModules = 128;
    public const int MaxMemRegions = 32;
    public const int MaxPrivs = 16;
    public const int MaxEtwEvents = 2048;
    public const int MaxStackFrames = 32;
    public const int MaxPaths = 1024;
    public const int MaxPayload = 256;
    public const int MaxStackModules = 8;
}

// ═══════════════════════════════════════════════════════════════════════
//  通用结果头
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnResultHeader
{
    public int ErrorCode;            // 0 = 成功
    public uint CommandId;           // 命令 ID (1-16)
    public uint EntryCount;          // 条目数量
    public uint EntrySize;           // 每个条目字节数
    public uint TotalSize;           // 整个缓冲区字节数
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ErrorMessage;      // 错误说明
}

// ═══════════════════════════════════════════════════════════════════════
//  DriverClassify 相关
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnSignerInfo
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Subject;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Issuer;
    public int IsMicrosoft;
    public int IsWhql;
    public int IsVendor;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnClassifyEntry
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string FileName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string FilePath;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string DriverObjectName;
    public int Klass;                // 0=INBOX,1=MICROSOFT,2=THIRD_PARTY_WHQL,3=UNTRUSTED
    public int SignerCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public CbnSignerInfo[] Signers;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string VendorName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ErrorReason;
    public int HasCatalog;
    public int HasEmbedded;
    // 驱动映像信息 (来自 LoadedDriverEntry)
    public ulong ImageBase;
    public uint ImageSize;
    public ushort LoadOrderIndex;
    // SHA256 哈希 (C++ 端 char[65], ANSI 窄字符)
    // 由于本结构体用 CharSet.Unicode, ByValTStr 会按宽字符 marshal (每字符 2 字节),
    // 与 C++ char[65] (每字符 1 字节) 布局不匹配, 因此用 byte[] 强制按 65 字节 marshal。
    // 使用时通过 Encoding.ASCII.GetString(...).TrimEnd('\0') 转换为字符串。
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 65)]
    public byte[] Sha256;
}

// ═══════════════════════════════════════════════════════════════
//  IAT 扫描相关
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Ansi)]
public struct CbnIatApi
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;
    public int IsDangerous;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Ansi)]
public struct CbnIatEntry
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string DllName;
    public int ApiCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public CbnIatApi[] Apis;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnIatResult
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string FilePath;
    public int DllCount;
    public int TotalApiCount;
    public int DangerousApiCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public CbnIatEntry[] Entries;
}

// ═══════════════════════════════════════════════════════════════════════
//  对象管理器扫描相关
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnNtDirEntry
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string Name;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string TypeName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string LinkTarget;
}

// ═══════════════════════════════════════════════════════════════════════
//  句柄扫描相关
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnHandleEntry
{
    public ulong OwnerPid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string OwnerName;
    public ulong HandleValue;
    public uint GrantedAccess;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string AccessStr;
    public ulong TargetPid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string TypeName;
    public int HighRisk;
}

// ═══════════════════════════════════════════════════════════════════════
//  进程树相关
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct CbnProcThread
{
    public ulong Tid;
    public ulong StartAddress;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Ansi)]
public struct CbnProcBrief
{
    public ulong Pid;
    public ulong Ppid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;
    public uint Threads;
    public long CreateTime;
    public uint Session;
    public ulong WorkingSet;
    public ulong PrivatePages;
    public uint Handles;
    public int BasePriority;
    public int ThreadCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public CbnProcThread[] ThreadList;
}

// ═══════════════════════════════════════════════════════════════════════
//  进程安全详情相关
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Ansi)]
public struct CbnThreadInfo
{
    public ulong Tid;
    public ulong StartAddress;
    public ulong Win32StartAddress;
    public int SuspendCount;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string StartModule;
    public int IsSuspended;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Ansi)]
public struct CbnModuleInfo
{
    public ulong Base;
    public uint Size;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string Path;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Ansi)]
public struct CbnMemRegion
{
    public ulong Base;
    public ulong Size;
    public uint Protect;
    public uint Type;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string ProtectStr;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string TypeStr;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string Reason;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Ansi)]
public struct CbnPrivilegeEntry
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 48)]
    public string Name;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Ansi)]
public struct CbnProcDetail
{
    public CbnProcBrief Brief;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ImagePath;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string CommandLine;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string Protection;
    public int PplBroken;

    public int EnabledPrivCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public CbnPrivilegeEntry[] EnabledPrivs;
    public int DisabledPrivCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public CbnPrivilegeEntry[] DisabledPrivs;

    public int ThreadInfoCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public CbnThreadInfo[] ThreadInfos;

    public int ModuleCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
    public CbnModuleInfo[] Modules;

    public int MemRegionCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public CbnMemRegion[] MemRegions;

    public int HandleCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
    public CbnHandleEntry[] Handles;
}

// ═══════════════════════════════════════════════════════════════════════
//  ETW 事件相关
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct CbnEtwEvent
{
    public uint Version;
    public uint IoControlCode;
    public uint InputBufferLength;
    public uint CaptureSize;
    public ulong RequestorPid;
    public ulong TargetDeviceAddr;
    public ulong FilterDeviceAddr;
    public ulong AttachId;
    public uint MajorFunction;
    public uint Method;
    public int StackFrameCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public ulong[] StackFrames;
    // 事件原始时间戳 (EventHeader.TimeStamp, FILETIME 100ns since 1601)
    public long Timestamp;
    // InputBuffer payload 原始字节 (最多 256)
    public uint PayloadSize;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] Payload;
}

// ═══════════════════════════════════════════════════════════════════════
//  通信监控相关
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnPathEntry
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string Path;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Tag;
    public uint Pid;
    public int Abnormal;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Note;
    public uint HitCount;
    public int Dumped;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string DumpFile;
    public int FileCopied;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string FileCopyName;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnCommsSummary
{
    public uint PathCount;
    public uint TotalIoctls;
    public uint TotalEvents;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
    public CbnPathEntry[] Paths;
}

// ═══════════════════════════════════════════════════════════════════════
//  通信监控 per-event 数据 (HeuristicDumper CommsMonitor 每事件回调)
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnStackModule
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string Path;
    public ulong Base;
    public uint Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnCommsEvent
{
    public long Timestamp;           // FILETIME
    public uint IoControlCode;
    public uint MajorFunction;
    public uint Method;
    public ulong RequestorPid;
    public ulong AttachId;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ProcessExe;
    public uint StackModuleCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public CbnStackModule[] StackModules;
    public uint PayloadSize;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] Payload;
}

// ═══════════════════════════════════════════════════════════════════════
//  驱动内存 dump 元数据 (HeuristicDumper DriverDumper)
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct CbnDriverDumpInfo
{
    public int Status;
    public uint AttachId;
    public ulong DriverObjectAddr;
    public ulong ImageBase;
    public uint ImageSize;
    public uint BytesDumped;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string FullPath;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string BaseName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string DumpFile;
}

// ═══════════════════════════════════════════════════════════════════════
//  附着操作结果 (复用 KernelComms.h 的结构)
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct CbnAttachResult
{
    public int Status;
    public uint AttachId;
    public ulong FilterDeviceAddr;
    public ulong LowerDeviceAddr;
    public ushort NewStackSize;
    public ushort TargetStackSize;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct CbnDetachResult
{
    public int Status;
    public uint DetachedId;
}

// ═══════════════════════════════════════════════════════════════════════
//  复用 C++ KernelComms.h 中已有的 POD 结构体
// ═══════════════════════════════════════════════════════════════════════

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct LoadedDriverEntry
{
    public ulong ImageBase;
    public uint ImageSize;
    public ushort LoadOrderIndex;
    public ushort Flags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string FullPath;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string DriverObjectName;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct DeviceEntry
{
    public ulong DeviceObject;
    public uint DeviceType;
    public uint Characteristics;
    public uint Flags;
    public ushort AttachedCount;
    public ushort StackSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string DeviceName;
}

[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct AttachEntry
{
    public ulong FilterDeviceAddr;
    public ulong LowerDeviceAddr;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string TargetPath;
    public uint AttachId;
    public ushort StackSize;
}
