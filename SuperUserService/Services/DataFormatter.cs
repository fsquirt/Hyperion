// DataFormatter.cs — 把 NativeDataResult<T> 中的结构化数据格式化为可读文本
//
// 设计原则:
//   - 本类不调用任何 P/Invoke, 不与 C++ 交互, 纯粹负责"从类出"
//   - 每个命令对应一个 Format* 方法, 接收 NativeDataResult<T>, 输出到 Console
//   - 失败时统一输出错误头 + ErrorCode + ErrorMessage
//   - 所有输出走 Console.WriteLine, 由 Program 控制编码

using System.Text;
using SuperUserService.Models;

namespace SuperUserService.Services;

/// <summary>
/// 把 <see cref="NativeDataResult{T}"/> 中的条目格式化为人类可读文本。
/// 这是"数据先入类, 再从类出"流程的"出"环节。
/// </summary>
internal static class DataFormatter
{
    // ═══════════════════════════════════════════════════════════════
    //  通用辅助
    // ═══════════════════════════════════════════════════════════════

    private static void PrintFailure<T>(NativeDataResult<T> result) where T : struct
    {
        Console.WriteLine($"[失败] ErrorCode={result.Header.ErrorCode}, Message={result.ErrorMessage}");
    }

    private static string Hex(ulong v) => $"0x{v:X}";
    private static string Hex(uint v)  => $"0x{v:X}";
    private static string Hex(int v)  => $"0x{v:X}";

    private static string KlassName(int klass) => klass switch
    {
        0 => "INBOX",
        1 => "MICROSOFT",
        2 => "THIRD_PARTY_WHQL",
        3 => "UNTRUSTED",
        _ => $"UNKNOWN({klass})"
    };

    private static void PrintBar()
    {
        Console.WriteLine(new string('=', 78));
    }

    // ═══════════════════════════════════════════════════════════════
    //  各命令的格式化方法
    // ═══════════════════════════════════════════════════════════════

    public static int FormatKernelScan(NativeDataResult<LoadedDriverEntry> r)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        LoadedDriverEntry[] a = r.Entries;
        Console.WriteLine($"已加载内核驱动: {a.Length} 个");
        PrintBar();
        Console.WriteLine($"{"#",3}  {"Base",-18} {"Size",-10} {"Idx",4} {"Flg",4}  {"Module",-24} {"DriverObj",-24}");
        Console.WriteLine(new string('-', 78));
        for (int i = 0; i < a.Length; i++)
        {
            ref var e = ref a[i];
            Console.WriteLine($"{i,3}  {Hex(e.ImageBase),-18} {e.ImageSize,-10} {e.LoadOrderIndex,4} {e.Flags,4}  " +
                              $"{Trunc(e.ModuleName, 24),-24} {Trunc(e.DriverObjectName, 24),-24}");
        }
        PrintBar();
        Console.WriteLine($"合计: {a.Length} 个");
        return 0;
    }

    public static int FormatClassify(NativeDataResult<CbnClassifyEntry> r, string title)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnClassifyEntry[] a = r.Entries;
        int inbox = 0, ms = 0, whql = 0, untrusted = 0;
        for (int i = 0; i < a.Length; i++)
        {
            switch (a[i].Klass) { case 0: inbox++; break; case 1: ms++; break; case 2: whql++; break; case 3: untrusted++; break; }
        }
        Console.WriteLine(title);
        Console.WriteLine($"共枚举 {a.Length} 个驱动, 分类完成");
        PrintBar();
        Console.WriteLine($"  INBOX:            {inbox}  (放过)");
        Console.WriteLine($"  MICROSOFT:        {ms}  (放过)");
        Console.WriteLine($"  THIRD_PARTY_WHQL: {whql}  (待附着, 无路径/UNTRUSTED 除外)");
        Console.WriteLine($"    其中 UNTRUSTED: {untrusted}  (异常, 需人工核查)");
        PrintBar();

        if (a.Length == 0) return 0;
        Console.WriteLine($"{"#",3}  {"Class",-18} {"FileName",-24} {"Vendor",-20} {"Catalog",7} {"Embed",5}");
        Console.WriteLine(new string('-', 78));
        for (int i = 0; i < a.Length; i++)
        {
            ref var e = ref a[i];
            Console.WriteLine($"{i,3}  {KlassName(e.Klass),-18} {Trunc(e.FileName, 24),-24} " +
                              $"{Trunc(e.VendorName, 20),-20} {(e.HasCatalog != 0 ? "yes" : "no"),7} " +
                              $"{(e.HasEmbedded != 0 ? "yes" : "no"),5}");
            if (e.SignerCount > 0)
            {
                for (int s = 0; s < e.SignerCount && s < e.Signers.Length; s++)
                {
                    ref var signer = ref e.Signers[s];
                    if (string.IsNullOrEmpty(signer.Subject)) continue;
                    Console.WriteLine($"       签名者[{s}]: {Trunc(signer.Subject, 60)}");
                }
            }
            if (!string.IsNullOrEmpty(e.ErrorReason))
                Console.WriteLine($"       [错误] {e.ErrorReason}");
        }
        PrintBar();
        return 0;
    }

    public static int FormatEnumDevices(NativeDataResult<DeviceEntry> r, string driverName)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        DeviceEntry[] a = r.Entries;
        Console.WriteLine($"驱动 {driverName} 的设备列表: {a.Length} 个");
        PrintBar();
        Console.WriteLine($"{"#",3}  {"DeviceObj",-18} {"Type",10} {"Char",10} {"Flags",10} {"Att",4} {"Stk",3}  {"DeviceName",-30}");
        Console.WriteLine(new string('-', 78));
        for (int i = 0; i < a.Length; i++)
        {
            ref var e = ref a[i];
            Console.WriteLine($"{i,3}  {Hex(e.DeviceObject),-18} {e.DeviceType,10} {e.Characteristics,10} " +
                              $"{e.Flags,10} {e.AttachedCount,4} {e.StackSize,3}  {Trunc(e.DeviceName, 30),-30}");
        }
        PrintBar();
        return 0;
    }

    public static int FormatIat(NativeDataResult<CbnIatResult> r)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnIatResult d = r.SingleEntry;
        Console.WriteLine($"IAT 扫描: {d.FilePath}");
        Console.WriteLine($"DLL 数: {d.DllCount}, API 总数: {d.TotalApiCount}, 危险 API: {d.DangerousApiCount}");
        PrintBar();
        for (int i = 0; i < d.DllCount && i < d.Entries.Length; i++)
        {
            ref var dll = ref d.Entries[i];
            Console.WriteLine($"[{i}] {dll.DllName}  (API {dll.ApiCount} 个)");
            for (int j = 0; j < dll.ApiCount && j < dll.Apis.Length; j++)
            {
                ref var api = ref dll.Apis[j];
                string mark = api.IsDangerous != 0 ? " [危险]" : "";
                Console.WriteLine($"      {api.Name}{mark}");
            }
        }
        PrintBar();
        return 0;
    }

    public static int FormatAttach(NativeDataResult<CbnAttachResult> r, string devicePath)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnAttachResult d = r.SingleEntry;
        Console.WriteLine($"附着设备: {devicePath}");
        PrintBar();
        Console.WriteLine($"  状态:           {(d.Status == 0 ? "成功" : $"失败 ({d.Status})")}");
        Console.WriteLine($"  AttachId:       {d.AttachId}");
        Console.WriteLine($"  FilterDevice:   {Hex(d.FilterDeviceAddr)}");
        Console.WriteLine($"  LowerDevice:    {Hex(d.LowerDeviceAddr)}");
        Console.WriteLine($"  NewStackSize:   {d.NewStackSize}");
        Console.WriteLine($"  TargetStackSize:{d.TargetStackSize}");
        PrintBar();
        return 0;
    }

    public static int FormatUnattach(NativeDataResult<CbnDetachResult> r, string arg)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnDetachResult d = r.SingleEntry;
        Console.WriteLine($"解绑附着: {arg}");
        PrintBar();
        Console.WriteLine($"  状态:        {(d.Status == 0 ? "成功" : $"失败 ({d.Status})")}");
        Console.WriteLine($"  DetachedId:  {d.DetachedId}");
        PrintBar();
        return 0;
    }

    public static int FormatListAttachments(NativeDataResult<AttachEntry> r)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        AttachEntry[] a = r.Entries;
        Console.WriteLine($"当前附着列表: {a.Length} 个");
        PrintBar();
        Console.WriteLine($"{"#",3}  {"Filter",-18} {"Lower",-18} {"Id",6} {"Stk",3}  {"TargetPath",-30}");
        Console.WriteLine(new string('-', 78));
        for (int i = 0; i < a.Length; i++)
        {
            ref var e = ref a[i];
            Console.WriteLine($"{i,3}  {Hex(e.FilterDeviceAddr),-18} {Hex(e.LowerDeviceAddr),-18} {e.AttachId,6} {e.StackSize,3}  " +
                              $"{Trunc(e.TargetPath, 30),-30}");
        }
        PrintBar();
        return 0;
    }

    public static int FormatScanObjects(NativeDataResult<CbnNtDirEntry> r, string dirs)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnNtDirEntry[] a = r.Entries;
        Console.WriteLine($"对象管理器扫描: {dirs}");
        Console.WriteLine($"共收集 {a.Length} 条");
        PrintBar();
        Console.WriteLine($"{"#",5}  {"Name",-40} {"Type",-20} {"LinkTarget",-30}");
        Console.WriteLine(new string('-', 78));
        for (int i = 0; i < a.Length; i++)
        {
            ref var e = ref a[i];
            Console.WriteLine($"{i,5}  {Trunc(e.Name, 40),-40} {Trunc(e.TypeName, 20),-20} {Trunc(e.LinkTarget, 30),-30}");
        }
        PrintBar();
        return 0;
    }

    public static int FormatEtw(NativeDataResult<CbnEtwEvent> r, uint durationSec)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnEtwEvent[] a = r.Entries;
        Console.WriteLine($"ETW 订阅完成 (持续 {durationSec}s): 收集 {a.Length} 个事件");
        PrintBar();
        Console.WriteLine($"{"#",5}  {"ReqPid",10} {"AttachId",10} {"IOC",10} {"MF",3} {"Mth",3}  {"Target",-18} {"Filter",-18}");
        Console.WriteLine(new string('-', 78));
        for (int i = 0; i < a.Length; i++)
        {
            ref var e = ref a[i];
            Console.WriteLine($"{i,5}  {e.RequestorPid,10} {e.AttachId,10} {Hex(e.IoControlCode),10} {e.MajorFunction,3} {e.Method,3}  " +
                              $"{Hex(e.TargetDeviceAddr),-18} {Hex(e.FilterDeviceAddr),-18}");
            if (e.StackFrameCount > 0)
            {
                int n = Math.Min(e.StackFrameCount, e.StackFrames.Length);
                Console.Write("       栈:");
                for (int j = 0; j < n; j++) Console.Write($" {Hex(e.StackFrames[j])}");
                Console.WriteLine();
            }
        }
        PrintBar();
        return 0;
    }

    public static int FormatComms(NativeDataResult<CbnCommsSummary> r, uint durationSec)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnCommsSummary d = r.SingleEntry;
        int pathCount = (int)d.PathCount;
        Console.WriteLine($"通信监控完成 (持续 {durationSec}s)");
        Console.WriteLine($"路径数: {d.PathCount}, IOCTL 数: {d.TotalIoctls}, 事件数: {d.TotalEvents}");
        PrintBar();
        Console.WriteLine($"{"#",4}  {"Path",-40} {"Tag",-12} {"Pid",8} {"Hits",5} {"Abn",3} {"Dumped",6}  {"Note",-20}");
        Console.WriteLine(new string('-', 78));
        for (int i = 0; i < pathCount && i < d.Paths.Length; i++)
        {
            ref var p = ref d.Paths[i];
            Console.WriteLine($"{i,4}  {Trunc(p.Path, 40),-40} {Trunc(p.Tag, 12),-12} {p.Pid,8} {p.HitCount,5} " +
                              $"{p.Abnormal,3} {(p.Dumped != 0 ? "yes" : "no"),6}  {Trunc(p.Note, 20),-20}");
        }
        PrintBar();
        return 0;
    }

    public static int FormatScanHandles(NativeDataResult<CbnHandleEntry> r, uint targetPid)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnHandleEntry[] a = r.Entries;
        int highRisk = 0;
        for (int i = 0; i < a.Length; i++) if (a[i].HighRisk != 0) highRisk++;
        Console.WriteLine($"句柄扫描: 持有 PID={targetPid} 的句柄 (共 {a.Length} 个, 高危 {highRisk})");
        PrintBar();
        Console.WriteLine($"{"#",3}  {"OwnerPid",10} {"OwnerName",-20} {"Handle",12} {"Access",10} {"TargetPid",10} {"Type",-12} {"Risk",4}");
        Console.WriteLine(new string('-', 78));
        for (int i = 0; i < a.Length; i++)
        {
            ref var e = ref a[i];
            Console.WriteLine($"{i,3}  {e.OwnerPid,10} {Trunc(e.OwnerName, 20),-20} {Hex(e.HandleValue),12} " +
                              $"{Trunc(e.AccessStr, 10),-10} {e.TargetPid,10} {Trunc(e.TypeName, 12),-12} " +
                              $"{(e.HighRisk != 0 ? "YES" : "no"),4}");
        }
        PrintBar();
        return 0;
    }

    public static int FormatTree(NativeDataResult<CbnProcBrief> r)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnProcBrief[] a = r.Entries;
        Console.WriteLine($"进程树: {a.Length} 个进程");

        if (a.Length == 0)
        {
            PrintBar();
            return 0;
        }

        PrintBar();

        Dictionary<ulong, CbnProcBrief> byPid = new(a.Length);
        Dictionary<ulong, List<ulong>> children = new(a.Length);

        for (int i = 0; i < a.Length; i++)
        {
            ref var p = ref a[i];
            byPid[p.Pid] = p;
            if (p.Ppid != p.Pid)
            {
                children.TryAdd(p.Ppid, new List<ulong>());
                children[p.Ppid].Add(p.Pid);
            }
        }

        foreach (var kv in children)
            kv.Value.Sort();

        ulong totalThreads = 0;
        ulong totalWs = 0;
        for (int i = 0; i < a.Length; i++)
        {
            totalThreads += a[i].Threads;
            totalWs += a[i].WorkingSet;
        }
        Console.WriteLine($"进程树快照: 共 {a.Length} 个进程, {totalThreads} 个线程, 总工作集 {totalWs / 1024} KB");
        Console.WriteLine(new string('-', 78));
        Console.WriteLine();

        List<ulong> roots = new();
        for (int i = 0; i < a.Length; i++)
        {
            ref var p = ref a[i];
            if (p.Pid == 0)
                roots.Insert(0, 0);
            else if (!byPid.ContainsKey(p.Ppid))
                roots.Add(p.Pid);
        }
        roots.Sort();
        roots = roots.Distinct().ToList();

        for (int i = 0; i < roots.Count; i++)
        {
            PrintTreeNode(byPid, children, roots[i], "", true, true);
            if (i + 1 < roots.Count)
                Console.WriteLine();
        }

        PrintBar();
        return 0;
    }

    private static void PrintTreeNode(Dictionary<ulong, CbnProcBrief> byPid,
                                      Dictionary<ulong, List<ulong>> children,
                                      ulong pid, string indent, bool isLast, bool isRoot)
    {
        if (!byPid.TryGetValue(pid, out CbnProcBrief info))
            return;

        string branch = isRoot ? "" : (isLast ? "└── " : "├── ");

        Console.WriteLine($"{indent}{branch}{info.Pid} {Trunc(info.Name, 32)}  [PPID={info.Ppid}, 线程={info.Threads}, 句柄={info.Handles}, WS={info.WorkingSet / 1024} KB, 私有={info.PrivatePages / 1024} KB, 优先级={info.BasePriority}]");

        if (!children.TryGetValue(pid, out List<ulong>? kids) || kids == null || kids.Count == 0)
            return;

        string childIndent = isRoot ? "" : indent + (isLast ? "    " : "│   ");

        for (int i = 0; i < kids.Count; i++)
        {
            bool last = (i + 1 == kids.Count);
            PrintTreeNode(byPid, children, kids[i], childIndent, last, false);
        }
    }

    public static int FormatSecurity(NativeDataResult<CbnProcDetail> r, ulong pid)
    {
        if (!r.Success) { PrintFailure(r); return r.Header.ErrorCode; }
        CbnProcDetail[] a = r.Entries;
        Console.WriteLine($"安全采集: {a.Length} 个进程 (target PID={pid})");
        PrintBar();
        for (int i = 0; i < a.Length; i++)
        {
            ref var d = ref a[i];
            ref var b = ref d.Brief;
            Console.WriteLine($"[PID {b.Pid}] {b.Name}  (PPID={b.Ppid}, 阻塞句柄数={b.Handles}, PPL={d.Protection}" +
                              $"{(d.PplBroken != 0 ? " [PPL 已破坏]" : "")})");
            Console.WriteLine($"  ImagePath:   {d.ImagePath}");
            Console.WriteLine($"  CommandLine: {Trunc(d.CommandLine, 100)}");

            if (d.EnabledPrivCount > 0)
            {
                Console.Write("  EnabledPrivs:");
                for (int j = 0; j < d.EnabledPrivCount && j < d.EnabledPrivs.Length; j++)
                    Console.Write($" {d.EnabledPrivs[j].Name}");
                Console.WriteLine();
            }
            if (d.DisabledPrivCount > 0)
            {
                Console.Write("  DisabledPrivs:");
                for (int j = 0; j < d.DisabledPrivCount && j < d.DisabledPrivs.Length; j++)
                    Console.Write($" {d.DisabledPrivs[j].Name}");
                Console.WriteLine();
            }

            if (d.ThreadInfoCount > 0)
            {
                Console.WriteLine($"  线程: {d.ThreadInfoCount} 个");
                for (int j = 0; j < d.ThreadInfoCount && j < d.ThreadInfos.Length; j++)
                {
                    ref var t = ref d.ThreadInfos[j];
                    string susp = t.IsSuspended != 0 ? " [挂起]" : "";
                    Console.WriteLine($"    TID={t.Tid} Start={Hex(t.StartAddress)} Win32Start={Hex(t.Win32StartAddress)}" +
                                      $" Mod={Trunc(t.StartModule, 30)}{susp}");
                }
            }

            if (d.ModuleCount > 0)
            {
                Console.WriteLine($"  模块: {d.ModuleCount} 个 (仅显示前 10)");
                int show = Math.Min(d.ModuleCount, Math.Min(10, d.Modules.Length));
                for (int j = 0; j < show; j++)
                {
                    ref var m = ref d.Modules[j];
                    Console.WriteLine($"    Base={Hex(m.Base)} Size={m.Size} {m.Name}");
                }
            }

            if (d.MemRegionCount > 0)
            {
                Console.WriteLine($"  可疑内存: {d.MemRegionCount} 个");
                for (int j = 0; j < d.MemRegionCount && j < d.MemRegions.Length; j++)
                {
                    ref var mem = ref d.MemRegions[j];
                    Console.WriteLine($"    Base={Hex(mem.Base)} Size={mem.Size} {mem.ProtectStr}/{mem.TypeStr} [{mem.Reason}]");
                }
            }

            if (d.HandleCount > 0)
            {
                Console.WriteLine($"  高危句柄: {d.HandleCount} 个");
                for (int j = 0; j < d.HandleCount && j < d.Handles.Length; j++)
                {
                    ref var h = ref d.Handles[j];
                    Console.WriteLine($"    Owner={h.OwnerPid}({Trunc(h.OwnerName, 16)}) Handle={Hex(h.HandleValue)} " +
                                      $"Access={Trunc(h.AccessStr, 16)} Type={Trunc(h.TypeName, 12)}");
                }
            }
            Console.WriteLine(new string('-', 78));
        }
        return 0;
    }

    // ═══════════════════════════════════════════════════════════════
    //  字符串截断
    // ═══════════════════════════════════════════════════════════════

    private static string Trunc(string? s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        // 控制台宽度有限, 中文名长度按 char 计算
        return s.Length <= max ? s : s.Substring(0, max - 1) + "…";
    }
}
