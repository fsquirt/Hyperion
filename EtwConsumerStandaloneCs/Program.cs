// Program.cs — 独立复刻 DriverAttachSelector.exe --etw 功能 (C# 版)
//
// 流程 (带详细输出, 与 C++ 版 EtwConsumerStandalone 一一对应):
//   1. 启用 SeSystemProfilePrivilege / SeDebugPrivilege
//   2. StartTraceW 开 Real-Time Session
//   3. EnableTraceEx2 带 EVENT_ENABLE_PROPERTY_STACK_TRACE 启用 Provider
//   4. OpenTraceW + ProcessTrace 实时消费
//   5. EventRecordCallback 解析 ETW_IOCTL_EVENT_HEADER + Payload + 调用栈
//
// 运行:
//   dotnet run -- [--duration 30] [--out C:\x.etl]
// 必须以管理员身份运行。

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace EtwConsumerCs;

internal static class Program
{
    // Provider GUID 与内核 EtwLogger.h 一致
    private static readonly Guid ProviderGuid = new("A7B3C9D2-4E5F-4A1B-9C8E-7D6F5E4A3B2C");
    private static readonly string SessionName = "KernelServiceIoctlTrace";

    private static readonly object Gate = new();
    private static Thread? _pumpThread;
    private static bool _stopFlag;

    // 防止回调被 GC 回收 (必须持有根)
    private static readonly EventRecordCallbackDelegate RecordCb = EventRecordCallback;
    private static readonly BufferCallbackDelegate BufferCb = BufferCallback;

    private static byte[]? _propsBuf;
    private static GCHandle _propsHandle;
    private static ulong _sessionHandle;
    private static ulong _consumerHandle;

    private static int Main(string[] args)
    {
        uint durationSec = 30;
        string? etlPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--duration" && i + 1 < args.Length) durationSec = uint.Parse(args[++i]);
            else if (args[i] == "--out" && i + 1 < args.Length) etlPath = args[++i];
            else if (args[i] == "--help" || args[i] == "-h")
            {
                Console.WriteLine("用法: EtwConsumerStandalone.exe [--duration 秒] [--out 文件.etl]");
                return 0;
            }
        }

        Console.WriteLine("═══════════════════════════════════════════════════════");
        Console.WriteLine("  ETW 实时订阅 — IOCTL 拦截事件 + 跨态调用栈 (独立版 C#)");
        Console.WriteLine("═══════════════════════════════════════════════════════");
        Log("INIT", $"Provider GUID: {{{ProviderGuid}}}");
        Log("INIT", $"Session 名称: {SessionName}");
        Log("INIT", durationSec > 0 ? $"持续时间: {durationSec} 秒" : "持续时间: 永久 (Ctrl+C 退出)");
        if (etlPath != null) Log("INIT", $"落盘文件: {etlPath}");

        // 当前是否管理员
        bool isAdmin = IsAdministrator();
        Log("INIT", $"是否管理员: {isAdmin} (StartTraceW 需要管理员权限)");

        _stopFlag = false;

        // Ctrl+C 处理
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            lock (Gate) _stopFlag = true;
            Log("CTRLC", "收到 Ctrl+C, 正在停止订阅...");
        };

        EnsurePrivileges();

        _pumpThread = new Thread(Pump) { IsBackground = true, Name = "EtwIoctlPump" };
        _pumpThread.Start();

        // 主线程等待泵线程退出
        _pumpThread.Join();
        Console.WriteLine("[OK] ETW 订阅已停止");
        return 0;
    }

    // ─────────────────────────────────────────────────────────────
    //  后台泵线程
    // ─────────────────────────────────────────────────────────────
    private static void Pump()
    {
        Log("PUMP", "进入泵线程");
        try
        {
            if (!SetupSession())
            {
                Console.Error.WriteLine("[ETW] 会话初始化失败，订阅未启动");
                return;
            }

            Log("PUMP", "SetupSession 成功, 开始 OpenTraceW");
            var logFile = BuildLogFile();
            Log("PUMP", $"EVENT_TRACE_LOGFILE: LoggerName='{logFile.LoggerName}' ProcessTraceMode=0x{logFile.ProcessTraceMode:X8} IsKernelTrace={logFile.IsKernelTrace}");
            _consumerHandle = OpenTraceW(ref logFile);
            int openErr = Marshal.GetLastWin32Error();
            if (_consumerHandle == INVALID_PROCESSTRACE_HANDLE)
            {
                Console.Error.WriteLine($"[ETW] OpenTraceW 失败: 0x{openErr:X8} (lastError={openErr})");
                StopTrace();
                return;
            }

            Log("PUMP", $"OpenTraceW 成功, consumerHandle=0x{_consumerHandle:X16}");
            Console.WriteLine("[ETW] 已订阅 Provider，等待 IOCTL 拦截事件…");

            while (true)
            {
                lock (Gate) { if (_stopFlag) break; }

                ulong[] handles = { _consumerHandle };
                Log("PUMP", "调用 ProcessTrace (阻塞)…");
                uint ptStatus = ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);
                Log("PUMP", $"ProcessTrace 返回: 0x{ptStatus:X8} lastError={Marshal.GetLastWin32Error()}");

                lock (Gate) { if (_stopFlag) break; }
                // 若异常退出 (Session 被外部停止), 等待一小段时间后重连尝试已无意义, 直接退出
                break;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ETW] 泵线程异常: {ex.Message}");
            Log("PUMP", $"异常: {ex}");
        }
        finally
        {
            Log("PUMP", "finally: 调用 StopTrace");
            StopTrace();
        }
    }

    private static bool SetupSession()
    {
        Log("SETUP", "进入 SetupSession");
        int propsSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>();
        int nameBytes = (SessionName.Length + 1) * 2;
        _propsBuf = new byte[propsSize + nameBytes];
        Log("SETUP", $"EVENT_TRACE_PROPERTIES 托管大小={propsSize}, sessionName.Length={SessionName.Length}, nameBytes={nameBytes}, 缓冲区总长={propsSize + nameBytes}");

        var props = new EVENT_TRACE_PROPERTIES
        {
            Wnode =
            {
                BufferSize = (uint)(propsSize + nameBytes),
                ClientContext = 1,
                Flags = WNODE_FLAG_TRACED_GUID
            },
            BufferSize = 64,
            MinimumBuffers = 4,
            MaximumBuffers = 32,
            MaximumFileSize = 100,
            FlushTimer = 1,
            LogFileMode = EVENT_TRACE_REAL_TIME_MODE,
            LogFileNameOffset = 0,
            LoggerNameOffset = (uint)propsSize
        };
        Marshal.StructureToPtr(props, Marshal.UnsafeAddrOfPinnedArrayElement(_propsBuf, 0), false);

        // 写入 Session 名称 (紧跟结构体尾部)
        int nameOffset = propsSize;
        for (int i = 0; i < SessionName.Length; i++)
        {
            short c = (short)SessionName[i];
            Buffer.BlockCopy(BitConverter.GetBytes(c), 0, _propsBuf, nameOffset + i * 2, 2);
        }
        // 末尾 \0
        Buffer.BlockCopy(BitConverter.GetBytes((short)0), 0, _propsBuf, nameOffset + SessionName.Length * 2, 2);

        _propsHandle = GCHandle.Alloc(_propsBuf, GCHandleType.Pinned);
        IntPtr pProps = _propsHandle.AddrOfPinnedObject();

        Log("SETUP", "EVENT_TRACE_PROPERTIES 明细:");
        Log("SETUP", $"  Wnode.BufferSize   = {props.Wnode.BufferSize} (期望值 {propsSize + nameBytes})");
        Log("SETUP", $"  Wnode.Flags        = 0x{props.Wnode.Flags:X8} (WNODE_FLAG_TRACED_GUID=0x{WNODE_FLAG_TRACED_GUID:X8})");
        Log("SETUP", $"  Wnode.ClientContext= {props.Wnode.ClientContext} (1=QPC)");
        Log("SETUP", $"  Wnode.Guid         = {props.Wnode.Guid}");
        Log("SETUP", $"  BufferSize         = {props.BufferSize}");
        Log("SETUP", $"  MinimumBuffers     = {props.MinimumBuffers}");
        Log("SETUP", $"  MaximumBuffers     = {props.MaximumBuffers}");
        Log("SETUP", $"  MaximumFileSize    = {props.MaximumFileSize}");
        Log("SETUP", $"  FlushTimer         = {props.FlushTimer}");
        Log("SETUP", $"  LogFileMode        = 0x{props.LogFileMode:X8} (REAL_TIME_MODE=0x{EVENT_TRACE_REAL_TIME_MODE:X8})");
        Log("SETUP", $"  LogFileNameOffset  = {props.LogFileNameOffset}");
        Log("SETUP", $"  LoggerNameOffset   = {props.LoggerNameOffset} (propsSize={propsSize})");

        bool nameInside = props.LoggerNameOffset + nameBytes <= props.Wnode.BufferSize;
        Log("SETUP", $"  LoggerName 是否落在 BufferSize 内: {nameInside}");

        // 先停残留 Session
        StopTrace();

        // 【关键修复】StopTrace 成功时会作为 OUT 参数覆写内存，导致属性变脏（如 LogFileNameOffset 越界）。
        // 必须在这里重新把干净的 props 序列化回内存中！
        Marshal.StructureToPtr(props, pProps, false);
        for (int i = 0; i < SessionName.Length; i++)
        {
            Buffer.BlockCopy(BitConverter.GetBytes((short)SessionName[i]), 0, _propsBuf, nameOffset + i * 2, 2);
        }
        Buffer.BlockCopy(BitConverter.GetBytes((short)0), 0, _propsBuf, nameOffset + SessionName.Length * 2, 2);

        // 原始属性缓冲区 hex dump (与 C++ 端逐字节对拍)
        DumpPropsBuffer();

        Log("SETUP", $"调用 StartTraceW(sessionName='{SessionName}')…");
        uint status = StartTraceW(out _sessionHandle, SessionName, pProps);
        int lastErr = Marshal.GetLastWin32Error();
        Log("SETUP", $"StartTraceW 返回 status=0x{status:X8}, sessionHandle=0x{_sessionHandle:X16}, lastError=0x{lastErr:X8}");
        if (status != ERROR_SUCCESS)
        {
            Console.Error.WriteLine($"[ETW] StartTraceW 失败: 0x{status:X8}");
            return false;
        }
        Console.WriteLine($"[OK] ETW Session 已启动: {SessionName}");

        // EnableTraceEx2
        var enableParams = new ENABLE_TRACE_PARAMETERS
        {
            Version = ENABLE_TRACE_PARAMETERS_VERSION_2,
            EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE,
            SourceId = ProviderGuid
        };

        GCHandle hParams = GCHandle.Alloc(enableParams, GCHandleType.Pinned);
        Guid provGuid = ProviderGuid;
        Log("SETUP", $"调用 EnableTraceEx2(providerGuid={provGuid}, level=VERBOSE, EnableProperty=0x{enableParams.EnableProperty:X8})…");
        try
        {
            status = EnableTraceEx2(_sessionHandle, ref provGuid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                0, 0, 0, hParams.AddrOfPinnedObject());
        }
        finally { hParams.Free(); }
        Log("SETUP", $"EnableTraceEx2 返回 status=0x{status:X8}, lastError=0x{Marshal.GetLastWin32Error():X8}");

        if (status != ERROR_SUCCESS)
        {
            Console.Error.WriteLine($"[ETW] EnableTraceEx2 失败: 0x{status:X8}");
            StopTrace();
            return false;
        }
        Console.WriteLine("[ETW] Provider 已启用（含 EVENT_ENABLE_PROPERTY_STACK_TRACE）");
        return true;
    }

    private static EVENT_TRACE_LOGFILE BuildLogFile()
    {
        return new EVENT_TRACE_LOGFILE
        {
            LoggerName = SessionName,
            ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            EventRecordCallback = RecordCb,
            BufferCallback = BufferCb,
            IsKernelTrace = 0
        };
    }

    private static void StopTrace()
    {
        if (!_propsHandle.IsAllocated)
        {
            Log("STOPTRACE", "props 未分配, 跳过");
            return;
        }
        Log("STOPTRACE", $"调用 ControlTraceW(STOP): sessionHandle=0x{_sessionHandle:X16}, sessionName='{SessionName}'");
        uint st = ControlTraceW(_sessionHandle, SessionName, _propsHandle.AddrOfPinnedObject(), EVENT_TRACE_CONTROL_STOP);
        Log("STOPTRACE", $"ControlTraceW 返回 status=0x{st:X8}, lastError=0x{Marshal.GetLastWin32Error():X8}");
    }

    // ─────────────────────────────────────────────────────────────
    //  事件回调
    // ─────────────────────────────────────────────────────────────
    private static void EventRecordCallback(ref EVENT_RECORD record)
    {
        try
        {
            Log("CB", $"收到事件: ProviderId={record.EventHeader.ProviderId} EventId={record.EventHeader.EventDescriptor.Id} Version={record.EventHeader.EventDescriptor.Version} UserDataLength={record.UserDataLength} ExtendedDataCount={record.ExtendedDataCount}");

            if (record.EventHeader.EventDescriptor.Id != 1) return;
            if (record.UserData == IntPtr.Zero) return;
            if (record.UserDataLength < Marshal.SizeOf<EtwIoctlEventHeader>()) return;

            var hdr = Marshal.PtrToStructure<EtwIoctlEventHeader>(record.UserData)!;
            if (hdr.AttachId == 0) return;

            DateTime ts = DateTime.FromFileTime((long)record.EventHeader.TimeStamp);
            ulong[] frames = CollectStackFrames(record);

            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine($"  IOCTL 拦截事件  (AttachId={hdr.AttachId})");
            sb.AppendLine("───────────────────────────────────────────────────────");
            sb.AppendLine($"  IoControlCode:    0x{hdr.IoControlCode:X8}  (METHOD_{(hdr.IoControlCode & 3) switch { 0 => "BUFFERED", 1 => "IN_DIRECT", 2 => "OUT_DIRECT", 3 => "NEITHER", _ => "?" }})");
            sb.Append($"  MajorFunction:    0x{hdr.MajorFunction:X2}");
            sb.Append(hdr.MajorFunction == 0x0E ? " (DEVICE_CONTROL)" :
                      hdr.MajorFunction == 0x00 ? " (CREATE)" :
                      hdr.MajorFunction == 0x02 ? " (CLOSE)" :
                      hdr.MajorFunction == 0x03 ? " (READ)" :
                      hdr.MajorFunction == 0x04 ? " (WRITE)" : "");
            sb.AppendLine();
            sb.AppendLine($"  发起进程 PID:     {hdr.RequestorPid}");
            sb.AppendLine($"  InputBuffer 长度: {hdr.InputBufferLength} 字节");
            sb.AppendLine($"  实际抓取:         {hdr.CaptureSize} 字节 (最多 4096)");
            sb.AppendLine($"  FilterDevice:     0x{hdr.FilterDeviceAddr:X16}");
            sb.AppendLine($"  TargetDevice:     0x{hdr.TargetDeviceAddr:X16}");
            sb.AppendLine($"  时间:             {ts:HH:mm:ss.fff}");
            Console.WriteLine(sb.ToString());

            // Payload
            int payloadLen = (int)hdr.CaptureSize;
            if (Marshal.SizeOf<EtwIoctlEventHeader>() + payloadLen > record.UserDataLength)
                payloadLen = record.UserDataLength - Marshal.SizeOf<EtwIoctlEventHeader>();
            if (payloadLen > 0)
            {
                var payload = new byte[payloadLen];
                Marshal.Copy(IntPtr.Add(record.UserData, Marshal.SizeOf<EtwIoctlEventHeader>()), payload, 0, payloadLen);
                Console.WriteLine("  Payload (Hex Dump):");
                Console.WriteLine(HexDump(payload));
            }
            else
            {
                Console.WriteLine("  Payload: <空>");
            }

            // 调用栈
            PrintStackTrace(frames, hdr.RequestorPid);
        }
        catch (Exception ex)
        {
            Log("CB", $"回调异常(已吞掉): {ex.Message}");
        }
    }

    private static void PrintStackTrace(ulong[] frames, ulong requestorPid)
    {
        if (frames.Length == 0)
        {
            Console.WriteLine("  调用栈: <无栈帧 — 检查 SeSystemProfilePrivilege>");
            return;
        }
        Console.WriteLine($"  调用栈 ({frames.Length} 帧):");
        for (int f = 0; f < frames.Length; f++)
        {
            Console.Write($"    [{f,2}] 0x{frames[f]:X16}");
            if (frames[f] < 0x800000000000UL)
            {
                string? mod = ResolveUserModule(requestorPid, frames[f]);
                Console.WriteLine(mod != null ? $"  {mod}" : "  <用户态:未解析>");
            }
            else
            {
                Console.WriteLine("  <内核态>");
            }
        }
    }

    private static string? ResolveUserModule(ulong pid, ulong addr)
    {
        if (pid == 0) return null;
        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)pid);
        if (hProc == IntPtr.Zero) return null;
        try
        {
            const int max = 1024;
            var mods = new IntPtr[max];
            if (EnumProcessModules(hProc, mods, (uint)(max * IntPtr.Size), out uint cb))
            {
                int count = (int)(cb / IntPtr.Size);
                if (count > max) count = max;
                for (int i = 0; i < count; i++)
                {
                    if (GetModuleInformation(hProc, mods[i], out MODULEINFO mi, (uint)Marshal.SizeOf<MODULEINFO>()))
                    {
                        ulong baseAddr = (ulong)mi.lpBaseOfDll;
                        if (addr >= baseAddr && addr < baseAddr + mi.SizeOfImage)
                        {
                            var sb = new StringBuilder(260);
                            GetModuleFileNameExW(hProc, mods[i], sb, (uint)sb.Capacity);
                            string path = sb.ToString();
                            int idx = path.LastIndexOf('\\');
                            string name = idx >= 0 ? path.Substring(idx + 1) : path;
                            return $"{name}+0x{addr - baseAddr:X}";
                        }
                    }
                }
            }
            return null;
        }
        finally { CloseHandle(hProc); }
    }

    private static uint BufferCallback(IntPtr logfile)
    {
        lock (Gate)
        {
            uint ret = _stopFlag ? 0u : 1u;
            Log("BCB", $"BufferCallback stopFlag={_stopFlag} -> {(ret == 0 ? "退出ProcessTrace" : "继续")}");
            return ret;
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  栈帧提取
    // ─────────────────────────────────────────────────────────────
    private static ulong[] CollectStackFrames(EVENT_RECORD record)
    {
        if (record.ExtendedData == IntPtr.Zero || record.ExtendedDataCount == 0)
            return Array.Empty<ulong>();

        int itemSize = Marshal.SizeOf<EVENT_HEADER_EXTENDED_DATA_ITEM>();
        for (int i = 0; i < record.ExtendedDataCount; i++)
        {
            IntPtr p = IntPtr.Add(record.ExtendedData, i * itemSize);
            var item = Marshal.PtrToStructure<EVENT_HEADER_EXTENDED_DATA_ITEM>(p);
            if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE32 &&
                item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
                continue;
            if (item.DataSize < 8) continue;

            bool is64 = item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64;
            int ptrSize = is64 ? 8 : 4;
            int frameCount = (int)(item.DataSize - 8) / ptrSize;
            if (frameCount <= 0) continue;

            var frames = new ulong[Math.Min(frameCount, 64)];
            var dataPtr = new IntPtr((long)item.DataPtr);
            for (int f = 0; f < frames.Length; f++)
            {
                frames[f] = is64
                    ? (ulong)Marshal.ReadInt64(dataPtr, 8 + f * 8)
                    : (ulong)(uint)Marshal.ReadInt32(dataPtr, 8 + f * 4);
            }
            return frames;
        }
        return Array.Empty<ulong>();
    }

    // ─────────────────────────────────────────────────────────────
    //  hex dump
    // ─────────────────────────────────────────────────────────────
    private static void DumpPropsBuffer()
    {
        if (_propsBuf == null) return;
        var sb = new StringBuilder();
        sb.AppendLine($"[PROPS] 属性缓冲区 hex dump (长度={_propsBuf.Length}, 偏移以字节计):");
        const int bytesPerLine = 16;
        for (int off = 0; off < _propsBuf.Length; off += bytesPerLine)
        {
            int len = Math.Min(bytesPerLine, _propsBuf.Length - off);
            sb.Append($"  {off,4:X4}: ");
            for (int i = 0; i < bytesPerLine; i++)
            {
                if (i < len) sb.Append($"{_propsBuf[off + i]:X2} ");
                else sb.Append("   ");
                if (i == 7) sb.Append(' ');
            }
            sb.Append(" | ");
            for (int i = 0; i < len; i++)
            {
                byte b = _propsBuf[off + i];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }
        Log("PROPS", sb.ToString());
    }

    private static string HexDump(byte[] data)
    {
        var sb = new StringBuilder();
        const int bytesPerLine = 16;
        for (int off = 0; off < data.Length; off += bytesPerLine)
        {
            int len = Math.Min(bytesPerLine, data.Length - off);
            sb.Append($"    {off,4:X4}: ");
            for (int i = 0; i < bytesPerLine; i++)
            {
                if (i < len) sb.Append($"{data[off + i]:X2} ");
                else sb.Append("   ");
                if (i == 7) sb.Append(' ');
            }
            sb.Append(" | ");
            for (int i = 0; i < len; i++)
            {
                byte b = data[off + i];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    // ─────────────────────────────────────────────────────────────
    //  权限
    // ─────────────────────────────────────────────────────────────
    private static void EnsurePrivileges()
    {
        Log("PRIV", "开始启用权限");
        bool p1 = EnablePrivilege("SeSystemProfilePrivilege");
        bool p2 = EnablePrivilege("SeDebugPrivilege");
        Log("PRIV", $"SeSystemProfilePrivilege={p1}, SeDebugPrivilege={p2}");
    }

    private static bool EnablePrivilege(string priv)
    {
        Log("PRIV", $"启用 {priv}…");
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, out IntPtr token))
        {
            Log("PRIV", $"{priv}: OpenProcessToken 失败, lastError=0x{Marshal.GetLastWin32Error():X8}");
            return false;
        }
        try
        {
            if (!LookupPrivilegeValueW(null, priv, out LUID luid))
            {
                Log("PRIV", $"{priv}: LookupPrivilegeValueW 失败, lastError=0x{Marshal.GetLastWin32Error():X8}");
                return false;
            }
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Attributes = SE_PRIVILEGE_ENABLED };
            tp.Luid = luid;
            bool ok = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            Log("PRIV", $"{priv}: AdjustTokenPrivileges ok={ok}, lastError=0x{err:X8}");
            return ok && err == 0;
        }
        finally { CloseHandle(token); }
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static void Log(string tag, string msg)
    {
        try { Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [{tag}] {msg}"); }
        catch { }
    }

    // ═══════════════════════════════════════════════════════════════
    //  原生声明
    // ═══════════════════════════════════════════════════════════════
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public sealed class EtwIoctlEventHeader
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
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_DESCRIPTOR
    {
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_HEADER
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public EVENT_DESCRIPTOR EventDescriptor;
        public ulong ProcessorTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_RECORD
    {
        public EVENT_HEADER EventHeader;
        public uint BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public IntPtr UserData;
        public IntPtr UserContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_HEADER_EXTENDED_DATA_ITEM
    {
        public ushort Reserved1;
        public ushort ExtType;
        public ushort Reserved2;
        public ushort DataSize;
        public ulong DataPtr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WNODE_HEADER
    {
        public uint BufferSize;
        public uint ProviderId;
        public ulong HistoricalContext;
        public ulong TimeStamp;   // 对应原生 union { LARGE_INTEGER TimeStamp; ... } (8 字节)
        public Guid Guid;
        public uint ClientContext;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_PROPERTIES
    {
        public WNODE_HEADER Wnode;
        public uint BufferSize;
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers;
        public uint FreeBuffers;
        public uint EventsLost;
        public uint BuffersWritten;
        public uint LogBuffersLost;
        public uint RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ENABLE_TRACE_PARAMETERS
    {
        public uint Version;
        public uint EnableProperty;
        public uint ControlFlags;
        public Guid SourceId;
        public IntPtr EnableFilterDesc;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEMTIME
    {
        public ushort wYear;
        public ushort wMonth;
        public ushort wDayOfWeek;
        public ushort wDay;
        public ushort wHour;
        public ushort wMinute;
        public ushort wSecond;
        public ushort wMilliseconds;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TIME_ZONE_INFORMATION
    {
        public int Bias;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string StandardName;
        public SYSTEMTIME StandardDate;
        public int StandardBias;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DaylightName;
        public SYSTEMTIME DaylightDate;
        public int DaylightBias;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TRACE_LOGFILE_HEADER
    {
        public uint BufferSize;
        public uint Version;
        public uint ProviderVersion;
        public uint NumberOfProcessors;
        public long EndTime;
        public uint TimerResolution;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint BuffersWritten;
        public uint StartBuffers;
        public uint PointerSize;
        public uint EventsLost;
        public uint CpuSpeedInMHz;
        public IntPtr LoggerName;
        public IntPtr LogFileName;
        public TIME_ZONE_INFORMATION TimeZone;
        public long BootTime;
        public long PerfFreq;
        public long StartTime;
        public uint ReservedFlags;
        public uint BuffersLost;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_HEADER
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid Guid;
        public uint KernelTime;
        public uint UserTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE
    {
        public EVENT_TRACE_HEADER Header;
        public uint InstanceId;
        public uint ParentInstanceId;
        public Guid ParentGuid;
        public IntPtr MofData;
        public uint MofLength;
        public uint ClientContext;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EVENT_TRACE_LOGFILE
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? LogFileName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        public EVENT_TRACE CurrentEvent;
        public TRACE_LOGFILE_HEADER LogfileHeader;
        public BufferCallbackDelegate BufferCallback;
        public uint BufferSize;
        public uint Filled;
        public uint EventsLost;
        public EventRecordCallbackDelegate EventRecordCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    private delegate void EventRecordCallbackDelegate(ref EVENT_RECORD eventRecord);
    private delegate uint BufferCallbackDelegate(IntPtr logfile);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint StartTraceW(out ulong sessionHandle, string sessionName, IntPtr properties);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint ControlTraceW(ulong sessionHandle, string? sessionName, IntPtr properties, uint control);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint EnableTraceEx2(ulong sessionHandle, ref Guid providerGuid,
        uint controlCode, byte traceLevel, ulong matchAnyKeyword, ulong matchAllKeyword,
        uint timeout, IntPtr enableParameters);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ulong OpenTraceW(ref EVENT_TRACE_LOGFILE logfile);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint ProcessTrace(ulong[] handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint CloseTrace(ulong handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValueW(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpFilename, uint nSize);

    private const uint ERROR_SUCCESS = 0;
    private const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
    private const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
    private const uint EVENT_ENABLE_PROPERTY_STACK_TRACE = 0x4;
    private const uint ENABLE_TRACE_PARAMETERS_VERSION_2 = 2;
    private const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
    private const uint EVENT_TRACE_CONTROL_STOP = 1;
    private const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
    private const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
    private const byte TRACE_LEVEL_VERBOSE = 0xFF;
    private const ushort EVENT_HEADER_EXT_TYPE_STACK_TRACE32 = 5;
    private const ushort EVENT_HEADER_EXT_TYPE_STACK_TRACE64 = 6;
    private const ulong INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
}
