using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Hyperion.UserService.Modules.Heuristic;

/// <summary>
/// ETW 实时订阅（移植自 DriverAttachSelector/EtwConsumer.cpp 与 HeuristicDumper/CommsMonitor.cpp）。
/// 订阅内核 IOCTL 拦截 Provider（GUID 与 KernelService/EtwLogger.h 一致），
/// 在后台线程消费 EVENT_RECORD，解析 <c>EtwIoctlEventHeader</c> + 跨态调用栈，
/// 对外抛出轻量的 <see cref="IoctlInterceptEvent"/>（仅在回调内做轻量解析，重 IO 由订阅方异步投递）。
/// </summary>
public sealed class EtwSession : IDisposable
{
    private readonly string _sessionName;
    private readonly Guid _providerGuid;
    private readonly object _gate = new();
    private Thread? _pumpThread;
    private bool _running;
    private bool _stopFlag;

    // 防止被 GC 回收的回调引用（必须持有根）
    private readonly EventRecordCallbackDelegate _recordCb;
    private readonly BufferCallbackDelegate _bufferCb;

    // ETW 句柄与缓冲区（保持存活直到 Stop）
    private byte[]? _propsBuf;
    private GCHandle _propsHandle;       // 钉住 propsBuf 防止 GC 移动（传给原生 ETW）
    private ulong _sessionHandle;
    private ulong _consumerHandle;

    public event Action<IoctlInterceptEvent>? IoctlIntercept;

    public EtwSession(string sessionName, Guid providerGuid)
    {
        _sessionName = sessionName;
        _providerGuid = providerGuid;
        _recordCb = EventRecordCallback;
        _bufferCb = BufferCallback;
        Log($"[ETW][INIT] sessionName='{sessionName}' providerGuid={providerGuid}");
    }

    // 统一日志出口（带时间戳，便于与 DriverAttachSelector.exe 控制台日志对照）
    private static void Log(string msg)
    {
        try { Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] {msg}"); }
        catch { }
    }

    // 把将要传给 StartTraceW 的原始属性缓冲区逐字节 hex dump 出来,
    // 用于与 C++ 端逐字节对拍（字段值打印看不出布局错位,必须看真实内存）。
    private void DumpPropsBuffer()
    {
        if (_propsBuf == null) return;
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"[ETW][DUMP] propsBuf 长度={_propsBuf.Length} (偏移以字节计):");
        const int bytesPerLine = 16;
        for (int off = 0; off < _propsBuf.Length; off += bytesPerLine)
        {
            int len = Math.Min(bytesPerLine, _propsBuf.Length - off);
            sb.Append($"  {off,4:X4}: ");
            for (int i = 0; i < bytesPerLine; i++)
            {
                if (i < len) sb.Append($"{_propsBuf[off + i]:X2} ");
                else sb.Append("   ");
            }
            sb.Append(" | ");
            for (int i = 0; i < len; i++)
            {
                byte b = _propsBuf[off + i];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }
        Log(sb.ToString());
    }

    // ─────────────────────────────────────────────────────────────
    //  公共控制
    // ─────────────────────────────────────────────────────────────

    public void Start()
    {
        Log("[ETW][START] 进入 Start");
        lock (_gate)
        {
            if (_running) { Log("[ETW][START] 已经在运行,直接返回"); return; }
            EnsurePrivileges();
            _stopFlag = false;
            _running = true;
        }

        _pumpThread = new Thread(Pump) { IsBackground = true, Name = "EtwIoctlPump" };
        _pumpThread.Start();
        Log("[ETW][START] 泵线程已启动");
    }

    public void Stop()
    {
        bool wasRunning;
        lock (_gate)
        {
            wasRunning = _running;
            _stopFlag = true;
        }
        if (!wasRunning) { Log("[ETW][STOP] 未运行,直接返回"); return; }

        Log("[ETW][STOP] 主动停止 Session 以踢醒 ProcessTrace");
        // 主动停止 Session 踢醒可能阻塞的 ProcessTrace
        StopTrace();

        _pumpThread?.Join(TimeSpan.FromSeconds(6));
        FreeProps();
        lock (_gate) _running = false;
        Log("[ETW][STOP] Stop 完成");
    }

    // ─────────────────────────────────────────────────────────────
    //  后台泵线程：StartTrace → EnableTraceEx2 → OpenTrace → ProcessTrace
    // ─────────────────────────────────────────────────────────────

    private void Pump()
    {
        Log("[ETW][PUMP] 进入泵线程");
        try
        {
            if (!SetupSession())
            {
                Console.Error.WriteLine("[ETW] 会话初始化失败，订阅未启动");
                return;
            }

            Log("[ETW][PUMP] SetupSession 成功,开始 OpenTraceW");
            var logFile = BuildLogFile();
            Log($"[ETW][PUMP] EVENT_TRACE_LOGFILE: LoggerName='{logFile.LoggerName}' ProcessTraceMode=0x{logFile.ProcessTraceMode:X8} IsKernelTrace={logFile.IsKernelTrace}");
            _consumerHandle = OpenTraceW(ref logFile);
            int openErr = Marshal.GetLastWin32Error();
            if (_consumerHandle == INVALID_PROCESSTRACE_HANDLE)
            {
                Console.Error.WriteLine($"[ETW] OpenTraceW 失败: 0x{openErr:X8} (lastError={openErr})");
                StopTrace();
                return;
            }

            Log($"[ETW] 已订阅 Provider {_providerGuid}，等待 IOCTL 拦截事件… consumerHandle=0x{_consumerHandle:X16}");

            ulong[] handles = { _consumerHandle };
            Log("[ETW][PUMP] 调用 ProcessTrace (阻塞)…");
            uint ptStatus = ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);
            Log($"[ETW][PUMP] ProcessTrace 返回: 0x{ptStatus:X8} lastError={Marshal.GetLastWin32Error()}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ETW] 泵线程异常: {ex.Message}");
            Log($"[ETW][PUMP] 异常: {ex}");
        }
        finally
        {
            Log("[ETW][PUMP] finally: 调用 StopTrace");
            StopTrace();
        }
    }

    private bool SetupSession()
    {
        Log("[ETW][SETUP] 进入 SetupSession");
        int propsSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>();
        int nameBytes = (_sessionName.Length + 1) * 2;
        _propsBuf = new byte[propsSize + nameBytes];
        Log($"[ETW][SETUP] EVENT_TRACE_PROPERTIES 托管大小={propsSize}, sessionName.Length={_sessionName.Length}, nameBytes={nameBytes}, 缓冲区总长={propsSize + nameBytes}");

        var props = new EVENT_TRACE_PROPERTIES
        {
            Wnode =
            {
                // 注意:BufferSize 必须是整个缓冲区(结构体 + 尾部追加的 Session 名)的总大小,
                // 否则 StartTraceW 校验 LoggerNameOffset 落在 BufferSize 内失败 → ERROR_BAD_LENGTH(0x18)。
                BufferSize = (uint)(propsSize + nameBytes),
                ClientContext = 1,   // QPC,与 C++ 端一致
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

        // 写入 Session 名称（紧跟结构体尾部，偏移 = LoggerNameOffset）
        int nameOffset = propsSize;
        for (int i = 0; i < _sessionName.Length; i++)
        {
            short c = (short)_sessionName[i];
            Buffer.BlockCopy(BitConverter.GetBytes(c), 0, _propsBuf, nameOffset + i * 2, 2);
        }

        // 钉住缓冲区，避免 GC 在原生 ETW 调用期间移动它
        _propsHandle = GCHandle.Alloc(_propsBuf, GCHandleType.Pinned);
        IntPtr pProps = _propsHandle.AddrOfPinnedObject();

        // 关键诊断: 把传给 StartTraceW 的所有字段打印出来 (对照 C++ 端)
        Log($"[ETW][SETUP] EVENT_TRACE_PROPERTIES 明细:");
        Log($"         Wnode.BufferSize   = {props.Wnode.BufferSize} (期望值 {propsSize + nameBytes})");
        Log($"         Wnode.Flags        = 0x{props.Wnode.Flags:X8} (WNODE_FLAG_TRACED_GUID=0x{WNODE_FLAG_TRACED_GUID:X8})");
        Log($"         Wnode.HistoricalContext = {props.Wnode.HistoricalContext}");
        Log($"         Wnode.ClientContext= {props.Wnode.ClientContext} (1=QPC)");
        Log($"         Wnode.Guid         = {props.Wnode.Guid}");
        Log($"         BufferSize         = {props.BufferSize}");
        Log($"         MinimumBuffers     = {props.MinimumBuffers}");
        Log($"         MaximumBuffers     = {props.MaximumBuffers}");
        Log($"         MaximumFileSize    = {props.MaximumFileSize}");
        Log($"         FlushTimer         = {props.FlushTimer}");
        Log($"         LogFileMode        = 0x{props.LogFileMode:X8} (REAL_TIME_MODE=0x{EVENT_TRACE_REAL_TIME_MODE:X8})");
        Log($"         LogFileNameOffset  = {props.LogFileNameOffset}");
        Log($"         LoggerNameOffset   = {props.LoggerNameOffset} (propsSize={propsSize})");
        Log($"         pProps             = 0x{pProps:X16}");
        // 校验 LoggerName 落在 BufferSize 内
        bool nameInside = props.LoggerNameOffset + nameBytes <= props.Wnode.BufferSize;
        Log($"[ETW][SETUP] LoggerName 是否落在 BufferSize 内: {nameInside} (LoggerNameOffset {props.LoggerNameOffset} + nameBytes {nameBytes} = {props.LoggerNameOffset + nameBytes} <= BufferSize {props.Wnode.BufferSize})");

        // 先停掉残留同名 Session
        StopTrace();

        // 原始属性缓冲区 hex dump（对照 C++ 端逐字节验证布局）
        DumpPropsBuffer();

        Log($"[ETW][SETUP] 调用 StartTraceW(sessionName='{_sessionName}')…");
        uint status = StartTraceW(out _sessionHandle, _sessionName, pProps);
        int lastErr = Marshal.GetLastWin32Error();
        Log($"[ETW][SETUP] StartTraceW 返回 status=0x{status:X8}, sessionHandle=0x{_sessionHandle:X16}, lastError=0x{lastErr:X8}");
        if (status != ERROR_SUCCESS)
        {
            Console.Error.WriteLine($"[ETW] StartTraceW 失败: 0x{status:X8}");
            return false;
        }

        var enableParams = new ENABLE_TRACE_PARAMETERS
        {
            Version = ENABLE_TRACE_PARAMETERS_VERSION_2,
            EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE,
            SourceId = _providerGuid
        };

        GCHandle hParams = GCHandle.Alloc(enableParams, GCHandleType.Pinned);
        Guid provGuid = _providerGuid;
        Log($"[ETW][SETUP] 调用 EnableTraceEx2(providerGuid={provGuid}, level=0x{TRACE_LEVEL_VERBOSE:X2}, EnableProperty=0x{enableParams.EnableProperty:X8})…");
        try
        {
            status = EnableTraceEx2(_sessionHandle, ref provGuid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                0, 0, 0, hParams.AddrOfPinnedObject());
        }
        finally
        {
            hParams.Free();
        }
        Log($"[ETW][SETUP] EnableTraceEx2 返回 status=0x{status:X8}, lastError=0x{Marshal.GetLastWin32Error():X8}");

        if (status != ERROR_SUCCESS)
        {
            Console.Error.WriteLine($"[ETW] EnableTraceEx2 失败: 0x{status:X8}");
            StopTrace();
            return false;
        }

        Console.WriteLine("[ETW] Provider 已启用（含 EVENT_ENABLE_PROPERTY_STACK_TRACE）");
        return true;
    }

    private EVENT_TRACE_LOGFILE BuildLogFile()
    {
        var logFile = new EVENT_TRACE_LOGFILE
        {
            LoggerName = _sessionName,
            ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            EventRecordCallback = _recordCb,
            BufferCallback = _bufferCb,
            IsKernelTrace = 0
        };
        Log($"[ETW][BUILD] EVENT_TRACE_LOGFILE: LoggerName='{logFile.LoggerName}' ProcessTraceMode=0x{logFile.ProcessTraceMode:X8} IsKernelTrace={logFile.IsKernelTrace}");
        return logFile;
    }

    private void StopTrace()
    {
        if (!_propsHandle.IsAllocated)
        {
            Log("[ETW][STOPTRACE] props 未分配,跳过");
            return;
        }
        Log($"[ETW][STOPTRACE] 调用 ControlTraceW(STOP): sessionHandle=0x{_sessionHandle:X16}, sessionName='{_sessionName}'");
        uint st = ControlTraceW(_sessionHandle, _sessionName, _propsHandle.AddrOfPinnedObject(), EVENT_TRACE_CONTROL_STOP);
        Log($"[ETW][STOPTRACE] ControlTraceW 返回 status=0x{st:X8}, lastError=0x{Marshal.GetLastWin32Error():X8}");
    }

    private void FreeProps()
    {
        if (_propsHandle.IsAllocated)
        {
            _propsHandle.Free();
            _propsBuf = null;
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  事件回调（在 ProcessTrace 线程上执行，必须轻量）
    // ─────────────────────────────────────────────────────────────

    private void EventRecordCallback(ref EVENT_RECORD record)
    {
        try
        {
            Log($"[ETW][CB] EventRecord: ProviderId={record.EventHeader.ProviderId} EventId={record.EventHeader.EventDescriptor.Id} Version={record.EventHeader.EventDescriptor.Version} UserDataLength={record.UserDataLength} ExtendedDataCount={record.ExtendedDataCount}");
            if (record.EventHeader.EventDescriptor.Id != KernelServiceIo.EtwEventIoctlIntercept)
                return;
            if (record.UserData == IntPtr.Zero) return;
            if (record.UserDataLength < Marshal.SizeOf<EtwIoctlEventHeader>()) return;

            var hdr = Marshal.PtrToStructure<EtwIoctlEventHeader>(record.UserData)!;

            // 只处理被附着设备（AttachId != 0 表示 KernelService FiDO 拦截到的通信）
            if (hdr.AttachId == 0) return;

            // 时间戳
            DateTime ts = DateTime.FromFileTime((long)record.EventHeader.TimeStamp);

            // 提取调用栈帧（仅读缓冲区，不做符号化）
            ulong[] frames = CollectStackFrames(record);

            var evt = new IoctlInterceptEvent
            {
                IoControlCode = hdr.IoControlCode,
                RequestorPid = hdr.RequestorPid,
                AttachId = hdr.AttachId,
                MajorFunction = hdr.MajorFunction,
                Method = hdr.Method,
                TimeStamp = ts,
                Frames = frames,
                ExePath = StackResolver.GetProcessImageName(hdr.RequestorPid) ?? ""
            };

            Log($"[ETW][CB] 解析到 IOCTL 拦截: IoControlCode=0x{hdr.IoControlCode:X8} RequestorPid={hdr.RequestorPid} AttachId={hdr.AttachId} 帧数={frames.Length}");
            IoctlIntercept?.Invoke(evt);
        }
        catch (Exception ex)
        {
            Log($"[ETW][CB] 回调异常(已吞掉): {ex.Message}");
            // 回调内异常绝不能逃逸到 ETW 框架
        }
    }

    private uint BufferCallback(ref EVENT_TRACE_LOGFILE logfile)
    {
        lock (_gate)
        {
            uint ret = _stopFlag ? 0u : 1u;
            Log($"[ETW][BCB] BufferCallback stopFlag={_stopFlag} -> {(ret == 0 ? "退出ProcessTrace" : "继续")}");
            return ret;
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  栈帧提取：从 ExtendedData 的 STACK_TRACE64/32 条目读地址数组
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
            IntPtr dataPtr = new IntPtr((long)item.DataPtr);
            bool is64 = item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64;

            // 布局: ULONG64 MatchId + Address[]  （帧数 = (DataSize - 8) / ptrSize）
            int ptrSize = is64 ? 8 : 4;
            int frameCount = (int)(item.DataSize - 8) / ptrSize;
            if (frameCount <= 0) continue;

            var frames = new ulong[Math.Min(frameCount, 64)];
            for (int f = 0; f < frames.Length; f++)
            {
                if (is64)
                    frames[f] = (ulong)Marshal.ReadInt64(dataPtr, 8 + f * 8);
                else
                    frames[f] = (ulong)(uint)Marshal.ReadInt32(dataPtr, 8 + f * 4);
            }
            return frames;
        }
        return Array.Empty<ulong>();
    }

    // ─────────────────────────────────────────────────────────────
    //  权限
    // ─────────────────────────────────────────────────────────────

    private static void EnsurePrivileges()
    {
        Log("[ETW][PRIV] 开始启用权限");
        bool p1 = EnablePrivilege("SeSystemProfilePrivilege"); // 抓栈必需
        bool p2 = EnablePrivilege("SeDebugPrivilege");         // 跨进程读模块必需
        Log($"[ETW][PRIV] SeSystemProfilePrivilege={p1}, SeDebugPrivilege={p2}");
    }

    private static bool EnablePrivilege(string priv)
    {
        Log($"[ETW][PRIV] 启用 {priv}…");
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, out IntPtr token))
        {
            Log($"[ETW][PRIV] {priv}: OpenProcessToken 失败, lastError=0x{Marshal.GetLastWin32Error():X8}");
            return false;
        }
        try
        {
            if (!LookupPrivilegeValueW(null, priv, out LUID luid))
            {
                Log($"[ETW][PRIV] {priv}: LookupPrivilegeValueW 失败, lastError=0x{Marshal.GetLastWin32Error():X8}");
                return false;
            }
            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Attributes = SE_PRIVILEGE_ENABLED
            };
            tp.Luid = luid;
            bool ok = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            Log($"[ETW][PRIV] {priv}: AdjustTokenPrivileges ok={ok}, lastError=0x{err:X8}");
            return ok && err == 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    public void Dispose() => Stop();

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
        public long TimeStamp;          // LARGE_INTEGER
        public Guid ProviderId;
        public EVENT_DESCRIPTOR EventDescriptor;
        public ulong ProcessorTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_RECORD
    {
        public EVENT_HEADER EventHeader;
        public ulong BufferContext;     // ETW_BUFFER_CONTEXT (8 字节)
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;     // EVENT_HEADER_EXTENDED_DATA_ITEM*
        public IntPtr UserData;         // void*
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
        public ulong HistoricalContext;   // 与 Version/Linkage 共用联合体
        public Guid Guid;                 // 16 字节
        public uint ClientContext;        // 原生 WNODE_HEADER 在 Guid 之后、Flags 之前还有一个 ClientContext 字段;
                                          // 漏掉它会导致下方 Flags 偏移错位 4 字节,StartTraceW 读到 Flags=0 → 0x57
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EVENT_TRACE_LOGFILE
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? LogFileName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        public IntPtr CurrentEvent;
        public IntPtr LogfileHeader;
        public BufferCallbackDelegate BufferCallback;
        public uint BufferSize;
        public uint Filled;
        public uint EventsLost;
        public EventRecordCallbackDelegate EventRecordCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    private delegate void EventRecordCallbackDelegate(ref EVENT_RECORD eventRecord);
    private delegate uint BufferCallbackDelegate(ref EVENT_TRACE_LOGFILE logfile);

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

    private const uint ERROR_SUCCESS = 0;
    private const uint WNODE_FLAG_TRACED_GUID = 0x00010000;
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
}

/// <summary>
/// 一次 IOCTL 拦截事件（已从 ETW EVENT_RECORD 解析，仅含轻量数据）。
/// </summary>
public sealed class IoctlInterceptEvent
{
    public uint IoControlCode;
    public ulong RequestorPid;
    public ulong AttachId;
    public uint MajorFunction;
    public uint Method;
    public DateTime TimeStamp;
    public string ExePath = "";
    public ulong[] Frames = Array.Empty<ulong>();
}
