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
    }

    // ─────────────────────────────────────────────────────────────
    //  公共控制
    // ─────────────────────────────────────────────────────────────

    public void Start()
    {
        lock (_gate)
        {
            if (_running) return;
            EnsurePrivileges();
            _stopFlag = false;
            _running = true;
        }

        _pumpThread = new Thread(Pump) { IsBackground = true, Name = "EtwIoctlPump" };
        _pumpThread.Start();
    }

    public void Stop()
    {
        bool wasRunning;
        lock (_gate)
        {
            wasRunning = _running;
            _stopFlag = true;
        }
        if (!wasRunning) return;

        // 主动停止 Session 踢醒可能阻塞的 ProcessTrace
        StopTrace();

        _pumpThread?.Join(TimeSpan.FromSeconds(6));
        FreeProps();
        lock (_gate) _running = false;
    }

    // ─────────────────────────────────────────────────────────────
    //  后台泵线程：StartTrace → EnableTraceEx2 → OpenTrace → ProcessTrace
    // ─────────────────────────────────────────────────────────────

    private void Pump()
    {
        try
        {
            if (!SetupSession())
            {
                Console.Error.WriteLine("[ETW] 会话初始化失败，订阅未启动");
                return;
            }

            var logFile = BuildLogFile();
            _consumerHandle = OpenTraceW(ref logFile);
            if (_consumerHandle == INVALID_PROCESSTRACE_HANDLE)
            {
                Console.Error.WriteLine($"[ETW] OpenTraceW 失败: {Marshal.GetLastWin32Error()}");
                StopTrace();
                return;
            }

            Console.WriteLine($"[ETW] 已订阅 Provider {_providerGuid}，等待 IOCTL 拦截事件…");

            ulong[] handles = { _consumerHandle };
            ProcessTrace(handles, 1, IntPtr.Zero, IntPtr.Zero);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ETW] 泵线程异常: {ex.Message}");
        }
        finally
        {
            StopTrace();
        }
    }

    private bool SetupSession()
    {
        int propsSize = Marshal.SizeOf<EVENT_TRACE_PROPERTIES>();
        int nameBytes = (_sessionName.Length + 1) * 2;
        _propsBuf = new byte[propsSize + nameBytes];

        var props = new EVENT_TRACE_PROPERTIES
        {
            Wnode =
            {
                // 注意:BufferSize 必须是整个缓冲区(结构体 + 尾部追加的 Session 名)的总大小,
                // 否则 StartTraceW 校验 LoggerNameOffset 落在 BufferSize 内失败 → ERROR_BAD_LENGTH(0x18)。
                BufferSize = (uint)(propsSize + nameBytes),
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

        // 先停掉残留同名 Session
        StopTrace();

        uint status = StartTraceW(out _sessionHandle, _sessionName, pProps);
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
        return new EVENT_TRACE_LOGFILE
        {
            LoggerName = _sessionName,
            ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
            EventRecordCallback = _recordCb,
            BufferCallback = _bufferCb,
            IsKernelTrace = 0
        };
    }

    private void StopTrace()
    {
        if (!_propsHandle.IsAllocated) return;
        ControlTraceW(_sessionHandle, _sessionName, _propsHandle.AddrOfPinnedObject(), EVENT_TRACE_CONTROL_STOP);
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

            IoctlIntercept?.Invoke(evt);
        }
        catch
        {
            // 回调内异常绝不能逃逸到 ETW 框架
        }
    }

    private uint BufferCallback(ref EVENT_TRACE_LOGFILE logfile)
    {
        lock (_gate) return _stopFlag ? 0u : 1u;
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
        EnablePrivilege("SeSystemProfilePrivilege"); // 抓栈必需
        EnablePrivilege("SeDebugPrivilege");         // 跨进程读模块必需
    }

    private static bool EnablePrivilege(string priv)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, out IntPtr token))
            return false;
        try
        {
            if (!LookupPrivilegeValueW(null, priv, out LUID luid))
                return false;
            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Attributes = SE_PRIVILEGE_ENABLED
            };
            tp.Luid = luid;
            bool ok = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return ok && Marshal.GetLastWin32Error() == 0;
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
        public ulong HistoricalContext;
        public Guid Guid;     // 与 ClientContext 共用原生联合体（取较大者 16 字节）
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
