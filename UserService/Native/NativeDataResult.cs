// NativeDataResult.cs — 托管包装类, 封装从 C++ 返回的扁平化缓冲区
//
// 设计要点:
//   - NativeDataResult<T> 持有非托管的 IntPtr 缓冲区, 实现 IDisposable 释放
//   - 通过 Marshal.PtrToStructure 解析 Header + 条目数组
//   - 调用方使用 using 块确保缓冲区被 CombNative_FreeBuffer 释放
//   - 提供强类型 Entries 属性, 避免调用方直接处理指针

using System.Runtime.InteropServices;

namespace UserService.Native;

/// <summary>
/// 原生数据导出结果的托管包装器。
/// 持有 C++ malloc 分配的缓冲区, 按需解析为强类型条目,
/// 释放时调用 CombNative_FreeBuffer 归还内存。
/// </summary>
public sealed class NativeDataResult<T> : IDisposable where T : struct
{
    private IntPtr _buffer;
    private readonly CbnResultHeader _header;
    private T[]? _entries;
    private bool _disposed;
    // S2: Entries 校验失败标志。_header 是 readonly 无法改 ErrorCode,
    //     用此标志让 Success 属性反映校验失败, 调用方可通过 Success 判断。
    private bool _validationFailed;

    /// <summary>从原生缓冲区构造。buffer 必须由 CombNative_Get* 返回。</summary>
    /// <remarks>
    /// C++ 端契约 (HyperionNativeData.h): CombNative_Get* 返回 nullptr 表示失败。
    /// 本构造函数对 nullptr 做防御: 不再对 IntPtr.Zero 调 PtrToStructure, 而是构造一个
    /// ErrorCode = -1 的失败结果, 让上层通过 Success/ErrorMessage 优雅处理。
    /// </remarks>
    public NativeDataResult(IntPtr buffer)
    {
        if (buffer == IntPtr.Zero)
        {
            // C++ 返回 nullptr = 失败 (malloc 失败/异常)。
            // 构造一个显式失败的头, 不调 PtrToStructure 避免访问 0 地址 AV。
            _buffer = IntPtr.Zero;
            _header = new CbnResultHeader
            {
                ErrorCode = -1,
                CommandId = 0,
                EntryCount = 0,
                EntrySize = 0,
                TotalSize = 0,
                ErrorMessage = "C++ 返回 nullptr (malloc 失败或异常)",
            };
            return;
        }

        _buffer = buffer;
        _header = Marshal.PtrToStructure<CbnResultHeader>(_buffer);
    }

    /// <summary>结果头 (含错误码、命令 ID、条目数等)。</summary>
    public ref readonly CbnResultHeader Header => ref _header;

    /// <summary>是否成功 (ErrorCode == 0 且缓冲区非空且校验未失败)。</summary>
    public bool Success => _buffer != IntPtr.Zero && _header.ErrorCode == 0 && !_validationFailed;

    /// <summary>错误消息 (失败时有效)。</summary>
    public string ErrorMessage => _header.ErrorMessage ?? string.Empty;

    /// <summary>条目数量 (成功时有效)。</summary>
    public int Count => (int)_header.EntryCount;

    /// <summary>
    /// 获取所有条目的托管数组 (懒加载, 解析后缓存)。
    /// 若失败则返回空数组。
    /// </summary>
    /// <remarks>
    /// 安全校验:
    ///   1. EntrySize 必须 >= sizeof(T), 否则 C++ 端结构体版本与 C# 不一致, 拒绝解析
    ///   2. sizeof(Header) + count * entrySize 必须 <= TotalSize, 防越界读
    ///   3. 上述任一校验失败则设置 _validationFailed=true 并返回空数组
    ///      (不抛异常, 让上层通过 Success 判断 — Success 会因 _validationFailed 返回 false)
    /// </remarks>
    public T[] Entries
    {
        get
        {
            if (_entries != null) return _entries;
            if (!Success || _header.EntryCount == 0 || _header.EntrySize == 0)
            {
                _entries = Array.Empty<T>();
                return _entries;
            }

            int count = (int)_header.EntryCount;
            int entrySize = (int)_header.EntrySize;
            int headerSize = Marshal.SizeOf<CbnResultHeader>();
            int managedEntrySize = Marshal.SizeOf<T>();

            // 校验 1: C++ entrySize 必须 >= C# 结构体大小, 否则版本不一致
            if (entrySize < managedEntrySize)
            {
                Console.Error.WriteLine(
                    $"[NativeDataResult] EntrySize({entrySize}) < sizeof(T)({managedEntrySize}), " +
                    $"C++/C# 结构体版本不一致, 拒绝解析 (count={count})");
                _validationFailed = true;  // S2: 让 Success 返回 false
                _entries = Array.Empty<T>();
                return _entries;
            }

            // 校验 2: 缓冲区总大小必须容纳 header + count * entrySize, 防越界读
            // 用 long 计算避免 count * entrySize 溢出
            long requiredBytes = (long)headerSize + (long)count * entrySize;
            if (requiredBytes > _header.TotalSize)
            {
                Console.Error.WriteLine(
                    $"[NativeDataResult] 缓冲区越界: 需要 {requiredBytes} 字节, " +
                    $"TotalSize={_header.TotalSize}, count={count}, entrySize={entrySize}");
                _validationFailed = true;  // S2: 让 Success 返回 false
                _entries = Array.Empty<T>();
                return _entries;
            }

            _entries = new T[count];
            IntPtr entryPtr = _buffer + headerSize;
            for (int i = 0; i < count; i++)
            {
                _entries[i] = Marshal.PtrToStructure<T>(entryPtr + i * entrySize);
            }
            return _entries;
        }
    }

    /// <summary>
    /// 获取单个结果条目 (用于 IAT / Comms 等只返回单条数据的命令)。
    /// 若失败或无条目则抛出 InvalidOperationException。
    /// </summary>
    /// <remarks>
    /// 若 EntryCount > 1, 说明 C++ 端本应只返回单条却返回了多条 (协议异常),
    /// 记 warning 后仍取第一条, 不抛异常以免阻塞主流程。
    /// S2-v3: 必须先调用 Entries 触发校验 (可能设置 _validationFailed),
    ///        再用校验后的 Success 和 entries.Length 判断。
    ///        否则 _validationFailed 懒加载: SingleEntry 先检查 Success (此时 _validationFailed=false,
    ///        Success=true), 再 return Entries[0] 触发校验失败返回空数组 → IndexOutOfRangeException。
    /// </remarks>
    public T SingleEntry
    {
        get
        {
            // S2-v3: 先触发 Entries 校验, 让 _validationFailed 在判断前就设置好
            var entries = Entries;
            if (!Success || entries.Length == 0)
                throw new InvalidOperationException(
                    $"无法获取条目: ErrorCode={_header.ErrorCode}, Message={ErrorMessage}");
            if (_header.EntryCount > 1)
            {
                Console.Error.WriteLine(
                    $"[NativeDataResult] SingleEntry: EntryCount={_header.EntryCount} > 1, " +
                    $"C++ 端本应返回单条却返回多条, 取第一条 (CommandId={_header.CommandId})");
            }
            return entries[0];
        }
    }

    public void Dispose()
    {
        if (!_disposed && _buffer != IntPtr.Zero)
        {
            NativeBufferHelper.CombNative_FreeBuffer(_buffer);
            _buffer = IntPtr.Zero;
            _disposed = true;
        }
    }
}

/// <summary>
/// 静态 P/Invoke 辅助类 (DllImport 不能放在泛型类中)。
/// </summary>
public static class NativeBufferHelper
{
    [DllImport("HyperionNative.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void CombNative_FreeBuffer(IntPtr buffer);
}
