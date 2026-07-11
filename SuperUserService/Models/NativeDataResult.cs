// NativeDataResult.cs — 托管包装类, 封装从 C++ 返回的扁平化缓冲区
//
// 设计要点:
//   - NativeDataResult<T> 持有非托管的 IntPtr 缓冲区, 实现 IDisposable 释放
//   - 通过 Marshal.PtrToStructure 解析 Header + 条目数组
//   - 调用方使用 using 块确保缓冲区被 CombNative_FreeBuffer 释放
//   - 提供强类型 Entries 属性, 避免调用方直接处理指针

using System.Runtime.InteropServices;

namespace SuperUserService.Models;

/// <summary>
/// 原生数据导出结果的托管包装器。
/// 持有 C++ malloc 分配的缓冲区, 按需解析为强类型条目,
/// 释放时调用 CombNative_FreeBuffer 归还内存。
/// </summary>
internal sealed class NativeDataResult<T> : IDisposable where T : struct
{
    private IntPtr _buffer;
    private readonly CbnResultHeader _header;
    private T[]? _entries;
    private bool _disposed;

    /// <summary>从原生缓冲区构造。buffer 必须由 CombNative_Get* 返回。</summary>
    public NativeDataResult(IntPtr buffer)
    {
        _buffer = buffer;
        _header = Marshal.PtrToStructure<CbnResultHeader>(_buffer);
    }

    /// <summary>结果头 (含错误码、命令 ID、条目数等)。</summary>
    public ref readonly CbnResultHeader Header => ref _header;

    /// <summary>是否成功 (ErrorCode == 0)。</summary>
    public bool Success => _header.ErrorCode == 0;

    /// <summary>错误消息 (失败时有效)。</summary>
    public string ErrorMessage => _header.ErrorMessage ?? string.Empty;

    /// <summary>条目数量 (成功时有效)。</summary>
    public int Count => (int)_header.EntryCount;

    /// <summary>
    /// 获取所有条目的托管数组 (懒加载, 解析后缓存)。
    /// 若失败则返回空数组。
    /// </summary>
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
            _entries = new T[count];
            IntPtr entryPtr = _buffer + Marshal.SizeOf<CbnResultHeader>();
            int entrySize = (int)_header.EntrySize;
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
    public T SingleEntry
    {
        get
        {
            if (!Success || _header.EntryCount == 0)
                throw new InvalidOperationException(
                    $"无法获取条目: ErrorCode={_header.ErrorCode}, Message={ErrorMessage}");
            return Entries[0];
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
internal static class NativeBufferHelper
{
    [DllImport("CombinationNative.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void CombNative_FreeBuffer(IntPtr buffer);
}
