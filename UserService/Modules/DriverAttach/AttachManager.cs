using System.Runtime.InteropServices;

namespace Hyperion.UserService.Modules.DriverAttach;

/// <summary>
/// 附着管理，对齐 KernelComms.cpp 的 Attach/Detach/Query。
/// 维护一份托管附着表供 Heuristic / ProcTree 查询"哪些驱动已附着"。
/// </summary>
public sealed class AttachManager
{
    private readonly object _lock = new();
    private readonly Dictionary<uint, KernelServiceIo.AttachEntry> _table = new();

    public IReadOnlyDictionary<uint, KernelServiceIo.AttachEntry> Attachments
    {
        get { lock (_lock) return new Dictionary<uint, KernelServiceIo.AttachEntry>(_table); }
    }

    public bool IsAttached(string targetPath)
    {
        lock (_lock)
            return _table.Values.Any(e => e.TargetPath.Equals(targetPath, StringComparison.OrdinalIgnoreCase));
    }

    public bool Attach(IntPtr hDevice, string devicePath,
        out uint attachId, out string error)
    {
        attachId = 0;
        error = "";

        var req = new KernelServiceIo.AttachDeviceRequest
        {
            DevicePath = devicePath.Length >= 260 ? devicePath.Substring(0, 259) : devicePath
        };
        byte[] reqBytes = KernelServiceIo.StructToBytes(req);
        var resp = new KernelServiceIo.AttachDeviceResponse();
        byte[] outBuf = new byte[Marshal.SizeOf<KernelServiceIo.AttachDeviceResponse>()];

        if (!KernelServiceIo.IoControl(hDevice, KernelServiceIo.IOCTL_ATTACH_DEVICE,
                reqBytes, outBuf, out uint bytesReturned))
        {
            error = $"DeviceIoControl 失败: {Marshal.GetLastWin32Error()}";
            return false;
        }
        resp = KernelServiceIo.ReadStruct<KernelServiceIo.AttachDeviceResponse>(outBuf, 0);
        if (resp.Status != 0)
        {
            // 精细化映射 NTSTATUS → 可读错误
            uint st = unchecked((uint)resp.Status);
            error = st switch
            {
                0xC0000237 => "已附着过",
                0xC0000034 => "设备对象不存在",
                0xC0000035 => "设备名冲突",
                0xC000003B => "设备路径语法错误",
                _ => $"内核返回 NTSTATUS=0x{st:X8}"
            };
            return false;
        }

        attachId = resp.AttachId;
        lock (_lock)
        {
            _table[attachId] = new KernelServiceIo.AttachEntry
            {
                AttachId = resp.AttachId,
                FilterDeviceAddr = resp.FilterDeviceAddr,
                LowerDeviceAddr = resp.LowerDeviceAddr,
                StackSize = resp.NewStackSize,
                TargetPath = devicePath
            };
        }
        return true;
    }

    public bool Detach(IntPtr hDevice, uint attachId)
    {
        var req = new KernelServiceIo.DetachDeviceRequest { AttachId = attachId };
        byte[] reqBytes = KernelServiceIo.StructToBytes(req);
        byte[] outBuf = new byte[Marshal.SizeOf<KernelServiceIo.DetachDeviceResponse>()];
        if (!KernelServiceIo.IoControl(hDevice, KernelServiceIo.IOCTL_DETACH_DEVICE,
                reqBytes, outBuf, out uint _))
            return false;
        var resp = KernelServiceIo.ReadStruct<KernelServiceIo.DetachDeviceResponse>(outBuf, 0);
        if (resp.Status != 0) return false;
        lock (_lock) _table.Remove(attachId);
        return true;
    }

    /// <summary>全量刷新附着表，对齐 QueryAttachments，含缓冲不足自动扩容。</summary>
    public void Refresh(IntPtr hDevice)
    {
        int headerSize = Marshal.SizeOf<KernelServiceIo.QueryAttachmentsResponse>();
        int entrySize = Marshal.SizeOf<KernelServiceIo.AttachEntry>();
        byte[] outBuf = new byte[headerSize + 16 * entrySize];

        for (int retry = 0; retry < 3; retry++)
        {
            if (KernelServiceIo.IoControl(hDevice, KernelServiceIo.IOCTL_QUERY_ATTACHMENTS,
                    null, outBuf, out uint bytesReturned))
            {
                if (bytesReturned < headerSize) return;
                var resp = KernelServiceIo.ReadStruct<KernelServiceIo.QueryAttachmentsResponse>(outBuf, 0);
                int need = headerSize + (int)resp.Count * entrySize;
                if (bytesReturned < need) return;
                var table = new Dictionary<uint, KernelServiceIo.AttachEntry>();
                int off = headerSize;
                for (int i = 0; i < resp.Count; i++)
                {
                    var e = KernelServiceIo.ReadStruct<KernelServiceIo.AttachEntry>(outBuf, off);
                    table[e.AttachId] = e;
                    off += entrySize;
                }
                lock (_lock) { _table.Clear(); foreach (var kv in table) _table[kv.Key] = kv.Value; }
                return;
            }
            int err = Marshal.GetLastWin32Error();
            if (err == 122 || err == 234)
            {
                if (bytesReturned >= headerSize)
                {
                    var resp = KernelServiceIo.ReadStruct<KernelServiceIo.QueryAttachmentsResponse>(outBuf, 0);
                    if (resp.NeededOutputBytes > outBuf.Length && resp.NeededOutputBytes < 1024 * 1024)
                    { outBuf = new byte[resp.NeededOutputBytes]; continue; }
                }
                if (outBuf.Length * 2 > 1024 * 1024) return;
                outBuf = new byte[outBuf.Length * 2];
                continue;
            }
            return;
        }
    }

    public void Clear() { lock (_lock) _table.Clear(); }
}
