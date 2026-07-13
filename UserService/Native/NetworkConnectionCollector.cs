using System.Net;
using System.Runtime.InteropServices;

namespace Hyperion.UserService;

/// <summary>
/// 网络连接采集器: 通过 GetExtendedTcpTable / GetExtendedUdpTable 采集目标 PID 的 TCP/UDP 连接。
/// 用于定向进程深扫的网络维度数据。
/// </summary>
internal static class NetworkConnectionCollector
{
    // ══════════════════════════════════════════════════════════════════
    //  P/Invoke 声明
    // ══════════════════════════════════════════════════════════════════

    [DllImport("Iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref uint dwSize, bool bOrder,
        int ulAf, TCP_TABLE_CLASS TableClass, uint Reserved);

    [DllImport("Iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref uint dwSize, bool bOrder,
        int ulAf, UDP_TABLE_CLASS TableClass, uint Reserved);

    // ══════════════════════════════════════════════════════════════════
    //  枚举
    // ══════════════════════════════════════════════════════════════════

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL = 5,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL,
    }

    private enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,  // = 1
        UDP_TABLE_OWNER_MODULE,
    }

    // ══════════════════════════════════════════════════════════════════
    //  常量
    // ══════════════════════════════════════════════════════════════════

    private const int AF_INET = 2;       // IPv4
    private const int AF_INET6 = 23;     // IPv6 (本任务不采集, 保留)
    private const uint ERROR_SUCCESS = 0;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    // ══════════════════════════════════════════════════════════════════
    //  数据结构
    // ══════════════════════════════════════════════════════════════════

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        public MIB_TCPROW_OWNER_PID table;  // 第一个元素, 后续通过偏移读取
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        public MIB_UDPROW_OWNER_PID table;
    }

    // ══════════════════════════════════════════════════════════════════
    //  公开数据类
    // ══════════════════════════════════════════════════════════════════

    /// <summary>采集到的网络连接记录</summary>
    public sealed class NetworkConnection
    {
        public string Protocol { get; set; } = "";     // "TCP" 或 "UDP"
        public string LocalAddr { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddr { get; set; } = "";
        public int RemotePort { get; set; }
        public string State { get; set; } = "";        // TCP 状态字符串, UDP 为空
        public uint OwnerPid { get; set; }
    }

    // ══════════════════════════════════════════════════════════════════
    //  公开方法
    // ══════════════════════════════════════════════════════════════════

    /// <summary>
    /// 采集指定 PID 的全部 TCP/UDP 网络连接。
    /// </summary>
    public static List<NetworkConnection> CollectForPid(uint pid)
    {
        var result = new List<NetworkConnection>();
        CollectTcpForPid(pid, result);
        CollectUdpForPid(pid, result);
        return result;
    }

    // ══════════════════════════════════════════════════════════════════
    //  TCP 采集
    //  流程:
    //    1. 第一次调用 GetExtendedTcpTable (pTcpTable=NULL, dwSize=0) 拿所需缓冲区大小
    //    2. 分配缓冲区, 第二次调用拿实际数据
    //    3. 读取 dwNumEntries, 逐行解析 MIB_TCPROW_OWNER_PID
    //    4. 过滤 dwOwningPid == pid, 转换字段后加入结果
    // ══════════════════════════════════════════════════════════════════

    private static void CollectTcpForPid(uint pid, List<NetworkConnection> result)
    {
        uint size = 0;
        // 1. 第一次调用: 查询所需缓冲区大小
        uint ret = GetExtendedTcpTable(
            IntPtr.Zero, ref size, false,
            AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

        if (ret == ERROR_SUCCESS)
        {
            // 无 TCP 连接 (size 可能为 0), 无需继续
            return;
        }

        if (ret != ERROR_INSUFFICIENT_BUFFER)
        {
            Console.Error.WriteLine($"[NetworkCollector] GetExtendedTcpTable(查询大小) 失败: ret={ret}");
            return;
        }

        if (size == 0) return;

        // 2. 分配缓冲区, 第二次调用读取数据
        IntPtr buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            ret = GetExtendedTcpTable(
                buffer, ref size, false,
                AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            if (ret != ERROR_SUCCESS)
            {
                Console.Error.WriteLine($"[NetworkCollector] GetExtendedTcpTable(读取数据) 失败: ret={ret}");
                return;
            }

            // 3. 读取 dwNumEntries (表头前 4 字节)
            uint numEntries = (uint)Marshal.ReadInt32(buffer);

            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            int tableOffset = (int)Marshal.OffsetOf<MIB_TCPTABLE_OWNER_PID>(nameof(MIB_TCPTABLE_OWNER_PID.table));

            // 4. 逐行解析, 通过偏移定位每一行
            for (int i = 0; i < numEntries; i++)
            {
                IntPtr rowPtr = IntPtr.Add(buffer, tableOffset + i * rowSize);
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                if (row.dwOwningPid != pid) continue;

                result.Add(new NetworkConnection
                {
                    Protocol = "TCP",
                    LocalAddr = AddrToString(row.dwLocalAddr),
                    LocalPort = PortFromNetOrder(row.dwLocalPort),
                    RemoteAddr = AddrToString(row.dwRemoteAddr),
                    RemotePort = PortFromNetOrder(row.dwRemotePort),
                    State = TcpStateToString(row.dwState),
                    OwnerPid = row.dwOwningPid,
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  UDP 采集
    //  流程同 TCP, 但 MIB_UDPROW_OWNER_PID 只有 3 个字段 (无 remoteAddr/state)
    // ══════════════════════════════════════════════════════════════════

    private static void CollectUdpForPid(uint pid, List<NetworkConnection> result)
    {
        uint size = 0;
        uint ret = GetExtendedUdpTable(
            IntPtr.Zero, ref size, false,
            AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

        if (ret == ERROR_SUCCESS)
        {
            return;
        }

        if (ret != ERROR_INSUFFICIENT_BUFFER)
        {
            Console.Error.WriteLine($"[NetworkCollector] GetExtendedUdpTable(查询大小) 失败: ret={ret}");
            return;
        }

        if (size == 0) return;

        IntPtr buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            ret = GetExtendedUdpTable(
                buffer, ref size, false,
                AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

            if (ret != ERROR_SUCCESS)
            {
                Console.Error.WriteLine($"[NetworkCollector] GetExtendedUdpTable(读取数据) 失败: ret={ret}");
                return;
            }

            uint numEntries = (uint)Marshal.ReadInt32(buffer);

            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            int tableOffset = (int)Marshal.OffsetOf<MIB_UDPTABLE_OWNER_PID>(nameof(MIB_UDPTABLE_OWNER_PID.table));

            for (int i = 0; i < numEntries; i++)
            {
                IntPtr rowPtr = IntPtr.Add(buffer, tableOffset + i * rowSize);
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);

                if (row.dwOwningPid != pid) continue;

                result.Add(new NetworkConnection
                {
                    Protocol = "UDP",
                    LocalAddr = AddrToString(row.dwLocalAddr),
                    LocalPort = PortFromNetOrder(row.dwLocalPort),
                    RemoteAddr = "",
                    RemotePort = 0,
                    State = "",
                    OwnerPid = row.dwOwningPid,
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    //  辅助: IP / Port / State 转换
    // ══════════════════════════════════════════════════════════════════

    /// <summary>
    /// 将 dwLocalAddr/dwRemoteAddr (网络字节序 uint) 转换为点分十进制字符串。
    /// </summary>
    private static string AddrToString(uint addr)
    {
        // dwLocalAddr/dwRemoteAddr 以网络字节序 (big-endian) 存储。
        // 网络字节序的 4 字节 [b0, b1, b2, b3] 在小端机器上被读为 uint,
        // BitConverter.GetBytes(uint) 在小端机器上返回 [LSB..MSB],
        // 两次反转恰好还原为网络字节序 [b0, b1, b2, b3]。
        byte[] bytes = BitConverter.GetBytes(addr);
        return new IPAddress(new byte[] { bytes[0], bytes[1], bytes[2], bytes[3] }).ToString();
    }

    /// <summary>
    /// 将 dwLocalPort/dwRemotePort (网络字节序, 存于低 16 位) 转换为主机序端口号。
    /// </summary>
    private static int PortFromNetOrder(uint port)
    {
        // 端口号以网络字节序存储在 32 位字段的低 16 位, 高 16 位可能含未初始化数据。
        // 交换低 16 位的两个字节即得到主机序端口号。
        return (int)(((port >> 8) & 0xFF) | ((port & 0xFF) << 8));
    }

    /// <summary>
    /// 将 MIB_TCP_STATE 数值转换为状态字符串。
    /// 参考: https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ne-tcpmib-mib_tcp_state
    /// </summary>
    private static string TcpStateToString(uint state)
    {
        return state switch
        {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => $"UNKNOWN({state})",
        };
    }
}
