using System.Runtime.InteropServices;

namespace SEWindows.UserService;

/// <summary>
/// 内核驱动加载器 — 通过 SCM 启动已存在的 kmdf 服务
/// </summary>
public static class DriverLoader
{
    private const string SERVICE_NAME = "kmdf";

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_START = 0x0010;
    private const uint SERVICE_ALL_ACCESS = 0xF01FF;

    /// <summary>
    /// 启动已存在的 kmdf 驱动服务
    /// </summary>
    public static bool LoadDriver(string driverPath)
    {
        Console.Error.WriteLine($"[Driver] Attempting to start service '{SERVICE_NAME}'...");

        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            Console.Error.WriteLine($"[Driver] OpenSCManager failed: {Marshal.GetLastWin32Error()}");
            return false;
        }

        try
        {
            IntPtr svc = OpenService(scm, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero)
            {
                Console.Error.WriteLine($"[Driver] OpenService('{SERVICE_NAME}') failed: {Marshal.GetLastWin32Error()}");
                Console.Error.WriteLine("[Driver] 请先手动创建驱动服务: sc create kmdf type= kernel binPath= <path>");
                return false;
            }

            try
            {
                if (StartService(svc, 0, IntPtr.Zero))
                {
                    Console.Error.WriteLine("[Driver] Driver started successfully");
                    return true;
                }

                var err = Marshal.GetLastWin32Error();
                if (err == 1056) // ERROR_SERVICE_ALREADY_RUNNING
                {
                    Console.Error.WriteLine("[Driver] Driver already running");
                    return true;
                }

                Console.Error.WriteLine($"[Driver] StartService failed: {err}");
                return false;
            }
            finally
            {
                CloseServiceHandle(svc);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    /// <summary>
    /// 不做任何操作（驱动由用户手动管理）
    /// </summary>
    public static void UnloadDriver()
    {
        // 不自动卸载，由用户手动管理: sc stop kmdf
    }
}
