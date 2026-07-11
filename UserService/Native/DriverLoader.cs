using System.Runtime.InteropServices;

namespace Hyperion.UserService;

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
    private static extern bool ControlService(IntPtr hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_START = 0x0010;
    private const uint SERVICE_STOP = 0x0020;
    private const uint SERVICE_ALL_ACCESS = 0xF01FF;
    private const uint SERVICE_CONTROL_STOP = 0x00000001;

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
    /// 停止 kmdf 驱动服务 (ControlService SERVICE_CONTROL_STOP)
    /// 服务本身不删除,下次 LoadDriver 可重新启动
    /// </summary>
    public static void UnloadDriver()
    {
        Console.Error.WriteLine($"[Driver] Stopping service '{SERVICE_NAME}'...");

        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero)
        {
            Console.Error.WriteLine($"[Driver] OpenSCManager failed: {Marshal.GetLastWin32Error()}");
            return;
        }

        try
        {
            IntPtr svc = OpenService(scm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero)
            {
                Console.Error.WriteLine($"[Driver] OpenService('{SERVICE_NAME}') for stop failed: {Marshal.GetLastWin32Error()}");
                return;
            }

            try
            {
                var status = new SERVICE_STATUS();
                if (ControlService(svc, SERVICE_CONTROL_STOP, ref status))
                {
                    Console.Error.WriteLine("[Driver] Driver stopped successfully");
                }
                else
                {
                    var err = Marshal.GetLastWin32Error();
                    // 1062 = ERROR_SERVICE_NOT_ACTIVE,服务未运行,视为成功
                    if (err == 1062)
                    {
                        Console.Error.WriteLine("[Driver] Service was not running");
                    }
                    else
                    {
                        Console.Error.WriteLine($"[Driver] ControlService(STOP) failed: {err}");
                    }
                }
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
}
