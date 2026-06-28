using Microsoft.Win32;

namespace SEWindows.UserService;

/// <summary>
/// 启动前防御:检测并清除 AppInit_DLLs 注入攻击。
///
/// AppInit_DLLs 是 Windows 的全局 DLL 注入机制:任何加载 user32.dll 的进程启动时,
/// 系统会加载 AppInit_DLLs 列出的所有 DLL。这是老牌注入手法,反作弊必须在启动前清除。
///
/// 检查两个注册表值 (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows):
///   - AppInit_DLLs (REG_SZ): 要注入的 DLL 路径列表(空字符串 = 不注入)
///   - LoadAppInit_DLLs (REG_DWORD): 0=禁用,1=启用
///
/// 安全策略:
///   - AppInit_DLLs 必须为空字符串
///   - LoadAppInit_DLLs 必须为 0
///   - 任一不满足,清空 AppInit_DLLs,把 LoadAppInit_DLLs 归零,返回 false
///
/// 注意:同时检查 64 位和 32 位注册表视图(Wow6432Node),32 位程序也会读 32 位视图。
/// </summary>
public static class AppInitCheck
{
    private const string WindowsRegPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

    /// <summary>
    /// 检查 AppInit_DLLs 注入。如果发现注入,自动清除并返回 false。
    /// </summary>
    /// <param name="clearedPaths">输出:被清除的 AppInit_DLLs 内容(用于日志/提示)</param>
    /// <returns>true=安全;false=发现注入并已清除</returns>
    public static bool CheckAndClean(out string clearedPaths)
    {
        clearedPaths = "";

        // 检查 64 位视图 (默认)
        bool infected64 = CheckView(registryView: RegistryView.Registry64, out clearedPaths);
        // 检查 32 位视图 (Wow6432Node)
        bool infected32 = CheckView(registryView: RegistryView.Registry32, out string clearedPaths32);
        if (infected32 && !string.IsNullOrEmpty(clearedPaths32))
            clearedPaths = string.IsNullOrEmpty(clearedPaths) ? clearedPaths32 : $"{clearedPaths} | {clearedPaths32}";

        return !infected64 && !infected32;
    }

    /// <summary>
    /// 检查指定注册表视图 (64/32 位)。如果发现注入,清除并返回 true。
    /// </summary>
    private static bool CheckView(RegistryView registryView, out string clearedPaths)
    {
        clearedPaths = "";

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView);
            using var key = baseKey.OpenSubKey(WindowsRegPath, writable: true);

            if (key == null)
            {
                // 键不存在,无注入
                return false;
            }

            // 1. 检查 AppInit_DLLs (REG_SZ)
            string appInitDlls = key.GetValue("AppInit_DLLs", "") as string ?? "";
            // 2. 检查 LoadAppInit_DLLs (REG_DWORD)
            int loadAppInit = key.GetValue("LoadAppInit_DLLs", 0) as int? ?? 0;

            bool appInitInfected = !string.IsNullOrWhiteSpace(appInitDlls);
            bool loadFlagInfected = loadAppInit != 0;

            if (!appInitInfected && !loadFlagInfected)
            {
                // 安全
                return false;
            }

            // 发现注入,记录原始值
            clearedPaths = appInitDlls;
            Console.Error.WriteLine($"[AppInit] INJECTION DETECTED (view={registryView}):");
            Console.Error.WriteLine($"[AppInit]   AppInit_DLLs = \"{appInitDlls}\"");
            Console.Error.WriteLine($"[AppInit]   LoadAppInit_DLLs = {loadAppInit}");

            // 清除:AppInit_DLLs 置空,LoadAppInit_DLLs 归零
            key.SetValue("AppInit_DLLs", "", RegistryValueKind.String);
            key.SetValue("LoadAppInit_DLLs", 0, RegistryValueKind.DWord);

            Console.Error.WriteLine($"[AppInit] CLEARED: AppInit_DLLs=\"\", LoadAppInit_DLLs=0");
            return true;
        }
        catch (Exception ex)
        {
            // 权限不足或注册表异常:按"发现注入"处理(保守)
            Console.Error.WriteLine($"[AppInit] CheckView({registryView}) exception: {ex.Message}");
            clearedPaths = $"(检查失败: {ex.Message})";
            return true;
        }
    }
}
