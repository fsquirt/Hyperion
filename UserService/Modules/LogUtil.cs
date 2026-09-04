using System.Text;

namespace Hyperion.UserService.Modules;

/// <summary>
/// 异常详情格式化：递归展开 InnerException 链 + 堆栈，便于在控制台/日志中定位根因。
/// </summary>
internal static class LogUtil
{
    public static string Detail(Exception? ex)
    {
        if (ex == null) return "(null exception)";

        var sb = new StringBuilder();
        int depth = 0;
        for (var e = ex; e != null; e = e.InnerException)
        {
            if (depth == 0)
                sb.Append($"{e.GetType().FullName}: {e.Message}");
            else
                sb.Append($"  ---> {e.GetType().FullName}: {e.Message}");
            depth++;
        }

        // 如有 HResult，有助于定位原生/Win32 错误
        if (ex is System.Runtime.InteropServices.ExternalException ee)
            sb.Append($" [HRESULT=0x{ee.HResult:X8}]");

        sb.AppendLine();

        // 完整堆栈：取最外层，已含各层展开
        if (!string.IsNullOrEmpty(ex.StackTrace))
            sb.AppendLine(ex.StackTrace);

        return sb.ToString().TrimEnd();
    }
}
