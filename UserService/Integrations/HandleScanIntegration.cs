using System.Text.Json;
using UserService.Native;

namespace Hyperion.UserService;

/// <summary>
/// 句柄扫描集成: 把 DriverAttachSelector 的 ScanHandlesForPid 能力接入 UserService。
///
/// 功能:
///   1. 对指定 PID 调用 FetchScanHandles, 获取该进程持有的全部句柄
///   2. 投递完整 CbnHandleEntry 列表到服务端 kernel-comms API (kind="handle-scan")
///   3. 含全维度: OwnerPid/OwnerName/HandleValue/GrantedAccess/AccessStr/TargetPid/TypeName/HighRisk
///
/// 触发时机:
///   - 由 UserService 主程序对高危目标进程 (如游戏进程) 调用一次
///   - 或在 Security 快照检测到 HighRiskHandle 时按需触发
///
/// 数据上报: 整体作为一个 JSON 投递, 服务端按 TypeName + HighRisk 聚合展示。
/// </summary>
internal sealed class HandleScanIntegration
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;

    public HandleScanIntegration(NativeHost host, ServerDataClient? server)
    {
        _host = host;
        _server = server;
    }

    /// <summary>
    /// 对指定 PID 执行句柄扫描并上报。
    /// </summary>
    public void ScanOnce(uint targetPid, string? processName = null)
    {
        if (targetPid == 0)
        {
            Console.Error.WriteLine("[HandleScan] targetPid=0, 跳过");
            return;
        }

        Console.Error.WriteLine($"[HandleScan] 扫描 PID={targetPid} 的句柄...");

        using var result = _host.Service.FetchScanHandles(targetPid);
        if (!result.Success)
        {
            Console.Error.WriteLine($"[HandleScan] 扫描失败: {result.ErrorMessage}");
            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "handle-scan",
                Level = "ERR",
                Source = "HandleScan",
                Title = $"句柄扫描失败: PID={targetPid}",
                DataJson = JsonSerializer.Serialize(new { error = result.ErrorMessage, pid = targetPid }),
                RequestorPid = targetPid,
            });
            return;
        }

        var entries = result.Entries;
        if (entries.Length == 0)
        {
            Console.Error.WriteLine($"[HandleScan] PID={targetPid} 无句柄");
            return;
        }

        int highRiskCount = entries.Count(e => e.HighRisk != 0);
        Console.Error.WriteLine(
            $"[HandleScan] PID={targetPid}: {entries.Length} 句柄, {highRiskCount} 高危");

        // 按 TypeName 分组统计 (Category C: 之前 UI 拿不到聚合)
        var byType = entries
            .GroupBy(e => e.TypeName)
            .Select(g => new
            {
                typeName = g.Key,
                count = g.Count(),
                highRisk = g.Count(e => e.HighRisk != 0),
            })
            .OrderByDescending(x => x.highRisk)
            .ThenByDescending(x => x.count)
            .ToArray();

        // 序列化全维度句柄列表 (含 GrantedAccess/AccessStr 用于判断跨进程权限)
        var objs = entries.Select(e => new
        {
            ownerPid = e.OwnerPid,
            ownerName = e.OwnerName,
            handleValue = e.HandleValue,
            grantedAccess = e.GrantedAccess,
            accessStr = e.AccessStr,
            targetPid = e.TargetPid,
            typeName = e.TypeName,
            highRisk = e.HighRisk,
        }).ToArray();

        var dataObj = new
        {
            targetPid = targetPid,
            processName = processName,
            totalCount = entries.Length,
            highRiskCount = highRiskCount,
            byType = byType,
            handles = objs,
        };

        _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
        {
            Kind = "handle-scan",
            Level = highRiskCount > 0 ? "HIGH" : "INFO",
            Source = "HandleScan",
            Title = $"句柄扫描: PID={targetPid} ({entries.Length} 句柄, {highRiskCount} 高危)",
            DataJson = JsonSerializer.Serialize(dataObj),
            RequestorPid = targetPid,
            HighRiskCount = highRiskCount,
        });
    }
}
