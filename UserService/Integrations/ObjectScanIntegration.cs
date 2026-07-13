using System.Text.Json;
using UserService.Native;

namespace Hyperion.UserService;

/// <summary>
/// 对象命名空间扫描集成: 把 DriverAttachSelector 的 ScanObjectNamespaces 能力接入 UserService。
///
/// 功能:
///   1. 扫描关键对象目录: \GLOBAL??, \Device, \BaseNamedObjects, \Driver
///   2. 投递完整 CbnNtDirEntry 列表到服务端 kernel-comms API (kind="object-scan")
///   3. 含全维度: Name/TypeName/LinkTarget (Category B: 之前 UserService 从不调用此 API)
///
/// 触发时机: 由 UserService 主程序在驱动扫描完成后调用一次。
/// 数据上报: 整体作为一个 JSON 投递, 服务端按 TypeName 聚合展示。
/// </summary>
internal sealed class ObjectScanIntegration
{
    private readonly NativeHost _host;
    private readonly ServerDataClient? _server;

    // 默认扫描的关键对象目录 (覆盖 BYOVD / 符号链接 / 设备命名空间)
    private static readonly string[] DefaultDirectories =
    {
        @"\GLOBAL??",       // 全局符号链接 (盘符, 设备接口)
        @"\Device",         // 设备对象
        @"\BaseNamedObjects", // 命名对象 (互斥/事件/节)
        @"\Driver",         // 驱动对象列表
    };

    public ObjectScanIntegration(NativeHost host, ServerDataClient? server)
    {
        _host = host;
        _server = server;
    }

    /// <summary>
    /// 执行对象命名空间扫描并上报。
    /// 默认扫描 4 个关键目录, 可传入自定义目录列表覆盖。
    /// </summary>
    public void ScanOnce(IEnumerable<string>? customDirectories = null)
    {
        var dirs = (customDirectories ?? DefaultDirectories).ToList();
        if (dirs.Count == 0)
        {
            Console.Error.WriteLine("[ObjScan] 无扫描目录, 跳过");
            return;
        }

        Console.Error.WriteLine($"[ObjScan] 扫描对象命名空间: {string.Join(", ", dirs)}");

        var parameters = new ScanObjectsParameters(dirs);
        using var result = _host.Service.FetchScanObjects(parameters);
        if (!result.Success)
        {
            Console.Error.WriteLine($"[ObjScan] 扫描失败: {result.ErrorMessage}");
            _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
            {
                Kind = "object-scan",
                Level = "ERR",
                Source = "ObjectScan",
                Title = "对象命名空间扫描失败",
                DataJson = JsonSerializer.Serialize(new { error = result.ErrorMessage, dirs }),
            });
            return;
        }

        var entries = result.Entries;
        if (entries.Length == 0)
        {
            Console.Error.WriteLine("[ObjScan] 扫描无结果");
            return;
        }

        Console.Error.WriteLine($"[ObjScan] 扫描完成: {entries.Length} 个对象");

        // 按 TypeName 分组统计 (Category C: 之前 UI 拿不到聚合)
        var byType = entries
            .GroupBy(e => e.TypeName)
            .Select(g => new { typeName = g.Key, count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToArray();

        // 序列化全维度对象列表 (含 LinkTarget 用于揭示符号链接指向)
        var objs = entries.Select(e => new
        {
            name = e.Name,
            typeName = e.TypeName,
            linkTarget = e.LinkTarget,
        }).ToArray();

        var dataObj = new
        {
            directories = dirs,
            totalCount = entries.Length,
            byType = byType,
            entries = objs,
        };

        _ = _server?.PostKernelCommAsync(new ServerDataClient.KernelCommPayload
        {
            Kind = "object-scan",
            Level = "INFO",
            Source = "ObjectScan",
            Title = $"对象命名空间扫描: {entries.Length} 个对象, {byType.Length} 种类型",
            DataJson = JsonSerializer.Serialize(dataObj),
        });
    }
}
