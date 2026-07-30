using System.Text.Json;
using Hyperion.Tracker;

namespace Hyperion.UserService.Modules.Upload;

/// <summary>
/// 取证数据上报（与 Server 端解耦，仅约定端点 /api/forensics/upload）。
/// 将 dump/*.dmp/*.exe/*.dll/*.sys 二进制与 IOCTL 统计 JSON 通过 HTTP 多部分表单上传；
/// 上传失败写入脱机缓冲目录，后台定时重试补传，避免取证数据丢失。
/// </summary>
public sealed class HttpForensicUploader : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _endpoint;
    private readonly string _offlineDir;
    private readonly string _uploadRoot;
    private readonly object _queueLock = new();
    private readonly List<string> _pending = new();
    private readonly System.Threading.Timer _retryTimer;
    private bool _disposed;

    public HttpForensicUploader(string endpoint, string uploadRoot)
    {
        _endpoint = endpoint;
        _uploadRoot = uploadRoot;
        _offlineDir = Path.Combine(uploadRoot, "offline_upload");
        Directory.CreateDirectory(_offlineDir);
        // 走纯托管 TLS(BouncyCastle),不碰系统 SChannel/LSASS,在 PPL 进程里也能正常 HTTPS。
        // 上传目标与服务端同域(hyperion.cloudyou.top),复用 CertPinning 的公钥(SPKI)固定即可。
        _http = CertPinning.CreatePinnedClient(timeout: TimeSpan.FromSeconds(30));
        // 启动即扫描脱机缓冲，恢复上次未传完的队列
        foreach (var f in Directory.GetFiles(_offlineDir))
            lock (_queueLock) _pending.Add(f);
        _retryTimer = new System.Threading.Timer(_ => _ = FlushOfflineAsync(), null,
            TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// 上报一组取证产物：二进制文件列表 + 一段元数据 JSON 文本。
    /// 立即尝试上传，失败则落盘到脱机缓冲目录稍后重试。
    /// </summary>
    public async Task UploadAsync(IEnumerable<string> files, string metadataJson, string? tag = null)
    {
        string? metaPath = null;
        try
        {
            // 元数据也作为 multipart 字段（不落盘先，直接附带）
            if (await TryUploadAsync(files, metadataJson))
                return;

            // 失败：把每个文件 + 元数据复制到脱机缓冲目录
            string batch = tag ?? DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            string batchDir = Path.Combine(_offlineDir, batch);
            Directory.CreateDirectory(batchDir);
            foreach (var f in files)
            {
                if (File.Exists(f))
                    File.Copy(f, Path.Combine(batchDir, Path.GetFileName(f)), true);
            }
            metaPath = Path.Combine(batchDir, "metadata.json");
            await File.WriteAllTextAsync(metaPath, metadataJson);
            lock (_queueLock) _pending.Add(batchDir);
            Console.WriteLine($"[UP] 上传失败，已缓冲到脱机目录: {batchDir}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[UP] UploadAsync 异常: {ex.Message}");
        }
    }

    private async Task<bool> TryUploadAsync(IEnumerable<string> files, string metadataJson)
    {
        try
        {
            using var content = new MultipartFormDataContent("hyperion_forensics_boundary");
            content.Add(new StringContent(metadataJson, System.Text.Encoding.UTF8, "application/json"), "metadata");
            foreach (var f in files)
            {
                if (!File.Exists(f)) continue;
                var bytes = await File.ReadAllBytesAsync(f);
                var fileContent = new ByteArrayContent(bytes);
                fileContent.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                content.Add(fileContent, "file", Path.GetFileName(f));
            }

            using var resp = await _http.PostAsync(_endpoint, content);
            if (resp.IsSuccessStatusCode || resp.StatusCode == System.Net.HttpStatusCode.Accepted)
            {
                Console.WriteLine($"[UP] 上报成功 → {_endpoint}");
                return true;
            }
            Console.Error.WriteLine($"[UP] 上报被拒绝: {(int)resp.StatusCode}");
            return false;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[UP] 上报异常（将脱机缓冲）: {ex.Message}");
            return false;
        }
    }

    /// <summary>重试脱机缓冲目录中的批次。</summary>
    private async Task FlushOfflineAsync()
    {
        if (_disposed) return;
        List<string> batches;
        lock (_queueLock)
        {
            batches = new List<string>(_pending);
        }
        foreach (var batchDir in batches)
        {
            try
            {
                if (!Directory.Exists(batchDir)) { RemovePending(batchDir); continue; }
                var files = Directory.GetFiles(batchDir)
                    .Where(f => !f.EndsWith("metadata.json", StringComparison.OrdinalIgnoreCase)).ToList();
                string metaPath = Path.Combine(batchDir, "metadata.json");
                string meta = File.Exists(metaPath) ? await File.ReadAllTextAsync(metaPath) : "{}";

                if (await TryUploadAsync(files, meta))
                {
                    Directory.Delete(batchDir, true);
                    RemovePending(batchDir);
                    Console.WriteLine($"[UP] 脱机批次补传成功: {batchDir}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[UP] 脱机补传异常: {ex.Message}");
            }
        }
    }

    private void RemovePending(string batchDir)
    {
        lock (_queueLock) _pending.Remove(batchDir);
    }

    public void Dispose()
    {
        _disposed = true;
        _retryTimer.Dispose();
        _http.Dispose();
    }
}
