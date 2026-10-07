using System.Text.Json;
using Hyperion.Server.Models;

namespace Hyperion.Server.Services;

/// <summary>
/// 客户端背景图管理服务。
/// 管理背景图的上传、指定图片或随机返回等模式切换、删除以及为客户端提供图片二进制流。
/// </summary>
public sealed class ClientSplashService
{
    private readonly ILogger<ClientSplashService> _logger;
    private readonly object _lock = new();

    private static readonly string StorageDir =
        Path.Combine(AppContext.BaseDirectory, "Data", "splash_images");

    private static readonly string SettingsPath =
        Path.Combine(AppContext.BaseDirectory, "Data", "splash_settings.json");

    private ClientSplashConfig _config = new();

    public ClientSplashService(ILogger<ClientSplashService> logger)
    {
        _logger = logger;
        Directory.CreateDirectory(StorageDir);
        LoadConfig();
    }

    public ClientSplashConfig GetConfig()
    {
        lock (_lock)
        {
            return new ClientSplashConfig
            {
                Mode = _config.Mode,
                SelectedImageId = _config.SelectedImageId,
                Images = _config.Images.Select(img => new SplashImageItem
                {
                    Id = img.Id,
                    OriginalFileName = img.OriginalFileName,
                    StoredFileName = img.StoredFileName,
                    FileSizeBytes = img.FileSizeBytes,
                    ContentType = img.ContentType,
                    UploadedAt = img.UploadedAt
                }).ToList()
            };
        }
    }

    public bool UpdateConfig(string mode, string? selectedImageId)
    {
        lock (_lock)
        {
            if (mode != SplashImageModes.Specified && mode != SplashImageModes.Random)
            {
                mode = SplashImageModes.Specified;
            }

            _config.Mode = mode;

            if (!string.IsNullOrWhiteSpace(selectedImageId))
            {
                if (_config.Images.Any(x => x.Id == selectedImageId))
                {
                    _config.SelectedImageId = selectedImageId;
                }
            }

            SaveConfigUnsafe();
            _logger.LogInformation("[Splash] 配置更新: Mode={Mode}, SelectedId={SelectedId}", mode, _config.SelectedImageId);
            return true;
        }
    }

    public async Task<(bool Success, string? Error, SplashImageItem? Item)> UploadImageAsync(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return (false, "上传文件为空", null);

        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        var allowedExts = new[] { ".jpg", ".jpeg", ".png", ".webp", ".bmp" };
        if (!allowedExts.Contains(ext))
            return (false, "只支持 JPG / PNG / WebP / BMP 格式的图片", null);

        var id = Guid.NewGuid().ToString("N");
        var storedFileName = $"{id}{ext}";
        var targetPath = Path.Combine(StorageDir, storedFileName);

        try
        {
            await using (var fs = new FileStream(targetPath, FileMode.Create, FileAccess.Write))
            {
                await file.CopyToAsync(fs);
            }

            var contentType = ext switch
            {
                ".png" => "image/png",
                ".webp" => "image/webp",
                ".bmp" => "image/bmp",
                _ => "image/jpeg"
            };

            var item = new SplashImageItem
            {
                Id = id,
                OriginalFileName = Path.GetFileName(file.FileName),
                StoredFileName = storedFileName,
                FileSizeBytes = file.Length,
                ContentType = contentType,
                UploadedAt = DateTime.Now
            };

            lock (_lock)
            {
                _config.Images.Add(item);
                if (string.IsNullOrEmpty(_config.SelectedImageId))
                {
                    _config.SelectedImageId = item.Id;
                }
                SaveConfigUnsafe();
            }

            _logger.LogInformation("[Splash] 上传新背景图: {OriginalName} -> {StoredName}", item.OriginalFileName, storedFileName);
            return (true, null, item);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Splash] 上传背景图写入磁盘失败");
            return (false, $"保存文件失败: {ex.Message}", null);
        }
    }

    public bool DeleteImage(string id)
    {
        lock (_lock)
        {
            var item = _config.Images.FirstOrDefault(x => x.Id == id);
            if (item == null) return false;

            var filePath = Path.Combine(StorageDir, item.StoredFileName);
            if (File.Exists(filePath))
            {
                try { File.Delete(filePath); } catch { }
            }

            _config.Images.Remove(item);

            if (_config.SelectedImageId == id)
            {
                _config.SelectedImageId = _config.Images.FirstOrDefault()?.Id;
            }

            SaveConfigUnsafe();
            _logger.LogInformation("[Splash] 已删除背景图: {Id}", id);
            return true;
        }
    }

    /// <summary>
    /// 获取当前应向客户端返回的背景图。
    /// 根据当前配置按指定或随机模式挑选图片，并返回文件流与 ContentType。
    /// </summary>
    public (Stream? Stream, string ContentType, string? ImageId) GetActiveImage()
    {
        lock (_lock)
        {
            if (_config.Images.Count == 0)
                return (null, "image/jpeg", null);

            SplashImageItem? target = null;
            if (_config.Mode == SplashImageModes.Random)
            {
                var idx = Random.Shared.Next(0, _config.Images.Count);
                target = _config.Images[idx];
            }
            else
            {
                target = _config.Images.FirstOrDefault(x => x.Id == _config.SelectedImageId)
                         ?? _config.Images.First();
            }

            var path = Path.Combine(StorageDir, target.StoredFileName);
            if (!File.Exists(path))
                return (null, target.ContentType, target.Id);

            try
            {
                var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                return (fs, target.ContentType, target.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[Splash] 读取背景图文件失败: {Path}", path);
                return (null, target.ContentType, target.Id);
            }
        }
    }

    public (Stream? Stream, string ContentType) GetImageById(string id)
    {
        lock (_lock)
        {
            var item = _config.Images.FirstOrDefault(x => x.Id == id);
            if (item == null) return (null, "image/jpeg");

            var path = Path.Combine(StorageDir, item.StoredFileName);
            if (!File.Exists(path)) return (null, item.ContentType);

            try
            {
                var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                return (fs, item.ContentType);
            }
            catch
            {
                return (null, item.ContentType);
            }
        }
    }

    private void LoadConfig()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                var loaded = JsonSerializer.Deserialize<ClientSplashConfig>(json);
                if (loaded != null)
                {
                    _config = loaded;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Splash] 加载配置失败，使用默认配置");
            _config = new ClientSplashConfig();
        }
    }

    private void SaveConfigUnsafe()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            var json = JsonSerializer.Serialize(_config, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Splash] 保存配置失败");
        }
    }
}
