using System.Text.Json.Serialization;

namespace Hyperion.Server.Models;

public static class SplashImageModes
{
    public const string Specified = "specified";
    public const string Random = "random";
}

public sealed class SplashImageItem
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("originalFileName")]
    public string OriginalFileName { get; set; } = "";

    [JsonPropertyName("storedFileName")]
    public string StoredFileName { get; set; } = "";

    [JsonPropertyName("fileSizeBytes")]
    public long FileSizeBytes { get; set; }

    [JsonPropertyName("contentType")]
    public string ContentType { get; set; } = "image/jpeg";

    [JsonPropertyName("uploadedAt")]
    public DateTime UploadedAt { get; set; } = DateTime.Now;
}

public sealed class ClientSplashConfig
{
    [JsonPropertyName("mode")]
    public string Mode { get; set; } = SplashImageModes.Specified;

    [JsonPropertyName("selectedImageId")]
    public string? SelectedImageId { get; set; }

    [JsonPropertyName("images")]
    public List<SplashImageItem> Images { get; set; } = new();
}
