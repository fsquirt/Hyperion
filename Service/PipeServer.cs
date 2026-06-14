using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SEWindows.Service;

/// <summary>
/// 命名管道服务器 — 等待 osu! 连接，接收验证请求，返回验证结果
/// </summary>
public sealed class PipeServer : IDisposable
{
    public const string PIPE_NAME = "sewindows-anticheat";

    public class VerifyRequest
    {
        [JsonPropertyName("type")] public string Type { get; set; } = "";
        [JsonPropertyName("pid")] public uint Pid { get; set; }
        [JsonPropertyName("exe_path")] public string ExePath { get; set; } = "";
    }

    public class VerifyResponse
    {
        [JsonPropertyName("type")] public string Type { get; set; } = "verify_result";
        [JsonPropertyName("success")] public bool Success { get; set; }
        [JsonPropertyName("test_mode")] public bool TestMode { get; set; }
        [JsonPropertyName("reason")] public string Reason { get; set; } = "";
    }

    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    /// <summary>
    /// 当收到 osu! 验证请求时触发
    /// 参数: (pid, exePath)
    /// 返回: (success, testMode, reason)
    /// </summary>
    public event Func<uint, string, Task<(bool success, bool testMode, string reason)>>? OnVerifyRequest;

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listenTask = Task.Run(() => ListenLoop(_cts.Token));
        Console.Error.WriteLine($"[Pipe] Server started on \\\\.\\pipe\\{PIPE_NAME}");
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _listenTask?.Wait(TimeSpan.FromSeconds(5));
        _cts?.Dispose();
    }

    private async Task ListenLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var pipeStream = new NamedPipeServerStream(
                    PIPE_NAME,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                Console.Error.WriteLine("[Pipe] Waiting for connection...");
                await pipeStream.WaitForConnectionAsync(ct);

                Console.Error.WriteLine("[Pipe] Client connected");
                await HandleClient(pipeStream, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Pipe] Error: {ex.Message}");
                await Task.Delay(1000, ct);
            }
        }
    }

    private async Task HandleClient(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            Console.Error.WriteLine($"[Pipe] HandleClient start, IsConnected={pipe.IsConnected}, CanRead={pipe.CanRead}");

            // 直接用原始字节读写，避免 StreamReader/StreamWriter 的缓冲问题
            var buffer = new byte[4096];
            Console.Error.WriteLine("[Pipe] Reading raw bytes...");
            int bytesRead = await pipe.ReadAsync(buffer, 0, buffer.Length, ct);
            Console.Error.WriteLine($"[Pipe] ReadAsync returned {bytesRead} bytes");

            if (bytesRead == 0)
            {
                Console.Error.WriteLine("[Pipe] Zero bytes read");
                return;
            }

            var line = Encoding.UTF8.GetString(buffer, 0, bytesRead).TrimEnd('\r', '\n');
            Console.Error.WriteLine($"[Pipe] Received: {line}");

            var request = JsonSerializer.Deserialize<VerifyRequest>(line);
            if (request == null || request.Type != "verify_request")
            {
                await WriteResponse(pipe, new VerifyResponse
                {
                    Success = false,
                    Reason = "invalid request"
                });
                return;
            }

            Console.Error.WriteLine($"[Pipe] Verify request: PID={request.Pid}, Exe={request.ExePath}");

            // Invoke the verification handler
            if (OnVerifyRequest == null)
            {
                await WriteResponse(pipe, new VerifyResponse
                {
                    Success = false,
                    Reason = "no handler registered"
                });
                return;
            }

            var (success, testMode, reason) = await OnVerifyRequest.Invoke(request.Pid, request.ExePath);

            await WriteResponse(pipe, new VerifyResponse
            {
                Success = success,
                TestMode = testMode,
                Reason = reason
            });

            Console.Error.WriteLine($"[Pipe] Response sent: success={success}, test={testMode}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[Pipe] Client handler error: {ex.Message}");
        }
    }

    private static async Task WriteResponse(NamedPipeServerStream pipe, VerifyResponse response)
    {
        var json = JsonSerializer.Serialize(response) + "\n";
        var bytes = Encoding.UTF8.GetBytes(json);
        await pipe.WriteAsync(bytes, 0, bytes.Length);
        await pipe.FlushAsync();
    }
}
