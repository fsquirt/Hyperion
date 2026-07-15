using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Client;
using OpenAI;
using OpenAI.Chat;
using System.ClientModel;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// ── 1. 加载配置 ──────────────────────────────────────────────────
var config = LoadConfig();
Directory.CreateDirectory(config.WorkDir);
Console.WriteLine($"[配置] 工作目录: {config.WorkDir}");
Console.WriteLine($"[配置] 服务器: {config.ServerUrl}");

using var httpClient = new HttpClient();
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// ── 2. 连接服务器 ────────────────────────────────────────────────
var connectResp = await ConnectAsync(httpClient, config);
if (connectResp == null || string.IsNullOrEmpty(connectResp.AgentId))
{
    Console.WriteLine("[错误] 无法连接服务器，退出。");
    return;
}
var agentId = connectResp.AgentId;
Console.WriteLine($"[连接] 与服务器建立会话，Agent ID: {agentId}");

if (connectResp.LlmApis == null || connectResp.LlmApis.Count == 0)
{
    Console.WriteLine("[错误] 服务器未返回 LLM API 配置，退出。");
    return;
}
var llmApi = connectResp.LlmApis[0];
Console.WriteLine($"[连接] 使用 LLM API: {llmApi.Name} ({llmApi.ModelName})");

var openaiOptions = new OpenAIClientOptions { Endpoint = new Uri(llmApi.BaseUrl) };
var openaiClient = new OpenAIClient(new ApiKeyCredential(llmApi.ApiKey), openaiOptions);
var chatClient = openaiClient.GetChatClient(llmApi.ModelName);

// ── 3. 心跳后台线程 ──────────────────────────────────────────────
var statusHolder = new StatusHolder { Status = "空闲" };
_ = Task.Run(() => HeartbeatLoopAsync(httpClient, config, agentId, statusHolder, cts.Token));

// ── 4. 主循环 ────────────────────────────────────────────────────
var analyzableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    ".exe", ".dll", ".sys", ".pyd", ".ocx"
};

try
{
    while (!cts.Token.IsCancellationRequested)
    {
        var task = await GetNextTaskAsync(httpClient, config, agentId, cts.Token);
        if (task == null || !task.HasTask)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(config.NoTaskWaitSeconds), cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            continue;
        }

        Console.WriteLine($"[任务] 领取到任务 - 会话ID: {task.SessionId}, 机器名: {task.MachineName}");
        Console.WriteLine($"[任务] 文件总数: {task.Files.Count}");
        Console.WriteLine("[任务] 文件列表:");
        int fileIdx = 0;
        foreach (var f in task.Files)
        {
            fileIdx++;
            var ext = Path.GetExtension(f.Name);
            var tag = string.Equals(ext, ".dmp", StringComparison.OrdinalIgnoreCase)
                ? "[跳过 - WinDbg]"
                : analyzableExtensions.Contains(ext)
                    ? "[可分析]"
                    : "[跳过]";
            Console.WriteLine($"  {fileIdx}. {f.Name} ({FormatSize(f.Size)}) {tag}");
        }

        // 下载所有文件到工作目录
        statusHolder.Status = "下载文件";
        foreach (var f in task.Files)
        {
            try
            {
                await DownloadFileAsync(httpClient, config, f, cts.Token);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[下载] {f.Name} 失败: {ex.Message}");
            }
        }

        // 过滤可分析文件
        var toAnalyze = task.Files
            .Where(f => analyzableExtensions.Contains(Path.GetExtension(f.Name)))
            .ToList();

        int n = toAnalyze.Count;
        for (int i = 0; i < n && !cts.Token.IsCancellationRequested; i++)
        {
            var file = toAnalyze[i];
            var filePath = Path.Combine(config.WorkDir, file.Name);
            try
            {
                await AnalyzeFileAsync(httpClient, config, chatClient, agentId,
                    task.SessionId, file.Name, filePath, i + 1, n, statusHolder, cts.Token);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[错误] 分析 {file.Name} 时异常: {ex.Message}");
            }
        }

        statusHolder.Status = "空闲";
    }
}
catch (OperationCanceledException)
{
    Console.WriteLine("\n[退出] 收到取消信号，正在退出...");
}
finally
{
    cts.Cancel();
    statusHolder.Status = "离线";
}

Console.WriteLine("再见！");

// ══════════════════════════════════════════════════════════════════
// 本地函数
// ══════════════════════════════════════════════════════════════════

static AgentConfig LoadConfig()
{
    var config = new AgentConfig();

    var searchPaths = new[]
    {
        Path.Combine(AppContext.BaseDirectory, "appsettings.json"),
        Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json"),
    };

    string? foundPath = null;
    foreach (var p in searchPaths)
    {
        if (File.Exists(p)) { foundPath = p; break; }
    }

    if (foundPath != null)
    {
        try
        {
            var json = File.ReadAllText(foundPath);
            var loaded = JsonSerializer.Deserialize<AgentConfig>(json);
            if (loaded != null) config = loaded;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[配置] 读取配置失败，使用默认值: {ex.Message}");
        }
    }
    else
    {
        // 配置文件不存在，创建示例文件
        try
        {
            var samplePath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");
            File.WriteAllText(samplePath, JsonSerializer.Serialize(new AgentConfig(),
                new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"[配置] 未找到配置文件，已创建示例: {samplePath}");
        }
        catch { }
    }

    // 环境变量覆盖
    if (Environment.GetEnvironmentVariable("ServerUrl") is { Length: > 0 } envServerUrl)
        config.ServerUrl = envServerUrl;
    if (Environment.GetEnvironmentVariable("CredentialToken") is { } envToken)
        config.CredentialToken = envToken;
    if (Environment.GetEnvironmentVariable("IdaPath") is { Length: > 0 } envIdaPath)
        config.IdaPath = envIdaPath;
    if (Environment.GetEnvironmentVariable("WinDbgPath") is { } envWinDbgPath)
        config.WinDbgPath = envWinDbgPath;
    if (Environment.GetEnvironmentVariable("WorkDir") is { Length: > 0 } envWorkDir)
        config.WorkDir = envWorkDir;
    if (Environment.GetEnvironmentVariable("IdaMcpEndpoint") is { Length: > 0 } envMcpEp)
        config.IdaMcpEndpoint = envMcpEp;
    if (int.TryParse(Environment.GetEnvironmentVariable("IdaAnalysisWaitSeconds"), out var iaws))
        config.IdaAnalysisWaitSeconds = iaws;
    if (int.TryParse(Environment.GetEnvironmentVariable("HeartbeatIntervalSeconds"), out var his))
        config.HeartbeatIntervalSeconds = his;
    if (int.TryParse(Environment.GetEnvironmentVariable("NoTaskWaitSeconds"), out var ntws))
        config.NoTaskWaitSeconds = ntws;

    return config;
}

static async Task<ConnectResponse?> ConnectAsync(HttpClient http, AgentConfig cfg)
{
    try
    {
        var request = new HttpRequestMessage(HttpMethod.Post, $"{cfg.ServerUrl}/api/reverse-agent/connect");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cfg.CredentialToken);
        request.Content = new StringContent("{}", Encoding.UTF8, "application/json");
        var resp = await http.SendAsync(request);
        if (!resp.IsSuccessStatusCode)
        {
            Console.WriteLine($"[错误] 连接失败: {(int)resp.StatusCode} {resp.ReasonPhrase}");
            return null;
        }
        var json = await resp.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<ConnectResponse>(json);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[错误] 连接异常: {ex.Message}");
        return null;
    }
}

static async Task HeartbeatLoopAsync(HttpClient http, AgentConfig cfg, string agentId,
    StatusHolder status, CancellationToken ct)
{
    while (!ct.IsCancellationRequested)
    {
        try
        {
            var body = JsonSerializer.Serialize(new
            {
                agent_id = agentId,
                current_status = status.Status
            });
            var request = new HttpRequestMessage(HttpMethod.Post, $"{cfg.ServerUrl}/api/reverse-agent/heartbeat");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cfg.CredentialToken);
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            await http.SendAsync(request, ct);
        }
        catch { }

        try
        {
            await Task.Delay(TimeSpan.FromSeconds(cfg.HeartbeatIntervalSeconds), ct);
        }
        catch
        {
            break;
        }
    }
}

static async Task<NextTaskResponse?> GetNextTaskAsync(HttpClient http, AgentConfig cfg,
    string agentId, CancellationToken ct)
{
    try
    {
        var url = $"{cfg.ServerUrl}/api/reverse-agent/next-task?agent_id={Uri.EscapeDataString(agentId)}";
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cfg.CredentialToken);
        var resp = await http.SendAsync(request, ct);
        if (!resp.IsSuccessStatusCode) return null;
        var json = await resp.Content.ReadAsStringAsync(ct);
        return JsonSerializer.Deserialize<NextTaskResponse>(json);
    }
    catch
    {
        return null;
    }
}

static async Task DownloadFileAsync(HttpClient http, AgentConfig cfg, TaskFile file, CancellationToken ct)
{
    var url = file.Url;
    if (string.IsNullOrEmpty(url))
    {
        // 如果没有 url 字段，尝试用 session_id + file_name 构造下载地址
        return;
    }
    if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
    {
        url = $"{cfg.ServerUrl.TrimEnd('/')}/{url.TrimStart('/')}";
    }

    var destPath = Path.Combine(cfg.WorkDir, file.Name);
    var request = new HttpRequestMessage(HttpMethod.Get, url);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", cfg.CredentialToken);
    using var resp = await http.SendAsync(request, ct);
    resp.EnsureSuccessStatusCode();
    using var fs = File.Create(destPath);
    await (await resp.Content.ReadAsStreamAsync(ct)).CopyToAsync(fs, ct);
}

static async Task AnalyzeFileAsync(HttpClient http, AgentConfig cfg, ChatClient chat,
    string agentId, string sessionId, string fileName, string filePath,
    int fileIndex, int fileCount, StatusHolder status, CancellationToken ct)
{
    Console.WriteLine($"[分析] 文件 {fileIndex}/{fileCount}: {fileName}");
    status.Status = $"分析 {fileName}";

    Process? idaProcess = null;
    Process? mcpProcess = null;
    McpClient? mcpClient = null;

    try
    {
        // ── 启动 IDA ───────────────────────────────────────────────
        Console.WriteLine($"[IDA] 启动 IDA 分析: {filePath}");
        try
        {
            idaProcess = Process.Start(new ProcessStartInfo
            {
                FileName = cfg.IdaPath,
                Arguments = $"-A -c -Opdb:fallback \"{filePath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[IDA] 启动失败: {ex.Message}");
        }

        // ── 启动 ida-pro-mcp ──────────────────────────────────────
        try
        {
            var mcpPsi = new ProcessStartInfo
            {
                FileName = "ida-pro-mcp",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            mcpProcess = Process.Start(mcpPsi);
            if (mcpProcess != null)
            {
                var readyTcs = new TaskCompletionSource<bool>();
                _ = Task.Run(() =>
                {
                    try
                    {
                        while (!mcpProcess.HasExited)
                        {
                            var line = mcpProcess.StandardOutput.ReadLine();
                            if (line == null) break;
                            if (line.Contains("Auto-connected") || line.Contains("MCP"))
                                readyTcs.TrySetResult(true);
                        }
                    }
                    catch { }
                    readyTcs.TrySetResult(false);
                });

                var winner = await Task.WhenAny(readyTcs.Task, Task.Delay(30000, ct));
                if (winner == readyTcs.Task && readyTcs.Task.Result)
                {
                    Console.WriteLine("[MCP] ida-pro-mcp 已启动");
                }
                else
                {
                    Console.WriteLine("[MCP] 等待 ida-pro-mcp 就绪超时，继续尝试...");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MCP] 启动 ida-pro-mcp 失败: {ex.Message}");
        }

        // ── 等待 IDA 自动分析完成 ─────────────────────────────────
        var remaining = cfg.IdaAnalysisWaitSeconds;
        while (remaining > 0 && !ct.IsCancellationRequested)
        {
            Console.WriteLine($"[IDA] 等待自动分析完成... {remaining}秒");
            var wait = Math.Min(10, remaining);
            try
            {
                await Task.Delay(wait * 1000, ct);
            }
            catch
            {
                break;
            }
            remaining -= wait;
        }

        // ── 生成 MCP 配置文件 ─────────────────────────────────────
        var mcpConfig = new
        {
            mcpServers = new Dictionary<string, object>
            {
                ["ida-pro-mcp"] = new
                {
                    type = "http",
                    url = cfg.IdaMcpEndpoint,
                    disabled = false
                }
            }
        };
        var mcpConfigPath = Path.Combine(cfg.WorkDir, "mcp_config.json");
        File.WriteAllText(mcpConfigPath,
            JsonSerializer.Serialize(mcpConfig, new JsonSerializerOptions { WriteIndented = true }));

        // ── 连接 MCP 服务器 ───────────────────────────────────────
        IList<McpClientTool> mcpTools = new List<McpClientTool>();
        try
        {
            var transport = new HttpClientTransport(new HttpClientTransportOptions
            {
                Endpoint = new Uri(cfg.IdaMcpEndpoint),
                TransportMode = HttpTransportMode.StreamableHttp,
                ConnectionTimeout = TimeSpan.FromSeconds(30),
            });
            mcpClient = await McpClient.CreateAsync(transport);
            mcpTools = await mcpClient.ListToolsAsync();
            Console.WriteLine($"[MCP] 已加载 {mcpTools.Count} 个 MCP 工具");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[MCP] 连接失败: {ex.Message}");
        }

        // ── 创建函数工具 ──────────────────────────────────────────
        var submitReportTool = AIFunctionFactory.Create(
            async (string markdown, string result) =>
            {
                try
                {
                    using var form = new MultipartFormDataContent();
                    form.Add(new StringContent(sessionId), "session_id");
                    form.Add(new StringContent(agentId), "agent_id");
                    form.Add(new StringContent(
                        $"报告_{sessionId}_{Path.GetFileNameWithoutExtension(fileName)}.md"),
                        "file_name");
                    form.Add(new StringContent(result), "result");
                    form.Add(new StringContent(markdown), "content");

                    var request = new HttpRequestMessage(HttpMethod.Post,
                        $"{cfg.ServerUrl}/api/reverse-agent/report");
                    request.Headers.Authorization =
                        new AuthenticationHeaderValue("Bearer", cfg.CredentialToken);
                    request.Content = form;
                    var resp = await http.SendAsync(request, ct);
                    resp.EnsureSuccessStatusCode();
                    Console.WriteLine("[报告] 报告已提交");
                    return "报告已提交成功";
                }
                catch (Exception ex)
                {
                    return $"报告提交失败: {ex.Message}";
                }
            },
            name: "submit_report",
            description: "提交逆向分析报告。在完成所有文件分析后调用此工具。markdown: Markdown格式的报告正文。result: 研判结果，只能是 normal/cheat/suspicious。");

        var executePythonTool = AIFunctionFactory.Create(
            (string code) =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = "python",
                        Arguments = "-",
                        RedirectStandardInput = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    };
                    using var p = Process.Start(psi);
                    if (p == null) return "无法启动 python";
                    p.StandardInput.Write(code);
                    p.StandardInput.Close();
                    var stdoutTask = p.StandardOutput.ReadToEndAsync();
                    var stderrTask = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(30000))
                    {
                        try { p.Kill(true); } catch { }
                        return "[执行超时]";
                    }
                    Task.WaitAll(stdoutTask, stderrTask);
                    return stdoutTask.Result + stderrTask.Result;
                }
                catch (Exception ex)
                {
                    return $"执行失败: {ex.Message}";
                }
            },
            name: "execute_python",
            description: "执行 Python 代码用于偏移值计算等辅助分析。code: Python 代码字符串。返回脚本的 stdout 输出。");

        // ── 创建 AIAgent ──────────────────────────────────────────
        var instructions = $"你是逆向分析助手。当前正在分析会话 {sessionId} 的文件 {fileName}（第 {fileIndex}/{fileCount} 个文件）。请通过 MCP 工具分析此文件的逆向特征，查找可能的作弊行为。分析完成后调用 submit_report 提交报告。回答用中文。请注意你一次最多只能并发调用2个工具。";

        AIAgent agent = chat.AsAIAgent(
            name: "ReverseAgent",
            description: "逆向分析助手",
            instructions: instructions,
            tools: [.. mcpTools, submitReportTool, executePythonTool],
            clientFactory: inner => new ChatClientBuilder(inner)
                .UseFunctionInvocation(configure: fic =>
                {
                    fic.IncludeDetailedErrors = true;
                    fic.MaximumConsecutiveErrorsPerRequest = 5;
                })
                .Build());

        // ── 运行 AI 分析 ──────────────────────────────────────────
        Console.WriteLine("[AI] 开始分析...");
        status.Status = $"分析 {fileName} (AI)";
        AgentSession agentSession = await agent.CreateSessionAsync();
        var prompt = $"请分析文件 {fileName}，查找可疑的作弊行为特征（如内存读写、进程注入、驱动通信等）。分析完成后请调用 submit_report 函数提交 Markdown 格式的分析报告。";

        try
        {
            await foreach (var update in agent.RunStreamingAsync(prompt, agentSession))
            {
                foreach (var content in update.Contents)
                {
                    switch (content)
                    {
                        case TextReasoningContent r:
                            Console.ForegroundColor = ConsoleColor.DarkGray;
                            Console.Write(r.Text);
                            Console.ResetColor();
                            break;
                        case TextContent t:
                            Console.Write(t.Text);
                            break;
                        case FunctionCallContent fc:
                            Console.ForegroundColor = ConsoleColor.DarkYellow;
                            Console.WriteLine($"\n[工具] {fc.Name}({fc.Arguments})");
                            Console.ResetColor();
                            break;
                        case FunctionResultContent fr:
                            Console.ForegroundColor = ConsoleColor.DarkGreen;
                            var resultText = fr.Result?.ToString() ?? "";
                            if (resultText.Length > 500) resultText = resultText[..500] + "...";
                            Console.WriteLine($"[结果] {resultText}");
                            Console.ResetColor();
                            break;
                    }
                }
            }
        }
        catch (HttpRequestException ex)
        {
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n[错误] 网络请求失败: {ex.Message}");
            Console.ResetColor();
        }
        Console.WriteLine();
    }
    finally
    {
        // ── 清理 MCP 客户端 ───────────────────────────────────────
        if (mcpClient != null)
        {
            try { await mcpClient.DisposeAsync(); } catch { }
        }

        // ── 终止 IDA 和 MCP 进程 ──────────────────────────────────
        try
        {
            Process.Start(new ProcessStartInfo("taskkill", "/F /IM ida.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            })?.WaitForExit();
        }
        catch { }
        try
        {
            Process.Start(new ProcessStartInfo("taskkill", "/F /IM ida-pro-mcp.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            })?.WaitForExit();
        }
        catch { }
        Console.WriteLine("[清理] 已终止 IDA 和 MCP 进程");
    }
}

static string FormatSize(long bytes)
{
    if (bytes < 1024) return $"{bytes} B";
    if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
    if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
    return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
}

// ══════════════════════════════════════════════════════════════════
// 数据类型
// ══════════════════════════════════════════════════════════════════

class AgentConfig
{
    public string ServerUrl { get; set; } = "http://localhost:5000";
    public string CredentialToken { get; set; } = "";
    public string IdaPath { get; set; } = @"C:\IDA Professional 9.4\ida.exe";
    public string WinDbgPath { get; set; } = "";
    public string WorkDir { get; set; } = @"C:\ReverseAgentWork";
    public string IdaMcpEndpoint { get; set; } = "http://127.0.0.1:13337/mcp";
    public int IdaAnalysisWaitSeconds { get; set; } = 60;
    public int HeartbeatIntervalSeconds { get; set; } = 5;
    public int NoTaskWaitSeconds { get; set; } = 30;
}

class StatusHolder
{
    public string Status { get; set; } = "空闲";
}

class ConnectResponse
{
    [JsonPropertyName("agent_id")]
    public string AgentId { get; set; } = "";

    [JsonPropertyName("llm_apis")]
    public List<LlmApi> LlmApis { get; set; } = new();

    [JsonPropertyName("connected_at")]
    public string ConnectedAt { get; set; } = "";
}

class LlmApi
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("base_url")]
    public string BaseUrl { get; set; } = "";

    [JsonPropertyName("api_key")]
    public string ApiKey { get; set; } = "";

    [JsonPropertyName("model_name")]
    public string ModelName { get; set; } = "";
}

class NextTaskResponse
{
    [JsonPropertyName("has_task")]
    public bool HasTask { get; set; }

    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = "";

    [JsonPropertyName("machine_name")]
    public string MachineName { get; set; } = "";

    [JsonPropertyName("files")]
    public List<TaskFile> Files { get; set; } = new();
}

class TaskFile
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("download_url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("size")]
    public long Size { get; set; }
}
