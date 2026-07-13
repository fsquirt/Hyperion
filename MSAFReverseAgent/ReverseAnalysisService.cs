using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Client;
using OpenAI;
using OpenAI.Chat;
using System.ClientModel;
using System.Text.Json;

namespace Hyperion.MSAFReverseAgent;

/// <summary>
/// 逆向分析服务 — 可被 Server 调用来分析捕获的文件。
/// .dmp 文件用 Windbg MCP, .dll/.exe/.sys 文件用 IDA MCP。
/// </summary>
public class ReverseAnalysisService : IDisposable, IAsyncDisposable
{
    private readonly string _openRouterApiKey;
    private readonly string _openRouterBaseUrl;
    private readonly string _modelId;

    // MCP 端点配置 (可注入, 默认 IDA)
    private readonly string _idaMcpEndpoint;
    private readonly string? _windbgMcpEndpoint;  // 可选, 暂无默认值

    private OpenAIClient? _openaiClient;
    private McpClient? _mcpClient;
    private string? _currentMcpEndpoint;  // 当前已连接的端点, 用于端点切换判定

    /// <summary>
    /// 创建逆向分析服务。
    /// </summary>
    /// <param name="openRouterApiKey">OpenRouter API key (默认从环境变量读取)</param>
    /// <param name="modelId">LLM 模型 ID (默认 tencent/hy3:free)</param>
    /// <param name="idaMcpEndpoint">IDA MCP 端点 (默认 http://127.0.0.1:13337/mcp)</param>
    /// <param name="windbgMcpEndpoint">Windbg MCP 端点 (可选, 暂无默认)</param>
    public ReverseAnalysisService(
        string? openRouterApiKey = null,
        string? modelId = null,
        string? idaMcpEndpoint = null,
        string? windbgMcpEndpoint = null)
    {
        _openRouterApiKey = openRouterApiKey
            ?? Environment.GetEnvironmentVariable("OPENROUTER_API_KEY")
            ?? "";
        _openRouterBaseUrl = "https://openrouter.ai/api/v1";
        _modelId = modelId ?? "tencent/hy3:free";
        _idaMcpEndpoint = idaMcpEndpoint ?? "http://127.0.0.1:13337/mcp";
        _windbgMcpEndpoint = windbgMcpEndpoint;
    }

    /// <summary>
    /// 分析文件并返回结构化结果。
    /// 根据文件扩展名自动选择 MCP:
    ///   .dmp → Windbg MCP (需配置 windbgMcpEndpoint)
    ///   .dll/.exe/.sys → IDA MCP
    /// </summary>
    public async Task<AnalysisResult> AnalyzeFileAsync(string filePath, string? fileType = null)
    {
        var result = new AnalysisResult
        {
            FilePath = filePath,
            FileType = fileType ?? Path.GetExtension(filePath).TrimStart('.'),
            StartedAt = DateTime.UtcNow,
        };

        try
        {
            // 根据文件类型选择 MCP 端点
            string mcpEndpoint;
            string analysisType;
            string ext = Path.GetExtension(filePath).ToLowerInvariant();

            if (ext == ".dmp")
            {
                mcpEndpoint = _windbgMcpEndpoint ?? throw new InvalidOperationException("Windbg MCP endpoint not configured");
                analysisType = "windbg";
            }
            else
            {
                mcpEndpoint = _idaMcpEndpoint;
                analysisType = "ida";
            }

            result.McpEndpoint = mcpEndpoint;
            result.AnalysisType = analysisType;

            // 连接 MCP (端点变化时会自动重连)
            await ConnectMcpAsync(mcpEndpoint);

            // 创建 agent
            var agent = await CreateAgentAsync(filePath, analysisType);

            // 运行分析
            var prompt = BuildAnalysisPrompt(filePath, analysisType);
            var session = await agent.CreateSessionAsync();

            var sb = new System.Text.StringBuilder();
            await foreach (var update in agent.RunStreamingAsync(prompt, session))
            {
                foreach (var content in update.Contents)
                {
                    if (content is TextContent t)
                        sb.Append(t.Text);
                }
            }

            result.Result = sb.ToString();
            result.Status = "success";
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.Error = ex.Message;
        }

        result.CompletedAt = DateTime.UtcNow;
        return result;
    }

    private async Task ConnectMcpAsync(string endpoint)
    {
        // 如果已经连接到同一个端点, 复用
        if (_mcpClient != null && _currentMcpEndpoint == endpoint) return;

        // 端点变化时, 先释放旧的 MCP 客户端
        if (_mcpClient is IAsyncDisposable asyncDisp)
        {
            await asyncDisp.DisposeAsync();
        }
        _mcpClient = null;
        _currentMcpEndpoint = null;

        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(endpoint),
            TransportMode = HttpTransportMode.StreamableHttp,
            ConnectionTimeout = TimeSpan.FromSeconds(30),
        });
        _mcpClient = await McpClient.CreateAsync(transport);
        _currentMcpEndpoint = endpoint;
    }

    private async Task<AIAgent> CreateAgentAsync(string filePath, string analysisType)
    {
        _openaiClient ??= new OpenAIClient(
            new ApiKeyCredential(_openRouterApiKey),
            new OpenAIClientOptions { Endpoint = new Uri(_openRouterBaseUrl) });

        var chatClient = _openaiClient.GetChatClient(_modelId);
        var mcpTools = await _mcpClient!.ListToolsAsync();

        string instructions = analysisType == "windbg"
            ? $"你是内存转储分析助手。分析文件: {filePath}。使用 Windbg MCP 工具执行分析。回答用中文。请注意你一次最多只能并发调用2个工具。"
            : $"你是逆向分析助手。分析文件: {filePath}。先调用 MCP 工具 (如 server_health 检查服务器、survey_binary 获取概览) 确认工具可用，再分析文件。回答用中文。请注意你一次最多只能并发调用2个工具。";

        return chatClient.AsAIAgent(
            name: "ReverseAgent",
            description: "逆向分析助手",
            instructions: instructions,
            tools: [.. mcpTools],
            clientFactory: inner => new ChatClientBuilder(inner)
                .UseFunctionInvocation(configure: fic =>
                {
                    fic.IncludeDetailedErrors = true;
                    fic.MaximumConsecutiveErrorsPerRequest = 5;
                })
                .Build());
    }

    private static string BuildAnalysisPrompt(string filePath, string analysisType)
    {
        string fileName = Path.GetFileName(filePath);
        if (analysisType == "windbg")
        {
            return $"请分析内存转储文件 {fileName}。文件路径: {filePath}\n" +
                   "执行以下步骤:\n" +
                   "1. 检查崩溃原因和异常地址\n" +
                   "2. 分析调用栈\n" +
                   "3. 识别可疑模块和函数\n" +
                   "4. 总结发现的安全威胁\n" +
                   "请以 JSON 格式返回分析结果。";
        }
        else
        {
            return $"请分析二进制文件 {fileName}。文件路径: {filePath}\n" +
                   "执行以下步骤:\n" +
                   "1. 获取二进制概览 (survey_binary)\n" +
                   "2. 识别导入的危险函数 (MmCopyMemory, MmMapIoSpace, ZwMapViewOfSection, MmCopyVirtualMemory)\n" +
                   "3. 检查导出函数和设备创建\n" +
                   "4. 分析可能的 IOCTL 处理函数\n" +
                   "5. 总结该文件的安全威胁等级和发现\n" +
                   "请以 JSON 格式返回分析结果。";
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_mcpClient is IAsyncDisposable asyncDisp)
        {
            await asyncDisp.DisposeAsync();
        }
        // 注意: OpenAIClient 在 OpenAI 2.12.0 中不实现 IDisposable,
        // 其内部 HttpClient 由 .NET 管理生命周期, 无需显式释放。
        _openaiClient = null;
        _mcpClient = null;
        _currentMcpEndpoint = null;
    }

    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}

/// <summary>
/// 文件分析结果。
/// </summary>
public class AnalysisResult
{
    public string FilePath { get; set; } = "";
    public string FileType { get; set; } = "";
    public string AnalysisType { get; set; } = "";  // "ida" / "windbg"
    public string? McpEndpoint { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime CompletedAt { get; set; }
    public string Status { get; set; } = "pending";  // pending / success / failed
    public string? Result { get; set; }
    public string? Error { get; set; }
}
