using Microsoft.Agents.AI;
using Microsoft.Extensions.AI;
using ModelContextProtocol.Client;
using OpenAI;
using OpenAI.Chat;
using System.ClientModel;

const string OpenRouterBaseUrl = "https://openrouter.ai/api/v1";
const string ModelId = "tencent/hy3:free";
const string McpEndpoint = "http://127.0.0.1:13337/mcp";

var apiKey = Environment.GetEnvironmentVariable("OPENROUTER_API_KEY")
    ?? "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";

// ── 1. OpenRouter（OpenAI 兼容端点）─────────────────────────────
var openaiOptions = new OpenAIClientOptions { Endpoint = new Uri(OpenRouterBaseUrl) };
var openaiClient = new OpenAIClient(new ApiKeyCredential(apiKey), openaiOptions);
var chatClient = openaiClient.GetChatClient(ModelId);

// ── 2. MCP 客户端（streamable-http）──────────────────────────────
Console.WriteLine("正在连接 MCP 服务器...");
var transport = new HttpClientTransport(new HttpClientTransportOptions
{
    Endpoint = new Uri(McpEndpoint),
    TransportMode = HttpTransportMode.StreamableHttp,
    ConnectionTimeout = TimeSpan.FromSeconds(30),
});
await using var mcpClient = await McpClient.CreateAsync(transport);
var mcpTools = await mcpClient.ListToolsAsync();
Console.WriteLine($"已加载 {mcpTools.Count} 个 MCP 工具:");
foreach (var t in mcpTools)
    Console.WriteLine($"  - {t.Name}: {t.Description}");

// ── 3. 创建 Agent ────────────────────────────────────────────────
AIAgent agent = chatClient.AsAIAgent(
    name: "ReverseAgent",
    description: "逆向分析助手，能调用 IDA Pro MCP 工具",
    instructions: "你是逆向分析助手。先调用 MCP 工具（如 server_health 检查服务器、survey_binary 获取概览）确认工具可用，再回答用户问题。回答用中文。",
    tools: [.. mcpTools]);

// ── 4. 多轮流式对话 ──────────────────────────────────────────────
AgentSession session = await agent.CreateSessionAsync();
Console.WriteLine("\n对话已就绪（输入空行退出）\n");

while (true)
{
    Console.Write("你> ");
    var input = Console.ReadLine();
    if (string.IsNullOrWhiteSpace(input)) break;

    Console.Write("助手> ");
    await foreach (var update in agent.RunStreamingAsync(input, session))
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
    Console.WriteLine();
}

Console.WriteLine("再见！");
