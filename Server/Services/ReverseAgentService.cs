using Microsoft.EntityFrameworkCore;
using Hyperion.Server.Data;
using Hyperion.Server.Models;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;

namespace Hyperion.Server.Services;

/// <summary>
/// 逆向分析 Agent 服务。
/// 活跃 Agent 保存在内存中，心跳超时 60s 自动清理；
/// 分析状态/报告持久化到 SQLite，对应 session_analysis_states 与 analysis_reports 两张表。
/// 通过 TrackerSessionStore 查询已结束会话及其取证文件。
/// </summary>
public sealed class ReverseAgentService : IDisposable
{
    private readonly ConcurrentDictionary<string, LiveAgent> _agents = new();
    private readonly IDbContextFactory<AttestationDbContext> _dbFactory;
    private readonly LlmApiService _llmApi;
    private readonly TrackerSessionStore _trackerStore;
    private readonly ILogger<ReverseAgentService> _logger;

    // 心跳超时 60 秒
    private static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(60);

    // 任务领取串行锁，避免多 Agent 同时领取同一会话
    private readonly SemaphoreSlim _claimLock = new(1, 1);

    // 可分析文件扩展名，含 .dmp 用于 WinDbg 动态分析
    private static readonly HashSet<string> AnalyzableExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".sys", ".pyd", ".ocx", ".dmp" };

    // sessionId 格式约束, 与 TrackerEndpoints 保持一致, 拼路径前必须校验, 防路径穿越
    private static readonly Regex SessionIdPattern = new("^[0-9a-f]{12}$", RegexOptions.Compiled);

    // 终端日志自增序号
    private long _logSeq = 0;

    // 会话清理定时器，持字段引用防止被 GC 回收，并在 Dispose 时释放
    private readonly Timer _cleanupTimer;

    public ReverseAgentService(
        IDbContextFactory<AttestationDbContext> dbFactory,
        LlmApiService llmApi,
        TrackerSessionStore trackerStore,
        ILogger<ReverseAgentService> logger)
    {
        _dbFactory = dbFactory;
        _llmApi = llmApi;
        _trackerStore = trackerStore;
        _logger = logger;
        _cleanupTimer = new Timer(Cleanup, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
    }

    public void Dispose() => _cleanupTimer.Dispose();

    /// <summary>
    /// 验证 Bearer token → 获取 LLM API 列表 → 创建含短期 agent token 的内存 Agent 记录 → 返回。
    /// 失败返回 null，对应 401 响应。
    /// agent_token 是后续所有 Agent 端点的短期凭据，agent_id 退化为纯标识。
    /// </summary>
    public async Task<ReverseAgentConnectResponse?> ConnectAsync(string? bearerToken)
    {
        if (!await _llmApi.ValidateCredentialAsync(bearerToken))
            return null;

        var apis = await _llmApi.GetClusterLlmApisAsync();
        var agentId = Guid.NewGuid().ToString("N")[..12];
        var agentToken = RandomNumberGenerator.GetHexString(32, lowercase: true);
        var now = DateTime.UtcNow.ToString("o");
        var agent = new LiveAgent
        {
            AgentId = agentId,
            Token = agentToken,
            ConnectedAt = now,
            LlmApiName = apis.FirstOrDefault()?.Name ?? "unknown",
            LastHeartbeat = DateTime.UtcNow,
        };
        _agents[agentId] = agent;
        _logger.LogInformation("[ReverseAgent] Agent 连接: {AgentId}", agentId);
        return new ReverseAgentConnectResponse { AgentId = agentId, AgentToken = agentToken, LlmApis = apis, ConnectedAt = now };
    }

    /// <summary>
    /// 用 agent token 认证 Agent：token 匹配内存记录即返回对应的 agentId。
    /// agent 数量少，仅数十级，线性扫描足够；token 随心跳超时一起失效。
    /// </summary>
    public bool TryAuthenticateAgent(string token, out string agentId)
    {
        agentId = "";
        if (string.IsNullOrEmpty(token)) return false;
        foreach (var (id, agent) in _agents)
        {
            // 常时比较，避免 token 比对时序侧信道
            if (FixedTimeEquals(agent.Token, token))
            {
                agentId = id;
                return true;
            }
        }
        return false;
    }

    /// <summary>常时字符串比较, 长度不等时立即返回, 无逐字符短路。</summary>
    private static bool FixedTimeEquals(string? a, string? b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(a), System.Text.Encoding.UTF8.GetBytes(b));
    }

    /// <summary>更新心跳时间和当前状态。</summary>
    public bool Heartbeat(string agentId, string currentStatus)
    {
        if (!_agents.TryGetValue(agentId, out var agent)) return false;
        agent.LastHeartbeat = DateTime.UtcNow;
        agent.CurrentStatus = currentStatus;
        return true;
    }

    /// <summary>
    /// 从内存移除 Agent，并立即回退该 Agent 正在分析、即 analyzing 状态的会话为 pending。
    /// 用于 Agent 主动断连或异常断联时及时释放会话，避免卡在 analyzing 状态。
    /// </summary>
    public async Task DisconnectAsync(string agentId)
    {
        _agents.TryRemove(agentId, out _);
        await RollbackExpiredAgentsAsync(new List<string> { agentId });
        _logger.LogInformation("[ReverseAgent] Agent 断连并回退占用会话: {AgentId}", agentId);
    }

    /// <summary>返回内存中所有 Agent。</summary>
    public List<ActiveAgentEntry> GetActiveAgents()
    {
        var now = DateTime.UtcNow;
        return _agents.Values.Select(a => ToEntry(a, now)).ToList();
    }

    /// <summary>判断指定 Agent 是否在线，用于 Agent 上报接口的鉴权。</summary>
    public bool IsAgentConnected(string agentId) => _agents.ContainsKey(agentId);

    /// <summary>
    /// 领取下一个待分析会话：
    /// 1. 查 pending 状态记录，关联 tracker_sessions 按 started_at DESC 找最新且有可分析文件的
    /// 2. 若无 pending，查 tracker_sessions 中不在 session_analysis_states 里的已结束会话
    ///    有可分析文件则创建 pending 记录
    /// 3. 标记为 analyzing，设置 assigned_agent_id / analysis_started_at / last_heartbeat_at
    /// 4. 返回会话信息和文件列表
    /// </summary>
    public async Task<NextTaskResponse> ClaimNextTaskAsync(string agentId)
    {
        if (!_agents.ContainsKey(agentId))
            return new NextTaskResponse { HasTask = false };

        await _claimLock.WaitAsync();
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();

            // 1. 查 pending 记录
            var pendingStates = await db.SessionAnalysisStates
                .Where(s => s.AnalysisStatus == "pending")
                .ToListAsync();

            string? selectedSessionId = null;
            string? selectedMachineName = null;
            List<FileEntry> selectedFiles = new();

            if (pendingStates.Count > 0)
            {
                var pendingIds = pendingStates.Select(s => s.SessionId).ToList();
                var sessions = await db.TrackerSessions
                    .Where(t => pendingIds.Contains(t.Id))
                    .OrderByDescending(t => t.StartedAt)
                    .ToListAsync();

                foreach (var session in sessions)
                {
                    var files = ExtractAnalyzableFiles(session.ExtraJson);
                    if (files.Count > 0)
                    {
                        selectedSessionId = session.Id;
                        selectedMachineName = session.MachineName;
                        selectedFiles = files;
                        break;
                    }
                }
            }

            // 2. 无 pending 可领取 → 查 tracker_sessions 中未在 session_analysis_states 里的
            if (selectedSessionId == null)
            {
                var newSessions = await db.TrackerSessions
                    .Where(t => !db.SessionAnalysisStates.Any(s => s.SessionId == t.Id))
                    .OrderByDescending(t => t.StartedAt)
                    .ToListAsync();

                foreach (var session in newSessions)
                {
                    var files = ExtractAnalyzableFiles(session.ExtraJson);
                    if (files.Count > 0)
                    {
                        // 创建 pending 状态记录
                        db.SessionAnalysisStates.Add(new SessionAnalysisStateEntity
                        {
                            SessionId = session.Id,
                            AnalysisStatus = "pending",
                        });
                        selectedSessionId = session.Id;
                        selectedMachineName = session.MachineName;
                        selectedFiles = files;
                        break;
                    }
                }
            }

            if (selectedSessionId == null)
                return new NextTaskResponse { HasTask = false };

            // 3. 标记为 analyzing
            var stateEntity = await db.SessionAnalysisStates.FindAsync(selectedSessionId);
            if (stateEntity == null)
                return new NextTaskResponse { HasTask = false };

            var now = DateTime.UtcNow.ToString("o");
            stateEntity.AnalysisStatus = "analyzing";
            stateEntity.AssignedAgentId = agentId;
            stateEntity.AnalysisStartedAt = now;
            stateEntity.LastHeartbeatAt = now;

            await db.SaveChangesAsync();

            // 更新 Agent 状态
            if (_agents.TryGetValue(agentId, out var agent))
            {
                agent.CurrentStatus = $"分析中: {selectedSessionId}";
            }

            // 4. 返回任务信息
            var taskFiles = selectedFiles.Select(f => new TaskFileInfo
            {
                Name = f.Name,
                StoredName = f.StoredName,
                DownloadUrl = $"/api/reverse-agent/download/{selectedSessionId}/{Uri.EscapeDataString(f.StoredName)}",
                Size = f.Size,
                Kind = f.Kind,
            }).ToList();

            return new NextTaskResponse
            {
                HasTask = true,
                SessionId = selectedSessionId,
                MachineName = selectedMachineName,
                Files = taskFiles,
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ReverseAgent] ClaimNextTask 失败");
            return new NextTaskResponse { HasTask = false };
        }
        finally
        {
            _claimLock.Release();
        }
    }

    /// <summary>
    /// 提交分析报告：保存到 analysis_reports 表，更新 session_analysis_states 为 done。
    /// 支持一会话一报告：fileName 可为空，表示会话级总结报告。
    /// 原子条件更新：只有该会话的领取者、即 AssignedAgentId 匹配者，且状态为 analyzing 时才会成功，
    /// 防止其他 Agent 覆盖报告或对已完成会话二次提交。
    /// </summary>
    public async Task<bool> SubmitReportAsync(
        string sessionId, string agentId, string? fileName, string result, string content)
    {
        var validResults = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "normal", "cheat", "suspicious" };
        if (!validResults.Contains(result))
            return false;

        try
        {
            var normalizedResult = result.ToLowerInvariant();
            await using var db = await _dbFactory.CreateDbContextAsync();
            await using var tx = await db.Database.BeginTransactionAsync();

            // 原子条件更新：仅当「领取者 == 提交者 且 状态 == analyzing」时成功；
            // SQLite 单写者 + 条件 UPDATE，并发下只有真正的持有者能拿到 rows == 1
            var rows = await db.SessionAnalysisStates
                .Where(s => s.SessionId == sessionId
                         && s.AssignedAgentId == agentId
                         && s.AnalysisStatus == "analyzing")
                .ExecuteUpdateAsync(s => s
                    .SetProperty(x => x.AnalysisStatus, "done")
                    .SetProperty(x => x.AnalysisResult, normalizedResult)
                    .SetProperty(x => x.AnalysisCompletedAt, DateTime.UtcNow.ToString("o")));

            if (rows != 1)
            {
                await tx.RollbackAsync();
                return false; // 不是领取者 / 状态不是 analyzing / 已提交过
            }

            // 状态更新成功才写报告，避免重复报告
            db.AnalysisReports.Add(new AnalysisReportEntity
            {
                Id = Guid.NewGuid().ToString("N"),
                SessionId = sessionId,
                FileName = string.IsNullOrWhiteSpace(fileName) ? "session_summary" : fileName,
                Result = normalizedResult,
                Content = content,
                GeneratedAt = DateTime.UtcNow.ToString("o"),
                AgentId = agentId,
            });
            await db.SaveChangesAsync();
            await tx.CommitAsync();

            // 更新 Agent 完成任务数
            if (_agents.TryGetValue(agentId, out var agent))
            {
                agent.CompletedTasks++;
                agent.CurrentStatus = "空闲";
            }

            _logger.LogInformation(
                "[ReverseAgent] 报告提交: session={SessionId} file={File} result={Result}",
                sessionId, fileName, normalizedResult);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ReverseAgent] SubmitReport 失败: {SessionId}", sessionId);
            return false;
        }
    }

    /// <summary>
    /// 校验 Agent 是否拥有该会话的访问权：是领取者且会话处于 analyzing。
    /// 用于 session-context / download / log 等需要会话级归属校验的端点。
    /// </summary>
    public async Task<bool> CanAgentAccessSessionAsync(string agentId, string sessionId)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.SessionAnalysisStates
            .AnyAsync(s => s.SessionId == sessionId
                        && s.AssignedAgentId == agentId
                        && s.AnalysisStatus == "analyzing");
    }

    /// <summary>
    /// 合并 TrackerSessionStore 的所有会话摘要与 session_analysis_states 状态。
    /// 没有 state 的会话按 file_count 判定：有文件则标记 pending，无文件则标记 no_files。
    /// 注意：TrackerSessionStore.LoadFinishedSummariesAsync 不解析 extra_json，
    /// 已结束会话的 FileCount 始终为 0，因此需要从 DB 补查实际文件数。
    /// </summary>
    public async Task<List<AnalysisQueueEntry>> GetAnalysisQueueAsync()
    {
        var summaries = await _trackerStore.GetSummariesAsync();
        await using var db = await _dbFactory.CreateDbContextAsync();
        var states = await db.SessionAnalysisStates.ToListAsync();
        var stateMap = states.ToDictionary(s => s.SessionId);

        // 从 tracker_sessions.extra_json 补查实际文件数, 因为已结束会话的 summary.FileCount 为 0。
        // 只查 FileCount 为 0 的会话, 并把计数下推到 SQLite 的 JSON1 函数在库端完成,
        // 避免把整列 extra_json 加载进内存, 单条记录可达数 MB
        var needCountIds = summaries.Where(s => s.FileCount == 0).Select(s => s.Id).ToList();
        var dbFileCounts = new Dictionary<string, int>();
        if (needCountIds.Count > 0)
        {
            var conn = db.Database.GetDbConnection();
            await conn.OpenAsync();
            await using var cmd = conn.CreateCommand();
            var paramNames = new List<string>(needCountIds.Count);
            for (int i = 0; i < needCountIds.Count; i++)
            {
                var p = cmd.CreateParameter();
                p.ParameterName = $"@id{i}";
                p.Value = needCountIds[i];
                cmd.Parameters.Add(p);
                paramNames.Add($"@id{i}");
            }
            cmd.CommandText =
                $"SELECT id, json_array_length(extra_json, '$.Files') FROM tracker_sessions WHERE id IN ({string.Join(",", paramNames)})";
            await using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                if (!reader.IsDBNull(1))
                    dbFileCounts[reader.GetString(0)] = reader.GetInt32(1);
            }
        }

        var result = new List<AnalysisQueueEntry>();
        foreach (var s in summaries)
        {
            // 优先用 summary 的 FileCount，活跃会话的内存值准确；
            // 为 0 时回退到 DB 端 JSON 计数，覆盖已结束会话
            var fileCount = s.FileCount;
            if (fileCount == 0 && dbFileCounts.TryGetValue(s.Id, out var dbCount))
            {
                fileCount = dbCount;
            }

            if (stateMap.TryGetValue(s.Id, out var state))
            {
                result.Add(new AnalysisQueueEntry
                {
                    SessionId = s.Id,
                    MachineName = s.MachineName,
                    StartedAt = s.StartedAt,
                    AnalysisStatus = state.AnalysisStatus,
                    AnalysisResult = state.AnalysisResult,
                    FileCount = fileCount,
                });
            }
            else
            {
                result.Add(new AnalysisQueueEntry
                {
                    SessionId = s.Id,
                    MachineName = s.MachineName,
                    StartedAt = s.StartedAt,
                    AnalysisStatus = fileCount > 0 ? "pending" : "no_files",
                    AnalysisResult = null,
                    FileCount = fileCount,
                });
            }
        }
        return result;
    }

    /// <summary>查分析报告列表，不含 content 字段。</summary>
    public async Task<List<ReportListEntry>> GetReportsAsync()
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.AnalysisReports
            .OrderByDescending(r => r.GeneratedAt)
            .Select(r => new ReportListEntry
            {
                Id = r.Id,
                SessionId = r.SessionId,
                FileName = r.FileName,
                Result = r.Result,
                GeneratedAt = r.GeneratedAt,
            })
            .ToListAsync();
    }

    /// <summary>查单条报告，含 content 字段。</summary>
    public async Task<ReportDetail?> GetReportAsync(string id)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var r = await db.AnalysisReports.FindAsync(id);
        if (r == null) return null;
        return new ReportDetail
        {
            Id = r.Id,
            SessionId = r.SessionId,
            FileName = r.FileName,
            Result = r.Result,
            GeneratedAt = r.GeneratedAt,
            Content = r.Content,
            AgentId = r.AgentId,
        };
    }

    /// <summary>
    /// 删除游戏会话：移除 tracker_sessions 记录、session_analysis_states 状态、
    /// analysis_reports 报告，以及 TrackerFiles/{sessionId} 本地文件目录。
    /// 不允许删除正在分析、即 analyzing 状态的会话，避免影响活跃 Agent。
    /// </summary>
    public async Task<(bool ok, string? error)> DeleteSessionAsync(string sessionId)
    {
        // sessionId 来自 URL,拼路径前必须校验格式,防路径穿越/任意目录删除
        if (sessionId == null || !SessionIdPattern.IsMatch(sessionId))
            return (false, "sessionId 格式非法");

        await using var db = await _dbFactory.CreateDbContextAsync();

        // 拒绝删除正在分析的会话
        var state = await db.SessionAnalysisStates.FindAsync(sessionId);
        if (state is { AnalysisStatus: "analyzing" })
            return (false, "会话正在分析中，无法删除");

        // 删除分析状态
        if (state != null)
            db.SessionAnalysisStates.Remove(state);

        // 删除关联报告
        var reports = await db.AnalysisReports
            .Where(r => r.SessionId == sessionId)
            .ToListAsync();
        if (reports.Count > 0)
            db.AnalysisReports.RemoveRange(reports);

        // 删除 tracker_sessions 记录
        var session = await db.TrackerSessions.FindAsync(sessionId);
        if (session != null)
            db.TrackerSessions.Remove(session);

        await db.SaveChangesAsync();

        // 删除关联的终端日志
        await DeleteAnalysisLogsAsync(sessionId);

        // 删除本地取证文件目录
        var filesDir = Path.Combine(AppContext.BaseDirectory, "TrackerFiles", sessionId);
        if (Directory.Exists(filesDir))
        {
            try { Directory.Delete(filesDir, recursive: true); }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[ReverseAgent] 删除会话文件目录失败: {Dir}", filesDir);
            }
        }

        _logger.LogInformation("[ReverseAgent] 会话已删除: {SessionId}", sessionId);
        return (true, null);
    }

    /// <summary>
    /// 强制重置会话分析状态：无论当前处于 pending / analyzing / done 哪个状态，
    /// 都会清空研判结果与报告，并将会话重新标记为 pending，以便被重新领取。
    /// 用于 Agent 异常断联后状态卡在 analyzing 的兜底手段。
    /// </summary>
    public async Task<(bool ok, string? error)> ResetAnalysisAsync(string sessionId)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();

        var state = await db.SessionAnalysisStates.FindAsync(sessionId);

        // 该会话若正被内存中的 Agent 占用，同步清空其状态，避免后台仍显示"分析中"
        var assignedAgentId = state?.AssignedAgentId;
        if (!string.IsNullOrWhiteSpace(assignedAgentId) &&
            _agents.TryGetValue(assignedAgentId, out var agent))
        {
            agent.CurrentStatus = "空闲";
        }

        // 删除关联报告
        var reports = await db.AnalysisReports
            .Where(r => r.SessionId == sessionId)
            .ToListAsync();
        if (reports.Count > 0)
            db.AnalysisReports.RemoveRange(reports);

        // 重置分析状态为 pending
        if (state != null)
        {
            state.AnalysisStatus = "pending";
            state.AnalysisResult = null;
            state.AssignedAgentId = null;
            state.AnalysisStartedAt = null;
            state.AnalysisCompletedAt = null;
            state.LastHeartbeatAt = null;
            state.CurrentFile = null;
        }
        else
        {
            // 无状态记录则新建一条 pending，会话有文件时才会被 Agent 领取
            db.SessionAnalysisStates.Add(new SessionAnalysisStateEntity
            {
                SessionId = sessionId,
                AnalysisStatus = "pending",
            });
        }

        await db.SaveChangesAsync();

        // 重置分析时一并清理旧终端日志
        await DeleteAnalysisLogsAsync(sessionId);

        _logger.LogInformation("[ReverseAgent] 会话分析状态已强制重置: {SessionId}", sessionId);
        return (true, null);
    }

    /// <summary>追加一条终端日志，由 Agent 在分析过程中上报。</summary>
    public async Task AppendAnalysisLogAsync(string sessionId, string agentId, string fileName, string level, string text)
    {
        if (string.IsNullOrWhiteSpace(sessionId) || string.IsNullOrWhiteSpace(text)) return;
        var safeLevel = level switch
        {
            "llm" => "llm",
            "tool_call" => "tool_call",
            "tool_result" => "tool_result",
            _ => "info",
        };
        await using var db = await _dbFactory.CreateDbContextAsync();
        db.AnalysisLogs.Add(new AnalysisLogEntity
        {
            Id = Guid.NewGuid().ToString("N"),
            SessionId = sessionId,
            Seq = Interlocked.Increment(ref _logSeq),
            Ts = DateTime.UtcNow.ToString("o"),
            Level = safeLevel,
            File = fileName ?? "",
            Text = text.Length > 60000 ? text[..60000] : text,
        });
        await db.SaveChangesAsync();
    }

    /// <summary>查询某会话的全部终端日志，按序号升序。</summary>
    public async Task<List<AnalysisLogDto>> GetAnalysisLogsAsync(string sessionId)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        return await db.AnalysisLogs
            .Where(l => l.SessionId == sessionId)
            .OrderBy(l => l.Seq)
            .Select(l => new AnalysisLogDto
            {
                SessionId = l.SessionId,
                Seq = l.Seq,
                Ts = l.Ts,
                Level = l.Level,
                File = l.File,
                Text = l.Text,
            })
            .ToListAsync();
    }

    /// <summary>删除某会话的全部终端日志，随会话删除/重置一起清理。</summary>
    public async Task DeleteAnalysisLogsAsync(string sessionId)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        var rows = await db.AnalysisLogs.Where(l => l.SessionId == sessionId).ToListAsync();
        if (rows.Count > 0)
        {
            db.AnalysisLogs.RemoveRange(rows);
            await db.SaveChangesAsync();
        }
    }

    /// <summary>清理过期的 Agent 记录。</summary>
    private void Cleanup(object? state)
    {
        var cutoff = DateTime.UtcNow - HeartbeatTimeout;
        var expiredAgentIds = new List<string>();

        foreach (var (id, agent) in _agents)
        {
            if (agent.LastHeartbeat < cutoff)
                expiredAgentIds.Add(id);
        }

        if (expiredAgentIds.Count == 0) return;

        foreach (var id in expiredAgentIds)
        {
            _agents.TryRemove(id, out _);
            _logger.LogInformation("[ReverseAgent] Agent 心跳超时移除: {AgentId}", id);
        }

        // 回退超时 Agent 占用的 session，由 analyzing 转 pending
        _ = RollbackExpiredAgentsAsync(expiredAgentIds);
    }

    private async Task RollbackExpiredAgentsAsync(List<string> agentIds)
    {
        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync();
            var states = await db.SessionAnalysisStates
                .Where(s => s.AnalysisStatus == "analyzing" && agentIds.Contains(s.AssignedAgentId ?? ""))
                .ToListAsync();

            foreach (var s in states)
            {
                s.AnalysisStatus = "pending";
                s.AssignedAgentId = null;
                s.LastHeartbeatAt = null;
            }

            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[ReverseAgent] 回退超时 Agent 占用 session 失败");
        }
    }

    /// <summary>将 LiveAgent 转换为 ActiveAgentEntry。</summary>
    private static ActiveAgentEntry ToEntry(LiveAgent a, DateTime now)
    {
        var isOnline = (now - a.LastHeartbeat) <= HeartbeatTimeout;
        return new ActiveAgentEntry
        {
            AgentId = a.AgentId,
            LlmApiName = a.LlmApiName,
            ConnectedAt = a.ConnectedAt,
            CompletedTasks = a.CompletedTasks,
            CurrentStatus = a.CurrentStatus,
            IsOnline = isOnline,
        };
    }

    /// <summary>从 tracker_sessions.extra_json 中提取可分析文件，按扩展名过滤。</summary>
    private List<FileEntry> ExtractAnalyzableFiles(string? extraJson)
    {
        try
        {
            var dto = JsonSerializer.Deserialize<ExtraPayloadDto>(extraJson ?? "{}");
            if (dto?.Files == null || dto.Files.Count == 0) return new();

            return dto.Files
                .Where(f => !string.IsNullOrEmpty(f.Name) &&
                            AnalyzableExtensions.Contains(Path.GetExtension(f.Name)))
                .Select(f => new FileEntry
                {
                    Kind = f.Kind,
                    Name = f.Name,
                    StoredName = f.StoredName,
                    DownloadUrl = f.DownloadUrl,
                    Size = f.Size,
                })
                .ToList();
        }
        catch
        {
            return new();
        }
    }

    
    /// <summary>内存中的 Agent 记录。</summary>
    private sealed class LiveAgent
    {
        public required string AgentId { get; init; }
        public required string Token { get; init; }
        public required string ConnectedAt { get; init; }
        public DateTime LastHeartbeat { get; set; }
        public string CurrentStatus { get; set; } = "空闲";
        public int CompletedTasks { get; set; }
        public string LlmApiName { get; set; } = "";
    }

    /// <summary>反序列化 tracker_sessions.extra_json 的 DTO，仅取 Files 字段。</summary>
    private sealed class ExtraPayloadDto
    {
        [JsonPropertyName("Files")] public List<FileEntryDto> Files { get; set; } = new();
    }

    private sealed class FileEntryDto
    {
        [JsonPropertyName("kind")] public string Kind { get; set; } = "";
        [JsonPropertyName("name")] public string Name { get; set; } = "";
        [JsonPropertyName("storedName")] public string StoredName { get; set; } = "";
        [JsonPropertyName("downloadUrl")] public string DownloadUrl { get; set; } = "";
        [JsonPropertyName("size")] public long Size { get; set; }
    }
}
