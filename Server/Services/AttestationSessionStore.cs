using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Hyperion.Server.Services;

/// <summary>
/// 内存会话管理，涵盖 MakeCredential 与 Quote 两类会话，带自动过期清理
/// </summary>
public sealed class AttestationSessionStore : IDisposable
{
    private record McSession(byte[] Secret, string AkNameHex, string EkFp, DateTime Created);
    private record QuoteSession(byte[] Nonce, string AkNameHex, DateTime Created);

    private readonly ConcurrentDictionary<string, McSession> _mcSessions = new();
    private readonly ConcurrentDictionary<string, QuoteSession> _quoteSessions = new();

    private static readonly TimeSpan SessionTimeout = TimeSpan.FromMinutes(5);

    // 持字段引用防止清理回调被 GC 停止, Dispose 时释放
    private readonly Timer _cleanupTimer;

    public AttestationSessionStore()
    {
        // 定期清理过期会话
        _cleanupTimer = new Timer(Cleanup, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    public void Dispose() => _cleanupTimer.Dispose();

    /// <summary>创建 MakeCredential 会话</summary>
    /// <param name="secret">密钥</param>
    /// <param name="akNameHex">AK 名称的十六进制表示</param>
    /// <param name="ekFp">EK 指纹</param>
    /// <returns>会话 ID</returns>
    public string CreateMcSession(byte[] secret, string akNameHex, string ekFp)
    {
        var sid = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        _mcSessions[sid] = new McSession(secret, akNameHex, ekFp, DateTime.UtcNow);
        return sid;
    }

    public (byte[] secret, string akNameHex, string ekFp)? PopMcSession(string sessionId)
    {
        if (_mcSessions.TryRemove(sessionId, out var session))
            return (session.Secret, session.AkNameHex, session.EkFp);
        return null;
    }

    /// <summary>创建 Quote 会话</summary>
    /// <param name="nonce">随机数</param>
    /// <param name="akNameHex">AK 名称的十六进制表示</param>
    /// <returns>会话 ID</returns>
    public string CreateQuoteSession(byte[] nonce, string akNameHex)
    {
        var qsid = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        _quoteSessions[qsid] = new QuoteSession(nonce, akNameHex, DateTime.UtcNow);
        return qsid;
    }

    /// <summary>获取 Quote 会话</summary>
    /// <param name="quoteSid">会话 ID</param>
    /// <returns>会话内容</returns>
    public (byte[] nonce, string akNameHex)? PopQuoteSession(string quoteSid)
    {
        if (_quoteSessions.TryRemove(quoteSid, out var session))
            return (session.Nonce, session.AkNameHex);
        return null;
    }

    
    /// <summary>清理所有过期会话</summary>
    private void Cleanup(object? state)
    {
        var cutoff = DateTime.UtcNow - SessionTimeout;
        foreach (var (key, session) in _mcSessions)
        {
            if (session.Created < cutoff)
                _mcSessions.TryRemove(key, out _);
        }
        foreach (var (key, session) in _quoteSessions)
        {
            if (session.Created < cutoff)
                _quoteSessions.TryRemove(key, out _);
        }
    }
}
