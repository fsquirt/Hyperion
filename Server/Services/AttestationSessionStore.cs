using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Hyperion.Server.Services;

/// <summary>
/// 内存会话管理，涵盖 MakeCredential 与 Quote 两类会话，带自动过期清理
/// </summary>
public sealed class AttestationSessionStore
{
    private record McSession(byte[] Secret, string AkNameHex, string EkFp, DateTime Created);
    private record QuoteSession(byte[] Nonce, string AkNameHex, DateTime Created);

    private readonly ConcurrentDictionary<string, McSession> _mcSessions = new();
    private readonly ConcurrentDictionary<string, QuoteSession> _quoteSessions = new();

    private static readonly TimeSpan SessionTimeout = TimeSpan.FromMinutes(5);

    public AttestationSessionStore()
    {
        // 定期清理过期会话
        var timer = new Timer(Cleanup, null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    // ═══════════════════════════════════════════════════════════════
    //  MakeCredential 会话
    // ═══════════════════════════════════════════════════════════════

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

    // ═══════════════════════════════════════════════════════════════
    //  Quote 会话
    // ═══════════════════════════════════════════════════════════════

    public string CreateQuoteSession(byte[] nonce, string akNameHex)
    {
        var qsid = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        _quoteSessions[qsid] = new QuoteSession(nonce, akNameHex, DateTime.UtcNow);
        return qsid;
    }

    public (byte[] nonce, string akNameHex)? PopQuoteSession(string quoteSid)
    {
        if (_quoteSessions.TryRemove(quoteSid, out var session))
            return (session.Nonce, session.AkNameHex);
        return null;
    }

    // ═══════════════════════════════════════════════════════════════
    //  清理过期会话
    // ═══════════════════════════════════════════════════════════════

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
