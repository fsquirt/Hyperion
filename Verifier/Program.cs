namespace Hyperion.Verifier;

static class Program
{
    static async Task<int> Main(string[] args)
    {
        string serverUrl = args.Length > 0 ? args[0] : "http://localhost:5000";
        var result = await VerifierEngine.RunAsync(serverUrl);
        return result.Success ? 0 : 1;
    }
}
