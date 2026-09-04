using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
internal struct BCRYPT_PSS_PADDING_INFO { public IntPtr pszAlgId; public uint cbSalt; }

internal static class Bcrypt
{
    [DllImport("bcrypt.dll")] public static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string? pszImplementation, uint dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] public static extern uint BCryptImportKeyPair(IntPtr hAlgorithm, IntPtr hImportKey, string pszBlobType, out IntPtr phKey, byte[] pbInput, int cbInput, uint dwFlags);
    [DllImport("bcrypt.dll")] public static extern uint BCryptVerifySignature(IntPtr hKey, IntPtr pPaddingInfo, byte[] pbHash, int cbHash, byte[] pbSignature, int cbSignature, uint dwFlags);
    [DllImport("bcrypt.dll")] public static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);
    [DllImport("bcrypt.dll")] public static extern uint BCryptDestroyKey(IntPtr hKey);
}
