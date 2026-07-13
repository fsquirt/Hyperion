// WvtCompare C# — 对 KslD.sys 调用 WinVerifyTrust，dump WINTRUST_DATA 二进制对比
using System;
using System.IO;
using System.Runtime.InteropServices;

internal static class Program
{
    private static void Main(string[] args)
    {
        Guid action = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        string file = args.Length > 0 ? args[0] : @"C:\Windows\system32\drivers\wd\KslD.sys";

        Console.Error.WriteLine($"[csharp] file={file}");
        Console.Error.WriteLine($"[csharp] SizeOf<WINTRUST_FILE_INFO>={Marshal.SizeOf<WINTRUST_FILE_INFO>()} (expect 32)");
        Console.Error.WriteLine($"[csharp] SizeOf<WINTRUST_DATA>={Marshal.SizeOf<WINTRUST_DATA>()} (expect 88)");

        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = file,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };
        var trustData = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = 2,
            fdwRevocationChecks = 0,
            dwUnionChoice = 1,
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>()),
            dwStateAction = 0,
            dwProvFlags = 0x100,
        };
        Console.Error.WriteLine($"[csharp] pFile=0x{trustData.pFile.ToInt64():X16} action={action}");

        int hr;
        IntPtr dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            Marshal.StructureToPtr(fileInfo, trustData.pFile, false);
            Marshal.StructureToPtr(trustData, dataPtr, false);

            DumpMem("cs_fileinfo.bin", "WINTRUST_FILE_INFO (csharp)", trustData.pFile, Marshal.SizeOf<WINTRUST_FILE_INFO>());
            DumpMem("cs_trustdata.bin", "WINTRUST_DATA (csharp)", dataPtr, Marshal.SizeOf<WINTRUST_DATA>());

            Console.Error.WriteLine("[csharp] calling WinVerifyTrust(VERIFY)...");
            hr = WinVerifyTrust((IntPtr)(-1), action, dataPtr);
            int le1 = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"[csharp] VERIFY hr=0x{hr & 0xFFFFFFFF:X8} lastErr=0x{le1:X8}");

            trustData.dwStateAction = 1; // WTD_STATEACTION_CLOSE
            Marshal.StructureToPtr(trustData, dataPtr, false);
            WinVerifyTrust((IntPtr)(-1), action, dataPtr);
            int le2 = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"[csharp] CLOSE lastErr=0x{le2:X8}");
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            Marshal.FreeHGlobal(trustData.pFile);
        }
        Console.Error.WriteLine($"[csharp] DONE hr=0x{hr & 0xFFFFFFFF:X8}");
    }

    private static void DumpMem(string binPath, string tag, IntPtr ptr, int len)
    {
        byte[] buf = new byte[len];
        Marshal.Copy(ptr, buf, 0, len);
        File.WriteAllBytes(binPath, buf);
        Console.Error.WriteLine($"[dump] wrote {len} bytes to {binPath}");
        Console.Error.WriteLine($"=== {tag} ({len} bytes) ===");
        for (int i = 0; i < len; i += 16)
        {
            Console.Error.Write($"{i:x4}  ");
            for (int j = 0; j < 16; j++)
            {
                if (i + j < len) Console.Error.Write($"{buf[i + j]:x2} ");
                else Console.Error.Write("   ");
            }
            Console.Error.Write(" ");
            for (int j = 0; j < 16; j++)
            {
                if (i + j < len)
                {
                    byte c = buf[i + j];
                    Console.Error.Write((c >= 32 && c < 127) ? (char)c : '.');
                }
            }
            Console.Error.WriteLine();
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);
}
