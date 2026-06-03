using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace SEWindows.Server.Services;

/// <summary>
/// TPM2 密码学操作：KDFa 密钥派生 + MakeCredential 凭证创建
/// </summary>
public static class Tpm2Crypto
{
    // ═══════════════════════════════════════════════════════════════
    //  TPM2 KDFa (NIST SP 800-108 Counter Mode, HMAC-SHA256)
    // ═══════════════════════════════════════════════════════════════

    public static byte[] Kdfa(byte[] key, string label, byte[] contextU, byte[] contextV, int bits)
    {
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var labelWithNull = new byte[labelBytes.Length + 1];
        Buffer.BlockCopy(labelBytes, 0, labelWithNull, 0, labelBytes.Length);
        // null terminator already 0

        var bitsBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bitsBytes, (uint)bits);

        var output = new List<byte>();
        uint counter = 1;
        using var hmac = new HMACSHA256(key);

        while (output.Count * 8 < bits)
        {
            var counterBytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(counterBytes, counter);

            // 链: counter || label || contextU || contextV || bits
            var inputLen = 4 + labelWithNull.Length + contextU.Length + contextV.Length + 4;
            var input = new byte[inputLen];
            var offset = 0;
            Buffer.BlockCopy(counterBytes, 0, input, offset, 4); offset += 4;
            Buffer.BlockCopy(labelWithNull, 0, input, offset, labelWithNull.Length); offset += labelWithNull.Length;
            Buffer.BlockCopy(contextU, 0, input, offset, contextU.Length); offset += contextU.Length;
            Buffer.BlockCopy(contextV, 0, input, offset, contextV.Length); offset += contextV.Length;
            Buffer.BlockCopy(bitsBytes, 0, input, offset, 4);

            var hash = hmac.ComputeHash(input);
            output.AddRange(hash);
            counter++;
        }

        var result = new byte[bits / 8];
        Buffer.BlockCopy(output.ToArray(), 0, result, 0, result.Length);
        return result;
    }

    // ═══════════════════════════════════════════════════════════════
    //  MakeCredential (服务端模拟 TPM2_MakeCredential)
    //  返回 (credentialBlob, encryptedSecret)
    // ═══════════════════════════════════════════════════════════════

    public static (byte[] credentialBlob, byte[] encryptedSecret) MakeCredential(
        byte[] ekPubSpkiDer, byte[] akName, byte[] credential)
    {
        // 1. 生成 32 字节随机 seed
        var seed = RandomNumberGenerator.GetBytes(32);

        // 2. 用 EK 公钥 RSA-OAEP 加密 seed, label = "IDENTITY\0"
        var encSecret = RsaOaepEncrypt(ekPubSpkiDer, seed);

        // 3. 派生对称密钥
        var symKey = Kdfa(seed, "STORAGE", akName, [], 128);

        // 4. 打包 credential: big-endian 2字节长度 + credential
        var packedCredential = new byte[2 + credential.Length];
        BinaryPrimitives.WriteUInt16BigEndian(packedCredential, (ushort)credential.Length);
        Buffer.BlockCopy(credential, 0, packedCredential, 2, credential.Length);

        // 5. AES-128-CFB 加密, IV = 16字节零
        var encIdentity = Aes128CfbEncrypt(symKey, new byte[16], packedCredential);

        // 6. 派生 HMAC 密钥
        var hmacKey = Kdfa(seed, "INTEGRITY", [], [], 256);

        // 7. 计算 integrity = HMAC-SHA256(hmacKey, encIdentity || akName)
        var hmacInput = new byte[encIdentity.Length + akName.Length];
        Buffer.BlockCopy(encIdentity, 0, hmacInput, 0, encIdentity.Length);
        Buffer.BlockCopy(akName, 0, hmacInput, encIdentity.Length, akName.Length);
        using var hmac = new HMACSHA256(hmacKey);
        var integrity = hmac.ComputeHash(hmacInput);

        // 8. 打包 credentialBlob: big-endian 2字节 integrity长度 || integrity || encIdentity
        var blob = new byte[2 + integrity.Length + encIdentity.Length];
        BinaryPrimitives.WriteUInt16BigEndian(blob, (ushort)integrity.Length);
        Buffer.BlockCopy(integrity, 0, blob, 2, integrity.Length);
        Buffer.BlockCopy(encIdentity, 0, blob, 2 + integrity.Length, encIdentity.Length);

        return (blob, encSecret);
    }

    // ═══════════════════════════════════════════════════════════════
    //  RSA-OAEP 加密（自定义 label = "IDENTITY\0"）
    //  .NET 原生不支持自定义 label，使用 BouncyCastle
    // ═══════════════════════════════════════════════════════════════

    private static byte[] RsaOaepEncrypt(byte[] spkiDer, byte[] data)
    {
        // 从 SPKI DER 导入公钥
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spkiDer, out _);
        var rsaParams = rsa.ExportParameters(false);

        // 转换为 BouncyCastle 参数
        var bcParams = new RsaKeyParameters(
            false,
            new Org.BouncyCastle.Math.BigInteger(1, rsaParams.Modulus!),
            new Org.BouncyCastle.Math.BigInteger(1, rsaParams.Exponent!));

        // OAEP with SHA-256, custom label "IDENTITY\0"
        var sha256 = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
        var labelBytes = "IDENTITY\0"u8.ToArray();

        // OaepEncoding(engine, hash, mgf1Hash, label)
        var cipher = new OaepEncoding(new RsaEngine(), sha256, sha256, labelBytes);
        cipher.Init(true, bcParams);
        return cipher.ProcessBlock(data, 0, data.Length);
    }

    // ═══════════════════════════════════════════════════════════════
    //  AES-128-CFB 加密 (CFB128, 全块反馈)
    // ═══════════════════════════════════════════════════════════════

    private static byte[] Aes128CfbEncrypt(byte[] key, byte[] iv, byte[] data)
    {
        // BouncyCastle AES-CFB128
        var cipher = new Org.BouncyCastle.Crypto.BufferedBlockCipher(
            new Org.BouncyCastle.Crypto.Modes.CfbBlockCipher(
                new Org.BouncyCastle.Crypto.Engines.AesEngine(), 128));
        cipher.Init(true, new Org.BouncyCastle.Crypto.Parameters.ParametersWithIV(
            new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key), iv));

        var output = new byte[cipher.GetOutputSize(data.Length)];
        var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
        len += cipher.DoFinal(output, len);
        return output[..len];
    }
}
