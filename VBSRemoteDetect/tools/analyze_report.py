# -*- coding: utf-8 -*-
"""
runtime_report.bin 离线分析脚本
布局依据 winnt.h (10.0.28000.0) + 实测偏移修正:
  [RUNTIME_REPORT_PACKAGE_HEADER 40B, 含对齐填充]
  [Nonce 32B @40]
  [RUNTIME_REPORT_DIGEST_HEADER × N @72, 每个 68B]
  [Signature Blob]
  [Authenticated Reports: RUNTIME_REPORT_HEADER(8B) + payload]
用法: python analyze_report.py runtime_report.bin [期望的challenge_nonce_hex]
"""
import struct
import sys
import hashlib


def hash_size_from_calg(calg):
    return {0x8004: 20, 0x800C: 32, 0x800D: 48, 0x800E: 64}.get(calg, -1)


def parse_report(filename, expected_nonce_hex=None):
    with open(filename, "rb") as f:
        data = f.read()
    print(f"[*] 读取文件: {filename}, {len(data)} 字节")

    # ── 1. 包头,共 40 字节, 实际字段 36B + 4B 对齐填充 ──
    magic = struct.unpack_from("<I", data, 0)[0]
    pkg_ver, num_reports = struct.unpack_from("<HH", data, 4)
    bitmap = struct.unpack_from("<Q", data, 8)[0]
    pkg_size = struct.unpack_from("<I", data, 16)[0]
    digest_type = struct.unpack_from("<H", data, 20)[0]
    digests_size = struct.unpack_from("<H", data, 22)[0]
    sig_scheme = struct.unpack_from("<H", data, 26)[0]
    sig_size = struct.unpack_from("<I", data, 28)[0]
    auth_size = struct.unpack_from("<I", data, 32)[0]

    # 注意: DWORD 0x52545250 小端存储, 字节序为 50 52 54 52,按 ASCII 读作 "PRTR"
    print(f"[+] Magic: 0x{magic:08X}" + ("" if magic == 0x52545250 else "  ← 非法! 应为 0x52545250"))
    print(f"[+] 包版本: {pkg_ver}  报告数: {num_reports}  类型掩码: 0x{bitmap:X}")
    print(f"[+] 包大小: {pkg_size}  Digest类型: 0x{digest_type:X} (0x800E=SHA-512)")
    print(f"[+] 签名方案: {sig_scheme} (1 = SHA512_RSA_PSS_SHA512)")
    print(f"[+] 签名大小: {sig_size}  认证区大小: {auth_size}")
    if magic != 0x52545250:
        return

    # ── 2. Nonce @40 ──
    nonce = data[40:72]
    print(f"[+] Nonce @40: {nonce.hex()}")
    if expected_nonce_hex:
        match = nonce.hex() == expected_nonce_hex.replace(" ", "").lower()
        print(f"[+] Nonce 与 challenge 匹配: {match}")

    # ── 3. Digest headers @72, 每个 68B ──
    digests = {}
    pos = 72
    digests_end = 72 + digests_size
    while pos + 68 <= digests_end:
        rtype = struct.unpack_from("<H", data, pos)[0]
        digests[rtype] = data[pos + 4: pos + 68]
        print(f"[+] Digest[类型 {rtype}]: {digests[rtype].hex()[:32]}...")
        pos += 68
    sig_off = digests_end
    reports_off = sig_off + sig_size
    print(f"[+] 签名 Blob: 0x{sig_off:X} ~ 0x{reports_off:X} ({sig_size}B, RSA-PSS/SHA-512)")
    print(f"[+] 认证报告区起点: 0x{reports_off:X}")

    # ── 4. Authenticated Reports ──
    p = reports_off
    reports_end = min(reports_off + auth_size, len(data))
    while p + 8 <= reports_end:
        rtype = struct.unpack_from("<H", data, p)[0]
        rsize = struct.unpack_from("<I", data, p + 4)[0]
        if rsize < 8 or p + rsize > reports_end:
            break
        report_data = data[p:p + rsize]
        calc = hashlib.sha512(report_data).digest()
        ok = digests.get(rtype) == calc
        print(f"\n──────── 报告类型 {rtype}, 长度 {rsize}B — SK 摘要校验: {'[OK]' if ok else '[FAIL 篡改]'} ────────")

        if rtype == 0:  # DRIVER_RUNTIME_REPORT
            num_drivers, flags = struct.unpack_from("<HH", report_data, 8)
            overflow, partial, boot_inc = flags & 1, (flags >> 1) & 1, (flags >> 2) & 1
            print(f"[+] 驱动总数: {num_drivers}  溢出: {bool(overflow)}  部分: {bool(partial)}  含Boot驱动: {bool(boot_inc)}")
            print(f"{'驱动名称':<26} | {'类型':<9} | {'次数':>4} | OEM | 镜像哈希 SHA-256")
            print("-" * 100)
            for i in range(num_drivers):
                e = 12 + i * 56
                if e + 56 > len(report_data):
                    break
                load_times = struct.unpack_from("<H", report_data, e + 44)[0]
                img_off_val = struct.unpack_from("<I", report_data, e + 36)[0]
                if load_times == 0 and img_off_val == 0:
                    continue  # 空槽位 (ghost entry)
                name = report_data[e:e + 32].split(b"\x00")[0].decode("ascii", errors="ignore")
                img_alg, pub_alg = struct.unpack_from("<HH", report_data, e + 32)
                img_off, pub_off = struct.unpack_from("<II", report_data, e + 36)
                oem_sz = struct.unpack_from("<H", report_data, e + 46)[0]
                oem_off = struct.unpack_from("<I", report_data, e + 48)[0]
                drv_flags = struct.unpack_from("<H", report_data, e + 52)[0]
                is_boot, is_unloaded = bool(drv_flags & 2), bool(drv_flags & 1)
                desc = "Boot" if is_boot else ("Unloaded" if is_unloaded else "Runtime")
                # 镜像哈希与发布者指纹各自按自己的算法取长度, 发布者通常 SHA-1=20B
                img_hsz = hash_size_from_calg(img_alg)
                pub_hsz = hash_size_from_calg(pub_alg)
                img = report_data[img_off:img_off + img_hsz].hex() if img_hsz > 0 and img_off and img_off + img_hsz <= len(report_data) else "N/A"
                pub = report_data[pub_off:pub_off + pub_hsz].hex() if pub_hsz > 0 and pub_off and pub_off + pub_hsz <= len(report_data) else "N/A"
                oem = report_data[oem_off:oem_off + oem_sz].decode("utf-8", errors="ignore") if oem_sz and oem_off and oem_off + oem_sz <= len(report_data) else ""
                print(f"{name:<26} | {desc:<9} | {load_times:>4} | {oem:<28} | img={img[:32]}... pub={pub[:40]}...")

        elif rtype == 1:  # CODE_INTEGRITY_RUNTIME_REPORT
            generation = struct.unpack_from("<Q", report_data, 8)[0]
            num_gens = struct.unpack_from("<I", report_data, 16)[0]
            print(f"[+] CI 策略代数: {generation}, 报告内含 {num_gens} 代")
        p += rsize

    print("\n[*] 注: Signature Blob 的微软信任根验证,即 SK 签名公钥来源,尚未实现 —")
    print("    生产版需经 measured boot (PCR12 VSM_IDK_INFO) 或微软根证书锚定。")


if __name__ == "__main__":
    f = sys.argv[1] if len(sys.argv) > 1 else "runtime_report.bin"
    nonce = sys.argv[2] if len(sys.argv) > 2 else None
    parse_report(f, nonce)
