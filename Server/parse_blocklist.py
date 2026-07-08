#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hyperion 恶意驱动阻止列表解析器（原型）
解析两个数据源，输出统一结构，供后续移植到 C# Server 端参考。

数据源:
  1. loldrivers.json          — LOLDrivers 项目 (https://www.loldrivers.io/)
  2. DriverPolicy_Enforced.xml — 微软易受攻击驱动阻止列表 (WDAC SiPolicy)

输出统一结构:
  {
    "source": "loldriver" | "msft",
    "driver_name": str,
    "md5":  str | None,   # 小写 hex
    "sha1": str | None,   # 小写 hex
    "sha256": str | None, # 小写 hex
  }
"""

import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter


# ═══════════════════════════════════════════════════════════════
#  1. 解析 loldrivers.json
# ═══════════════════════════════════════════════════════════════

def parse_loldrivers(path: str):
    """解析 LOLDrivers JSON，返回统一条目列表。

    LOLDrivers JSON 结构（v3）:
      顶层 = [ {driver}, ... ]，每个 driver 含:
        Id             — 驱动标识（用作 driver_name）
        Category       — 分类
        KnownVulnerableSamples[] — 已知漏洞样本数组
          [i].Filename / MD5 / SHA1 / SHA256 / Authentihash{...}
      一个 driver 可能有多个样本（不同版本/变体），每个样本独立成条。
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"[loldrivers] 顶层类型: {type(data).__name__}, 条目数: {len(data)}")
    if data:
        print(f"[loldrivers] 样例键: {list(data[0].keys())}")

    entries = []
    hash_stat = Counter()
    no_sample = 0
    for item in data:
        driver_name = item.get("Id") or item.get("Description") or "unknown"
        samples = item.get("KnownVulnerableSamples", []) or []
        if not samples:
            no_sample += 1
            continue

        for s in samples:
            md5 = s.get("MD5")
            sha1 = s.get("SHA1")
            sha256 = s.get("SHA256")
            # 至少要有一个哈希才有意义
            if not (md5 or sha1 or sha256):
                continue
            # 样本若有 Filename 则附加到驱动名后，便于区分多版本
            fname = s.get("Filename") or s.get("OriginalFilename") or ""
            name = f"{driver_name}\\{fname}" if fname else driver_name
            entries.append(_norm_entry("loldriver", name, md5, sha1, sha256))
            if md5: hash_stat["md5"] += 1
            if sha1: hash_stat["sha1"] += 1
            if sha256: hash_stat["sha256"] += 1

    print(f"[loldrivers] 解析条目数: {len(entries)}")
    print(f"[loldrivers] 无样本条目: {no_sample}")
    print(f"[loldrivers] 哈希统计: {dict(hash_stat)}")
    return entries


# ═══════════════════════════════════════════════════════════════
#  2. 解析 DriverPolicy_Enforced.xml (微软 WDAC SiPolicy)
# ═══════════════════════════════════════════════════════════════

NS = {"sip": "urn:schemas-microsoft-com:sipolicy"}

# FriendlyName 里标识哈希类型的关键词
#   "Hash Sha1"        → 文件 SHA1 (40 hex)
#   "Hash Sha256"      → 文件 SHA256 (64 hex)
#   "Hash Page Sha1"   → 页哈希 SHA1 (排除，不是整文件哈希)
#   "Hash Page Sha256" → 页哈希 SHA256 (排除)
# 注意: 部分老格式条目 FriendlyName 里不含 "Sha1/Sha256" 字样，
#       需依据 Hash 长度判定 (40=SHA1, 64=SHA256)。

SHA1_LEN = 40
SHA256_LEN = 64


def _detect_hash_type(friendly: str, hash_hex: str) -> str | None:
    """根据 FriendlyName 与哈希长度判定类型，返回 'sha1'/'sha256'/None。"""
    fl = friendly.lower()
    # 页哈希排除
    if "page sha1" in fl or "page sha256" in fl:
        return None
    if "sha1" in fl:
        return "sha1"
    if "sha256" in fl:
        return "sha256"
    # 回退: 依据长度
    n = len(hash_hex)
    if n == SHA1_LEN:
        return "sha1"
    if n == SHA256_LEN:
        return "sha256"
    return None


def _extract_driver_name(friendly: str, deny_id: str) -> str:
    """从 FriendlyName 提取驱动名；失败时回退到 Deny ID。"""
    # FriendlyName 形如:
    #   "Agent64\05f052_4045ae_694848_8cb62c_b1d962 Hash Sha1"
    #   "AsrDrv10.sys Hash Sha256"
    #   "asrdrv104\4bf974...89 Hash Sha1"
    # 取第一个 \ 或 .sys 之前的部分
    m = re.match(r"^([^\\\s]+(?:\\[^\\\s]+)?)", friendly)
    if m:
        return m.group(1)
    # 回退: 从 ID 提取 ID_DENY_<NAME>_<suffix>
    m2 = re.match(r"ID_DENY_(.+?)_", deny_id)
    return m2.group(1) if m2 else deny_id


def parse_msft_xml(path: str):
    """解析微软 WDAC SiPolicy XML，返回统一条目列表。"""
    tree = ET.parse(path)
    root = tree.getroot()

    # FileRules 下的 Deny 节点
    file_rules = root.find("sip:FileRules", NS)
    if file_rules is None:
        print("[msft] 未找到 FileRules 节点")
        return []

    # 按驱动名聚合: 一个驱动可能有 SHA1+SHA256+页哈希多条
    by_driver: dict[str, dict] = {}
    hash_stat = Counter()
    deny_count = 0
    skipped_page = 0

    for deny in file_rules.findall("sip:Deny", NS):
        deny_count += 1
        deny_id = deny.get("ID", "")
        friendly = deny.get("FriendlyName", "")
        hash_hex = deny.get("Hash", "")
        if not hash_hex:
            continue

        htype = _detect_hash_type(friendly, hash_hex)
        if htype is None:
            skipped_page += 1
            continue

        name = _extract_driver_name(friendly, deny_id)
        hash_lower = hash_hex.lower()

        if name not in by_driver:
            by_driver[name] = {"source": "msft", "driver_name": name,
                               "md5": None, "sha1": None, "sha256": None}
        if htype == "sha1" and not by_driver[name]["sha1"]:
            by_driver[name]["sha1"] = hash_lower
            hash_stat["sha1"] += 1
        elif htype == "sha256" and not by_driver[name]["sha256"]:
            by_driver[name]["sha256"] = hash_lower
            hash_stat["sha256"] += 1

    entries = list(by_driver.values())
    print(f"[msft] Deny 节点总数: {deny_count}")
    print(f"[msft] 跳过页哈希: {skipped_page}")
    print(f"[msft] 聚合驱动数: {len(entries)}")
    print(f"[msft] 哈希统计: {dict(hash_stat)}")
    return entries


# ═══════════════════════════════════════════════════════════════
#  3. 辅助
# ═══════════════════════════════════════════════════════════════

def _norm_entry(source, driver_name, md5, sha1, sha256):
    return {
        "source": source,
        "driver_name": driver_name or "",
        "md5": md5.lower() if md5 else None,
        "sha1": sha1.lower() if sha1 else None,
        "sha256": sha256.lower() if sha256 else None,
    }


def print_sample(entries, n=3, label=""):
    print(f"\n── {label} 样例 (前 {n} 条) ──")
    for e in entries[:n]:
        print(f"  {e}")


# ═══════════════════════════════════════════════════════════════
#  4. 主入口
# ═══════════════════════════════════════════════════════════════

def main():
    base = os.path.dirname(os.path.abspath(__file__))
    loldriver_path = os.path.join(base, "loldrivers.json")
    msft_xml_path = os.path.join(base, "VulnerableDriverBlockList", "DriverPolicy_Enforced.xml")

    print("=" * 60)
    print("Hyperion 恶意驱动阻止列表解析器")
    print("=" * 60)

    # ── LOLDrivers ──
    lol_entries = []
    if os.path.exists(loldriver_path):
        print(f"\n[1/2] 解析 loldrivers.json ...")
        try:
            lol_entries = parse_loldrivers(loldriver_path)
            print_sample(lol_entries, 3, "LOLDrivers")
        except Exception as ex:
            print(f"[loldrivers] 解析失败: {ex}")
    else:
        print(f"[!] 未找到 {loldriver_path}")

    # ── MSFT ──
    msft_entries = []
    if os.path.exists(msft_xml_path):
        print(f"\n[2/2] 解析 DriverPolicy_Enforced.xml ...")
        try:
            msft_entries = parse_msft_xml(msft_xml_path)
            print_sample(msft_entries, 3, "MSFT")
        except Exception as ex:
            print(f"[msft] 解析失败: {ex}")
    else:
        print(f"[!] 未找到 {msft_xml_path}")

    # ── 汇总 ──
    print("\n" + "=" * 60)
    print("汇总")
    print("=" * 60)
    print(f"  LOLDrivers 条目: {len(lol_entries)}")
    print(f"  MSFT 条目:       {len(msft_entries)}")
    print(f"  合计:            {len(lol_entries) + len(msft_entries)}")

    # 去重统计（按 sha256）
    seen = set()
    dup = 0
    for e in lol_entries + msft_entries:
        if e["sha256"]:
            if e["sha256"] in seen:
                dup += 1
            else:
                seen.add(e["sha256"])
    print(f"  SHA256 重复(跨源): {dup}")

    print("\n[✓] 解析完成，逻辑可移植到 C# Server 端。")


if __name__ == "__main__":
    sys.exit(main() or 0)
