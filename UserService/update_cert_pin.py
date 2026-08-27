#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update_cert_pin.py — 从服务端获取最新 TLS 证书,
替换 UserService/Comm/CertPinning.cs 中 EmbeddedServerCertPem 常量内容。

背景: 正式服务器(hyperion.cloudyou.top)的 CDN TLS 证书每半个月轮换一次,
CertPinning 内置的 leaf 证书会过期, 需要定期同步。

服务端地址来源: 读取同目录 Program.cs 中硬编码的 serverUrl 变量。
若该地址为内网开发地址(192.168.0.0/16), CertPinning 运行时会自动跳过
HTTPS/TLS 证书校验(见 ManagedTlsHandler), 内置证书根本不会被使用,
因此脚本直接跳过更新。

用法:
    python update_cert_pin.py            # 从 Program.cs 读地址, 自动判断内外网

只做三件事:
  1. TLS 连接到目标站点, 取第一张对端证书(leaf)。
  2. 校验证书 CN/SAN 包含目标域名(防止抓到错误证书)。
  3. 用正则替换 Comm/CertPinning.cs 中 EmbeddedServerCertPem 的 PEM 块,
     保持原有缩进与 "@" 引号格式不变。
"""
import base64
import ipaddress
import os
import re
import socket
import ssl
import sys
import urllib.parse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROGRAM_CS = os.path.join(SCRIPT_DIR, "Program.cs")
DEFAULT_CSPATH = os.path.join(SCRIPT_DIR, "Comm", "CertPinning.cs")

# 服务端地址硬编码于 Program.cs:  string serverUrl = "http://x.x.x.x:5000";
SERVER_URL_PATTERN = re.compile(r'string\s+serverUrl\s*=\s*"([^"]+)"')


def read_server_url() -> str:
    """从 Program.cs 读取硬编码的 serverUrl。"""
    with open(PROGRAM_CS, "r", encoding="utf-8") as f:
        content = f.read()
    m = SERVER_URL_PATTERN.search(content)
    if not m:
        raise RuntimeError(f"在 {PROGRAM_CS} 中未找到 serverUrl 变量")
    return m.group(1).strip()


def is_lan_dev_url(url: str) -> bool:
    """判断是否为内网开发地址(仅 192.168.0.0/16), 与 CertPinning.IsLanDevServerUrl 保持一致。"""
    try:
        host = urllib.parse.urlparse(url).hostname
        ip = ipaddress.ip_address(host)
    except (ValueError, TypeError):
        return False
    return ip.version == 4 and ip in ipaddress.ip_network("192.168.0.0/16")


def der_to_pem(der: bytes) -> str:
    """DER 证书 -> PEM 单行块(64 字符折行), 与 C# 源码内嵌格式一致。"""
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"


def fetch_leaf_pem(host: str, port: int) -> str:
    """TLS 连接取对端证书(leaf), 校验 CN/SAN 包含目标域名。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    with socket.create_connection((host, port), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            peer_certs = tls.getpeercert(binary_form=False)
            leaf_der = tls.getpeercert(binary_form=True)
            if not leaf_der:
                raise RuntimeError("无法获取对端证书 (getpeercert 为空)")

            # SAN 校验
            san_ok = False
            for entry in peer_certs.get("subjectAltName", ()):
                if entry[0] in ("DNS", "IP") and entry[1] == host:
                    san_ok = True
                    break
            if not san_ok:
                # 退一步校验 CN
                cn = None
                for rdn in peer_certs.get("subject", ()):
                    for key, value in rdn:
                        if key == "commonName":
                            cn = value
                if cn != host:
                    raise RuntimeError(
                        f"证书 SAN/CN 与目标域名 {host} 不匹配 (SAN 校验失败, CN={cn})"
                    )

    return der_to_pem(leaf_der)


def replace_embedded_pem(cs_path: str, new_pem: str) -> bool:
    """替换 CertPinning.cs 中 EmbeddedServerCertPem 的 PEM 块。返回是否发生替换。"""
    with open(cs_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 匹配:  EmbeddedServerCertPem = @"-----BEGIN CERTIFICATE-----\n ... \n-----END CERTIFICATE-----";
    pattern = re.compile(
        r'(EmbeddedServerCertPem = @")'
        r'-----BEGIN CERTIFICATE-----.*?'
        r'-----END CERTIFICATE-----'
        r'(";)',
        re.S,
    )
    if not pattern.search(content):
        raise RuntimeError(f"在 {cs_path} 中未找到 EmbeddedServerCertPem 块")

    new_content, n = pattern.subn(
        lambda m: m.group(1) + new_pem + m.group(2), content
    )
    if n == 0:
        raise RuntimeError("替换未生效")

    with open(cs_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    return True


def main() -> int:
    # 1. 从 Program.cs 读取地址并判断内外网
    server_url = read_server_url()
    print(f"[1/4] 从 Program.cs 读取服务端地址: {server_url}")

    if is_lan_dev_url(server_url):
        print(f"[SKIP] {server_url} 为内网开发地址(192.168.0.0/16), "
              "运行时已自动关闭 TLS 证书校验, 内置证书不会被使用, 跳过更新")
        return 0

    parsed = urllib.parse.urlparse(server_url if "//" in server_url else "//" + server_url)
    host = parsed.hostname
    if not host:
        raise RuntimeError(f"无法从 serverUrl 解析出主机名: {server_url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 2. 获取证书
    print(f"[2/4] 从 https://{host}:{port} 获取 leaf 证书 ...")
    new_pem = fetch_leaf_pem(host, port)
    print(new_pem)
    print(f"[3/4] 证书已获取, PEM 长度 {len(new_pem)} 字节")

    # 3. 替换
    print(f"[4/4] 替换 {DEFAULT_CSPATH} 中 EmbeddedServerCertPem ...")
    replace_embedded_pem(DEFAULT_CSPATH, new_pem)

    print("[OK] 证书更新成功")
    return 0


if __name__ == "__main__":
    sys.exit(main())
