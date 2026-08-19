#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
update_cert_pin.py — 从 https://hyperion.cloudyou.top 获取最新 TLS 证书,
替换 Tracker/CertPinning.cs 中 EmbeddedServerCertPem 常量内容。

背景: hyperion.cloudyou.top 的 CDN TLS 证书每半个月轮换一次,
CertPinning 内置的 leaf 证书会过期, 需要定期同步。

用法:
    python update_cert_pin.py [host] [port]

默认 host=hyperion.cloudyou.top port=443。

只做三件事:
  1. TLS 连接到目标站点, 取第一张对端证书(leaf)。
  2. 校验证书 CN/SAN 包含目标域名(防止抓到错误证书)。
  3. 用正则替换 CertPinning.cs 中 EmbeddedServerCertPem 的 PEM 块,
     保持原有缩进与 "@" 引号格式不变。
"""
import base64
import re
import socket
import ssl
import sys

DEFAULT_HOST = "hyperion.cloudyou.top"
DEFAULT_PORT = 443
DEFAULT_CSPATH = "CertPinning.cs"


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
    host = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    cs_path = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_CSPATH

    print(f"[1/3] 从 https://{host}:{port} 获取 leaf 证书 ...")
    new_pem = fetch_leaf_pem(host, port)
    print(new_pem)
    print(f"[2/3] 证书已获取, PEM 长度 {len(new_pem)} 字节")

    print(f"[3/3] 替换 {cs_path} 中 EmbeddedServerCertPem ...")
    replace_embedded_pem(cs_path, new_pem)

    print("[OK] 证书更新成功")
    return 0


if __name__ == "__main__":
    sys.exit(main())