#!/usr/bin/env python3
"""
Parse proxy share links into a unified configuration dict.
Supported formats: vmess://, vless://, ss://, trojan://, hysteria2:// (hy2://)
"""
import base64
import json
import re
from urllib.parse import urlparse, parse_qs, unquote


def _b64decode(s: str) -> bytes:
    """Base64 decode with padding fix."""
    s = s.strip().replace('-', '+').replace('_', '/')
    pad = 4 - len(s) % 4
    if pad != 4:
        s += '=' * pad
    return base64.b64decode(s)


def _empty() -> dict:
    return {
        "protocol": "",
        "server": "",
        "port": 0,
        "uuid": "",
        "alter_id": 0,
        "security": "auto",
        "password": "",
        "method": "",
        "flow": "",
        "network": "tcp",
        "path": "",
        "host": "",
        "tls": False,
        "sni": "",
        "fp": "",
        "insecure": False,
        "obfs": "",
        "obfs_password": "",
    }


def _parse_vmess(link: str) -> dict | None:
    """vmess://BASE64(json)"""
    try:
        b64 = link[len("vmess://"):]
        raw = _b64decode(b64).decode("utf-8")
        obj = json.loads(raw)
        d = _empty()
        d["protocol"] = "vmess"
        d["server"] = obj.get("add", "")
        d["port"] = int(obj.get("port", 443))
        d["uuid"] = obj.get("id", "")
        d["alter_id"] = int(obj.get("aid", 0))
        d["security"] = obj.get("scy", obj.get("security", "auto")) or "auto"
        d["network"] = obj.get("net", "tcp") or "tcp"
        d["path"] = obj.get("path", "") or ""
        d["host"] = obj.get("host", "") or ""
        tls_val = obj.get("tls", "")
        d["tls"] = tls_val in ("tls", "xtls", True, "true")
        d["sni"] = obj.get("sni", obj.get("host", "")) or ""
        d["fp"] = obj.get("fp", "") or ""
        return d
    except Exception:
        return None


def _parse_vless(link: str) -> dict | None:
    """vless://UUID@host:port?params#name"""
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)

        def p(k, default=""):
            return params.get(k, [default])[0]

        d = _empty()
        d["protocol"] = "vless"
        d["uuid"] = parsed.username or ""
        d["server"] = parsed.hostname or ""
        d["port"] = parsed.port or 443
        d["flow"] = p("flow")
        d["network"] = p("type", "tcp")
        d["path"] = unquote(p("path", p("serviceName")))
        d["host"] = p("host")
        security = p("security", "none")
        d["tls"] = security in ("tls", "xtls", "reality")
        d["sni"] = p("sni", p("serverName"))
        d["fp"] = p("fp", p("fingerprint"))
        d["insecure"] = p("allowInsecure", "0") in ("1", "true")
        return d
    except Exception:
        return None


def _parse_trojan(link: str) -> dict | None:
    """trojan://password@host:port?params#name"""
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)

        def p(k, default=""):
            return params.get(k, [default])[0]

        d = _empty()
        d["protocol"] = "trojan"
        d["password"] = unquote(parsed.username or "")
        d["server"] = parsed.hostname or ""
        d["port"] = parsed.port or 443
        d["network"] = p("type", "tcp")
        d["path"] = unquote(p("path", p("serviceName")))
        d["host"] = p("host")
        security = p("security", "tls")
        d["tls"] = security in ("tls", "xtls")
        d["sni"] = p("sni", p("serverName"))
        d["fp"] = p("fp", p("fingerprint"))
        d["insecure"] = p("allowInsecure", "0") in ("1", "true")
        return d
    except Exception:
        return None


def _parse_ss(link: str) -> dict | None:
    """
    ss://BASE64(method:password)@host:port#name
    or ss://BASE64(method:password#name)  (old format, no @ separator)
    """
    try:
        rest = link[len("ss://"):]

        # Strip fragment (name)
        if '#' in rest:
            rest = rest[:rest.index('#')]

        # Check for SIP002 format: ss://BASE64@host:port
        if '@' in rest:
            userinfo, hostpart = rest.rsplit('@', 1)
            # userinfo may be plain BASE64 or already decoded
            try:
                decoded = _b64decode(userinfo).decode("utf-8")
            except Exception:
                decoded = unquote(userinfo)

            if ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                method, password = "", decoded

            parsed_host = urlparse("ss://" + hostpart)
            server = parsed_host.hostname or ""
            port = parsed_host.port or 8388
        else:
            # Legacy format: ss://BASE64(method:password@host:port)
            decoded = _b64decode(rest).decode("utf-8")
            if '@' in decoded:
                # method:password@host:port
                userinfo, hostpart = decoded.rsplit('@', 1)
                if ':' in userinfo:
                    method, password = userinfo.split(':', 1)
                else:
                    method, password = "", userinfo
                if ':' in hostpart:
                    server, port_str = hostpart.rsplit(':', 1)
                    port = int(port_str)
                else:
                    server, port = hostpart, 8388
            else:
                # Very old format: method:password:host:port (no @)
                parts = decoded.split(':')
                if len(parts) < 4:
                    return None
                method = parts[0]
                port = int(parts[-1])
                server = parts[-2]
                password = ':'.join(parts[1:-2])

        d = _empty()
        d["protocol"] = "ss"
        d["method"] = method
        d["password"] = password
        d["server"] = server
        d["port"] = int(port)
        return d
    except Exception:
        return None


def _parse_hysteria2(link: str) -> dict | None:
    """
    hysteria2://password@host:port?params#name
    hy2://password@host:port?params#name
    """
    try:
        # Normalise scheme so urlparse works
        normalised = re.sub(r'^hy2://', 'hysteria2://', link, flags=re.IGNORECASE)
        parsed = urlparse(normalised)
        params = parse_qs(parsed.query)

        def p(k, default=""):
            return params.get(k, [default])[0]

        d = _empty()
        d["protocol"] = "hysteria2"
        d["password"] = unquote(parsed.username or "")
        d["server"] = parsed.hostname or ""
        d["port"] = parsed.port or 443
        d["sni"] = p("sni")
        d["insecure"] = p("insecure", "0") in ("1", "true")
        obfs_type = p("obfs")
        if obfs_type:
            d["obfs"] = obfs_type
            d["obfs_password"] = p("obfs-password", p("obfsParam"))
        # hysteria2 always has its own TLS — mark tls=True for awareness
        d["tls"] = True
        return d
    except Exception:
        return None


def parse_proxy_link(link: str) -> dict | None:
    """
    Parse a proxy share link and return a unified config dict.
    Returns None if the link is unsupported or malformed.
    """
    if not link:
        return None
    link = link.strip()

    lower = link.lower()
    if lower.startswith("vmess://"):
        return _parse_vmess(link)
    elif lower.startswith("vless://"):
        return _parse_vless(link)
    elif lower.startswith("trojan://"):
        return _parse_trojan(link)
    elif lower.startswith("ss://"):
        return _parse_ss(link)
    elif lower.startswith("hysteria2://") or lower.startswith("hy2://"):
        return _parse_hysteria2(link)
    return None


if __name__ == "__main__":
    # Quick self-test
    test_links = [
        # VMess
        'vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJhaWQiOiIwIiwiYWxwbiI6IiIsImZwIjoiIiwiaG9zdCI6IiIsImlkIjoiMTIyMzQ1Njc4OSIsIm5ldCI6InRjcCIsInBhdGgiOiIiLCJwb3J0IjoiNDQzIiwicHMiOiJ2bWVzcyIsInNjeSI6ImF1dG8iLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoibm9uZSIsInYiOiIyIn0=',
        # VLESS
        'vless://12345678-1234-1234-1234-123456789012@127.0.0.1:443?type=ws&path=%2Fpath&host=example.com&security=tls&sni=example.com#test',
        # Trojan
        'trojan://mypassword@127.0.0.1:443?sni=example.com&security=tls#myserver',
        # SS
        'ss://YWVzLTI1Ni1nY206bWV0YUAxMjcuMC4wLjE6NDQz#home',
        # Hysteria2
        'hysteria2://mypassword@127.0.0.1:443?sni=example.com&insecure=1#hy2test',
        # hy2 alias
        'hy2://pass123@1.2.3.4:8443?obfs=salamander&obfs-password=secret',
    ]
    for link in test_links:
        result = parse_proxy_link(link)
        print(f"\n{'='*60}")
        print(f"Link: {link[:60]}...")
        print(f"Result: {result}")
