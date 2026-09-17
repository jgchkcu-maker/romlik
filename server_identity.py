#!/usr/bin/env python3
import base64
import hashlib
import json
import urllib.parse


def _b64decode(s: str) -> str:
    s = (s or "").strip()
    s += "=" * ((4 - len(s) % 4) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(s).decode("utf-8", "ignore")
        except Exception:
            pass
    return ""


def _query(uri: str):
    p = urllib.parse.urlparse(uri)
    q = {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(p.query.replace("&amp;", "&")).items()}
    return p, q


def _digest(parts) -> str:
    raw = "\x1f".join(str(x or "").strip().lower() for x in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def _clean_host(value: str) -> str:
    return (value or "").strip().strip("[]").lower().rstrip(".")


def server_identity(uri: str, protocol: str = "", fallback_host: str = "", fallback_port: int = 0) -> str:
    """Identify the real backend rather than an account/config variant.

    Direct proxies collapse to protocol + host:port regardless of UUID/password,
    fingerprint or transport spelling. CDN-style WS/gRPC/xHTTP configs collapse
    by their logical Host/SNI + path/service so different edge IPs are one backend.
    Reality always uses the direct host:port because its SNI is only a camouflage
    target and must not merge unrelated servers.
    """
    protocol = (protocol or uri.split(":", 1)[0]).lower()
    try:
        if protocol == "vmess" or uri.startswith("vmess://"):
            d = json.loads(_b64decode(uri[8:].split("#", 1)[0]))
            addr = _clean_host(str(d.get("add", fallback_host) or fallback_host))
            port = int(d.get("port", fallback_port) or fallback_port or 0)
            host_hdr = _clean_host(str(d.get("host", "") or ""))
            net = str(d.get("net", "tcp") or "tcp").lower()
            path = str(d.get("path", "") or "")

            if host_hdr and host_hdr != addr and net in ("ws", "grpc", "xhttp", "h2", "http"):
                return _digest(("backend", protocol, "cdn", host_hdr, net, path))
            return _digest(("backend", protocol, "direct", addr, port))

        if protocol in ("vless", "trojan") or uri.startswith(("vless://", "trojan://")):
            p, q = _query(uri)
            host = _clean_host(p.hostname or fallback_host)
            port = p.port or fallback_port or 0
            net = (q.get("type", "tcp") or "tcp").lower()
            security = (q.get("security", "none") or "none").lower()
            host_hdr = _clean_host(q.get("host", ""))
            sni = _clean_host(q.get("sni", "") or q.get("serverName", ""))
            path = q.get("path", "")
            service = q.get("serviceName", "") or q.get("service", "")

            if security == "reality":
                return _digest(("backend", protocol, "direct", host, port))

            if host_hdr and host_hdr != host and net in ("ws", "grpc", "xhttp", "h2", "http"):
                return _digest(("backend", protocol, "cdn", host_hdr, net, path, service))

            if not host_hdr and sni and sni != host and net in ("ws", "grpc", "xhttp", "h2", "http"):
                return _digest(("backend", protocol, "cdn", sni, net, path, service))

            return _digest(("backend", protocol, "direct", host, port))

        if protocol == "ss" or uri.startswith("ss://"):
            p = urllib.parse.urlparse(uri)
            host = _clean_host(p.hostname or fallback_host)
            port = p.port or fallback_port or 0
            if host and port:
                return _digest(("backend", "ss", host, port))
            return _digest(("backend", "ss", fallback_host, fallback_port))
    except Exception:
        pass

    return _digest(("backend", protocol, fallback_host, fallback_port, uri.split("#", 1)[0]))
