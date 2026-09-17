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


def server_identity(uri: str, protocol: str = "", fallback_host: str = "", fallback_port: int = 0) -> str:
    """Return a logical backend identity, collapsing CDN edge-IP variants.

    This intentionally treats configs with the same credentials + logical
    SNI/Host/path as one real server even when the Cloudflare edge IP/port differs.
    Direct endpoints keep host:port in the identity.
    """
    protocol = (protocol or uri.split(":", 1)[0]).lower()
    try:
        if protocol == "vmess" or uri.startswith("vmess://"):
            d = json.loads(_b64decode(uri[8:].split("#", 1)[0]))
            addr = str(d.get("add", fallback_host) or fallback_host)
            port = int(d.get("port", fallback_port) or fallback_port or 0)
            host_hdr = str(d.get("host", "") or "")
            sni = str(d.get("sni", "") or "")
            logical = host_hdr or sni or addr
            direct = not host_hdr and not sni
            return _digest((
                "vmess", d.get("id", ""), d.get("net", "tcp"), d.get("tls", "none"),
                logical, d.get("path", ""), port if direct else "", d.get("aid", 0),
            ))

        if protocol in ("vless", "trojan") or uri.startswith(("vless://", "trojan://")):
            p, q = _query(uri)
            user = urllib.parse.unquote(p.username or "")
            host = p.hostname or fallback_host
            port = p.port or fallback_port or 0
            host_hdr = q.get("host", "")
            sni = q.get("sni", "") or q.get("serverName", "")
            logical = host_hdr or sni or host
            direct = not host_hdr and not sni
            return _digest((
                protocol, user, q.get("type", "tcp"), q.get("security", "none"),
                logical, q.get("path", ""), q.get("serviceName", "") or q.get("service", ""),
                q.get("pbk", ""), q.get("sid", ""), q.get("flow", ""),
                port if direct else "",
            ))

        if protocol == "ss" or uri.startswith("ss://"):
            p = urllib.parse.urlparse(uri)
            if p.hostname and p.port:
                creds = urllib.parse.unquote(p.username or "")
                decoded = _b64decode(creds)
                if decoded:
                    creds = decoded
                return _digest(("ss", creds, p.hostname, p.port))
            raw = uri[5:].split("#", 1)[0].split("?", 1)[0]
            decoded = _b64decode(raw)
            return _digest(("ss", decoded or raw, fallback_host, fallback_port))
    except Exception:
        pass

    base = uri.split("#", 1)[0]
    return _digest((protocol, base, fallback_host, fallback_port))
