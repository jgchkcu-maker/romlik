#!/usr/bin/env python3
import base64
import json
import os
import socket
import urllib.parse
import urllib.request
from pathlib import Path

FAST_BADGE_COUNT = int(os.environ.get("FAST_BADGE_COUNT", "5"))
POOLS = ("normal", "whitelist")


def flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in code)


def resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


def geo_lookup(nodes):
    ips = []
    seen = set()
    host_to_ip = {}
    for node in nodes:
        host = str(node.get("host", ""))
        if not host:
            continue
        ip = resolve(host)
        host_to_ip[host] = ip
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)

    ip_geo = {}
    for start in range(0, len(ips), 100):
        batch = ips[start:start + 100]
        body = json.dumps([
            {"query": ip, "fields": "status,country,countryCode,query"}
            for ip in batch
        ]).encode()
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "romlik/geo-labels"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                rows = json.loads(r.read().decode("utf-8", "ignore"))
            for row in rows:
                if row.get("status") == "success":
                    ip_geo[row.get("query", "")] = (row.get("countryCode", ""), row.get("country", ""))
        except Exception as e:
            print("geo batch failed:", type(e).__name__, e, flush=True)

    result = {}
    for host, ip in host_to_ip.items():
        result[host] = ip_geo.get(ip, ("", ""))
    return result


def label_for(node, pool, rank, geo):
    code, country = geo.get(str(node.get("host", "")), ("", ""))
    badge = "⚡ " if rank <= FAST_BADGE_COUNT else ""
    f = flag(code)
    country = country or "Server"
    if pool == "whitelist":
        return f"{badge}{f} Белые списки • {country}"
    return f"{badge}{f} {country}"


def rewrite_uri(uri: str, label: str) -> str:
    if uri.startswith("vmess://"):
        raw = uri[8:].split("#", 1)[0]
        raw += "=" * ((4 - len(raw) % 4) % 4)
        try:
            data = json.loads(base64.urlsafe_b64decode(raw).decode("utf-8", "ignore"))
            data["ps"] = label
            packed = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
            return "vmess://" + base64.b64encode(packed).decode()
        except Exception:
            return uri

    try:
        p = urllib.parse.urlsplit(uri)
        return urllib.parse.urlunsplit((
            p.scheme,
            p.netloc,
            p.path,
            p.query,
            urllib.parse.quote(label, safe=""),
        ))
    except Exception:
        return uri


def happ_text(pool: str, text: str) -> str:
    title = "Romlik White Lists" if pool == "whitelist" else "Romlik Fast VPN"
    return (
        f"#profile-title: {title}\n"
        "#profile-update-interval: 5\n"
        "#subscription-auto-update-open-enable: 1\n"
        + text
    )


def main():
    all_nodes = []
    pool_nodes = {}
    for pool in POOLS:
        path = Path(f"out/{pool}.json")
        try:
            nodes = json.loads(path.read_text())
        except Exception:
            nodes = []
        pool_nodes[pool] = nodes
        all_nodes.extend(nodes)

    geo = geo_lookup(all_nodes)

    for pool in POOLS:
        nodes = pool_nodes[pool]
        decorated = []
        for rank, node in enumerate(nodes, 1):
            label = label_for(node, pool, rank, geo)
            node["display_name"] = label
            node["country_code"] = geo.get(str(node.get("host", "")), ("", ""))[0]
            node["country"] = geo.get(str(node.get("host", "")), ("", ""))[1]
            decorated.append(rewrite_uri(str(node.get("uri", "")), label))

        text = "\n".join(decorated) + ("\n" if decorated else "")
        Path(f"out/{pool}.txt").write_text(text)
        Path(f"out/{pool}.b64").write_text(base64.b64encode(text.encode()).decode())
        Path(f"out/{pool}.json").write_text(json.dumps(nodes, ensure_ascii=False, indent=2))

        # HAPP gets its own plain-text subscription with metadata. If a scan
        # temporarily finds zero servers, keep the previous known-good HAPP file.
        happ_path = Path(f"out/happ-{pool}.txt")
        if decorated:
            happ_path.write_text(happ_text(pool, text))
        elif not happ_path.exists():
            happ_path.write_text(happ_text(pool, text))

        print(pool, "decorated", len(nodes), flush=True)


if __name__ == "__main__":
    main()
