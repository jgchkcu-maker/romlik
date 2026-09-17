#!/usr/bin/env python3
import base64
import json
import os
import socket
import urllib.parse
import urllib.request
from pathlib import Path

from server_identity import server_identity

FAST_BADGE_COUNT = int(os.environ.get("FAST_BADGE_COUNT", "5"))
WHITELIST_LIMIT = int(os.environ.get("WHITELIST_LIMIT", "40"))
HAPP_TOTAL_LIMIT = int(os.environ.get("HAPP_TOTAL_LIMIT", "100"))
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

    return {host: ip_geo.get(ip, ("", "")) for host, ip in host_to_ip.items()}


def logical_id(node) -> str:
    return server_identity(
        str(node.get("uri", "")),
        str(node.get("protocol", "")),
        str(node.get("host", "")),
        int(node.get("port") or 0),
    )


def dedupe_nodes(nodes):
    """Keep the best-scoring config for every logical backend."""
    best = {}
    for node in nodes:
        ident = logical_id(node)
        cur = best.get(ident)
        score = float(node.get("score") or 0)
        mbps = float(node.get("mbps") or 0)
        if cur is None or (score, mbps) > (
            float(cur.get("score") or 0),
            float(cur.get("mbps") or 0),
        ):
            best[ident] = node
    out = list(best.values())
    out.sort(
        key=lambda n: (
            float(n.get("score") or 0),
            float(n.get("mbps") or 0),
            -float(n.get("latency_ms") or 999999),
        ),
        reverse=True,
    )
    return out


def label_for(node, pool, rank, geo):
    code, country = geo.get(str(node.get("host", "")), ("", ""))
    badge = "⚡ " if rank <= FAST_BADGE_COUNT else ""
    f = flag(code)
    country = country or "Server"
    suffix = f" • {rank:02d}"
    if pool == "whitelist":
        return f"{badge}{f} Белые списки • {country}{suffix}"
    return f"{badge}{f} {country}{suffix}"


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


def happ_text(title: str, lines) -> str:
    text = "\n".join(lines) + ("\n" if lines else "")
    return (
        f"#profile-title: {title}\n"
        "#profile-update-interval: 5\n"
        "#subscription-auto-update-open-enable: 1\n"
        + text
    )


def write_preserving(path: Path, title: str, lines):
    if lines:
        path.write_text(happ_text(title, lines))
    elif not path.exists():
        path.write_text(happ_text(title, lines))


def main():
    all_nodes = []
    pool_nodes = {}
    raw_counts = {}
    for pool in POOLS:
        path = Path(f"out/{pool}.json")
        try:
            nodes = json.loads(path.read_text())
        except Exception:
            nodes = []
        raw_counts[pool] = len(nodes)
        nodes = dedupe_nodes(nodes)
        if pool == "whitelist":
            nodes = nodes[:WHITELIST_LIMIT]
        pool_nodes[pool] = nodes
        all_nodes.extend(nodes)

    geo = geo_lookup(all_nodes)
    records_by_pool = {"normal": [], "whitelist": []}

    for pool in POOLS:
        nodes = pool_nodes[pool]
        decorated = []
        for rank, node in enumerate(nodes, 1):
            ident = logical_id(node)
            label = label_for(node, pool, rank, geo)
            code, country = geo.get(str(node.get("host", "")), ("", ""))
            node["display_name"] = label
            node["country_code"] = code
            node["country"] = country
            node["server_identity"] = ident
            uri = rewrite_uri(str(node.get("uri", "")), label)
            decorated.append(uri)
            records_by_pool[pool].append({
                "identity": ident,
                "uri": uri,
                "node": node,
                "score": float(node.get("score") or 0),
                "mbps": float(node.get("mbps") or 0),
            })

        text = "\n".join(decorated) + ("\n" if decorated else "")
        Path(f"out/{pool}.txt").write_text(text)
        Path(f"out/{pool}.b64").write_text(base64.b64encode(text.encode()).decode())
        Path(f"out/{pool}.json").write_text(json.dumps(nodes, ensure_ascii=False, indent=2))

        title = "Romlik White Lists" if pool == "whitelist" else "Romlik Fast VPN"
        write_preserving(Path(f"out/happ-{pool}.txt"), title, decorated)
        print(
            pool,
            "raw_working", raw_counts[pool],
            "unique_real", len(nodes),
            flush=True,
        )

    whitelist = records_by_pool["whitelist"][:WHITELIST_LIMIT]
    normal_slots = max(0, HAPP_TOTAL_LIMIT - len(whitelist))
    normal = records_by_pool["normal"][:normal_slots]
    combined = whitelist + normal
    combined.sort(key=lambda x: (x["score"], x["mbps"]), reverse=True)
    combined = combined[:HAPP_TOTAL_LIMIT]
    combined_uris = [x["uri"] for x in combined]

    write_preserving(
        Path("out/happ.txt"),
        "Romlik • Fast + White Lists",
        combined_uris,
    )

    real_servers = []
    for item in combined:
        n = item["node"]
        real_servers.append({
            "identity": item["identity"][:16],
            "pool": n.get("pool", ""),
            "protocol": n.get("protocol", ""),
            "display_name": n.get("display_name", ""),
            "country": n.get("country", ""),
            "host": n.get("host", ""),
            "port": n.get("port", 0),
            "mbps": n.get("mbps"),
            "latency_ms": n.get("latency_ms"),
            "score": n.get("score"),
            "source": n.get("source", ""),
        })
    Path("out/real-servers.json").write_text(
        json.dumps(real_servers, ensure_ascii=False, indent=2)
    )

    print(
        "happ combined real_unique", len(combined),
        "normal", len(normal),
        "whitelist", len(whitelist),
        flush=True,
    )


if __name__ == "__main__":
    main()
