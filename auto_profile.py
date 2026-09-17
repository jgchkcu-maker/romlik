#!/usr/bin/env python3
import json
import os
from collections import Counter
from pathlib import Path

import scanner
from server_identity import server_identity

TOTAL_LIMIT = int(os.environ.get("AUTO_TOTAL_LIMIT", "100"))
WHITELIST_LIMIT = int(os.environ.get("AUTO_WHITELIST_LIMIT", "40"))
COUNTRY_LIMIT = int(os.environ.get("AUTO_COUNTRY_LIMIT", "12"))
COUNTRY_HARD_LIMIT = int(os.environ.get("AUTO_COUNTRY_HARD_LIMIT", "20"))
PROBE_URL = os.environ.get("AUTO_PROBE_URL", "https://cp.cloudflare.com/generate_204")
PROBE_INTERVAL = os.environ.get("AUTO_PROBE_INTERVAL", "30s")


def _quality(node):
    return (
        1 if node.get("mobile_candidate") else 0,
        float(node.get("score") or 0),
        float(node.get("mbps") or 0),
        -float(node.get("latency_ms") or 999999),
    )


def _identity(node):
    existing = str(node.get("server_identity") or "")
    if existing:
        return existing
    return server_identity(
        str(node.get("uri", "")),
        str(node.get("protocol", "")),
        str(node.get("host", "")),
        int(node.get("port") or 0),
    )


def _dedupe(nodes):
    best = {}
    for node in nodes:
        ident = _identity(node)
        cur = best.get(ident)
        if cur is None or _quality(node) > _quality(cur):
            best[ident] = node
    return sorted(best.values(), key=_quality, reverse=True)


def _country(node):
    return str(node.get("country_code") or node.get("country") or "ZZ").upper()


def select_country_balanced(
    normal,
    whitelist,
    total_limit=TOTAL_LIMIT,
    per_country_limit=COUNTRY_LIMIT,
    whitelist_limit=WHITELIST_LIMIT,
    hard_country_limit=COUNTRY_HARD_LIMIT,
):
    """Build the hidden AUTO pool without allowing one normal country to dominate.

    Whitelist/mobile nodes are reserved first (up to whitelist_limit). Normal nodes
    are filled in quality order with a progressive country cap. The cap can relax
    from per_country_limit up to hard_country_limit to fill more slots, but never
    past the hard cap.
    """
    total_limit = max(0, int(total_limit))
    whitelist_limit = max(0, min(int(whitelist_limit), total_limit))
    per_country_limit = max(1, int(per_country_limit))
    hard_country_limit = max(per_country_limit, int(hard_country_limit))

    white = _dedupe(whitelist)
    selected = white[:whitelist_limit]
    used = {_identity(n) for n in selected}

    normal_unique = [n for n in _dedupe(normal) if _identity(n) not in used]
    country_counts = Counter()

    caps = [per_country_limit]
    step = 4
    cap = per_country_limit + step
    while cap < hard_country_limit:
        caps.append(cap)
        cap += step
    if caps[-1] != hard_country_limit:
        caps.append(hard_country_limit)

    selected_normal = []
    selected_normal_ids = set()
    for cap in caps:
        for node in normal_unique:
            if len(selected) + len(selected_normal) >= total_limit:
                break
            ident = _identity(node)
            if ident in selected_normal_ids:
                continue
            country = _country(node)
            if country_counts[country] >= cap:
                continue
            selected_normal.append(node)
            selected_normal_ids.add(ident)
            country_counts[country] += 1
        if len(selected) + len(selected_normal) >= total_limit:
            break

    return selected + selected_normal


def _as_node(node):
    return scanner.Node(
        uri=str(node.get("uri", "")),
        protocol=str(node.get("protocol", "")),
        host=str(node.get("host", "")),
        port=int(node.get("port") or 0),
        source=str(node.get("source", "")),
        pool=str(node.get("pool", "normal")),
        remark=str(node.get("display_name") or node.get("remark") or ""),
    )


def build_subscription(nodes):
    outbounds = []
    valid_nodes = []
    for idx, node in enumerate(nodes, 1):
        try:
            outbound = scanner.outbound(_as_node(node))
        except Exception:
            continue
        outbound["tag"] = f"proxy-{idx:03d}"
        outbounds.append(outbound)
        valid_nodes.append(node)

    if not outbounds:
        raise ValueError("AUTO profile has no valid proxy outbounds")

    first_tag = outbounds[0]["tag"]
    cfg = {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": outbounds + [
            {"tag": "direct", "protocol": "freedom", "settings": {}}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "ip": [
                        "127.0.0.0/8",
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "169.254.0.0/16",
                    ],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "auto",
                },
            ],
            "balancers": [
                {
                    "tag": "auto",
                    "selector": ["proxy-"],
                    "fallbackTag": first_tag,
                    "strategy": {"type": "leastPing"},
                }
            ],
        },
        "observatory": {
            "subjectSelector": ["proxy-"],
            "probeURL": PROBE_URL,
            "probeInterval": PROBE_INTERVAL,
            "enableConcurrency": True,
        },
        "remarks": f"⚡ AUTO • {len(outbounds)} servers",
        "meta": {
            "serverDescription": "Local least-ping auto selection",
            "internalServerCount": len(outbounds),
        },
    }
    return [cfg]


def _load(path):
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def main():
    normal = _load("out/normal.json")
    whitelist = _load("out/whitelist.json")
    selected = select_country_balanced(normal, whitelist)
    payload = build_subscription(selected)
    cfg = payload[0]

    Path("out/happ-auto.json").write_text(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    )

    countries = Counter(_country(n) for n in selected if n.get("pool") != "whitelist")
    status = {
        "visible_configs": 1,
        "internal_selected": len(selected),
        "internal_valid_outbounds": sum(
            1 for x in cfg["outbounds"] if str(x.get("tag", "")).startswith("proxy-")
        ),
        "whitelist": sum(1 for n in selected if n.get("pool") == "whitelist"),
        "mobile": sum(1 for n in selected if n.get("mobile_candidate")),
        "normal_country_counts": dict(sorted(countries.items())),
        "normal_country_limit": COUNTRY_LIMIT,
        "normal_country_hard_limit": COUNTRY_HARD_LIMIT,
        "strategy": "leastPing",
        "probe_url": PROBE_URL,
        "probe_interval": PROBE_INTERVAL,
    }
    Path("out/auto-profile-status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2)
    )
    print("AUTO PROFILE", json.dumps(status, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
