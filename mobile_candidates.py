#!/usr/bin/env python3
import json
import os
import urllib.request
from dataclasses import asdict
from pathlib import Path

import scanner
from server_identity import server_identity

MOBILE_LIMIT = int(os.environ.get("MOBILE_WHITELIST_LIMIT", "40"))
UA = "romlik-mobile-whitelist/1.0"


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", "ignore")


def main():
    cfg = json.loads(Path("sources.json").read_text())
    preferred = [
        src for src in cfg.get("whitelist", [])
        if src.get("name") in {"igareck-mobile", "igareck-cidr-checked", "igareck-cidr-all"}
    ]

    # Prefer the dedicated Russian mobile feed first. Fall back to the checked
    # whitelist feeds only when the mobile feed contains fewer unique backends.
    preferred.sort(key=lambda s: {
        "igareck-mobile": 0,
        "igareck-cidr-checked": 1,
        "igareck-cidr-all": 2,
    }.get(s.get("name"), 99))

    best = {}
    order = []
    source_stats = []

    for src in preferred:
        try:
            text = fetch_text(src["url"])
            nodes, raw_count = scanner.extract(text, src["name"], "whitelist")
            source_stats.append({"name": src["name"], "raw": raw_count, "parsed": len(nodes)})
        except Exception as e:
            source_stats.append({"name": src.get("name", ""), "error": f"{type(e).__name__}: {e}"})
            continue

        for n in nodes:
            ident = server_identity(n.uri, n.protocol, n.host, n.port)
            if ident in best:
                continue
            d = asdict(n)
            d["mobile_candidate"] = True
            d["mobile_source"] = src["name"]
            d["server_identity"] = ident
            # These are intentionally not rejected based on an Azure/Xray test.
            # A whitelist route can be useful only from the target mobile network.
            d["ok"] = True
            d["score"] = None
            d["mbps"] = None
            d["latency_ms"] = None
            best[ident] = d
            order.append(ident)
            if len(order) >= MOBILE_LIMIT:
                break
        if len(order) >= MOBILE_LIMIT:
            break

    out = [best[i] for i in order[:MOBILE_LIMIT]]
    Path("out").mkdir(exist_ok=True)
    Path("out/mobile-whitelist.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
    Path("out/mobile-whitelist-status.json").write_text(json.dumps({
        "count": len(out),
        "limit": MOBILE_LIMIT,
        "sources": source_stats,
        "note": "Candidates are selected from Russian mobile whitelist feeds and are not discarded by Azure reachability tests.",
    }, ensure_ascii=False, indent=2))
    print("mobile whitelist candidates", len(out), "limit", MOBILE_LIMIT, flush=True)


if __name__ == "__main__":
    main()
