#!/usr/bin/env python3
import ipaddress
from collections import defaultdict

from server_identity import server_identity


def logical_id(node: dict) -> str:
    existing = str(node.get("server_identity") or "")
    if existing:
        return existing
    return server_identity(
        str(node.get("uri", "")),
        str(node.get("protocol", "")),
        str(node.get("host", "")),
        int(node.get("port") or 0),
    )


def _quality(node: dict):
    score = float(node.get("score") or 0)
    mbps = float(node.get("mbps") or 0)
    latency = float(node.get("latency_ms") or 999999)
    return score, mbps, -latency


def _network_bucket(node: dict) -> str:
    host = str(node.get("host", "")).strip().strip("[]")
    try:
        ip = ipaddress.ip_address(host)
        prefix = 24 if ip.version == 4 else 48
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return host.lower() or "unknown"


def _dedupe_best(nodes, *, prefer_mobile=False):
    best = {}
    for node in nodes:
        ident = logical_id(node)
        cur = best.get(ident)
        rank = ((1 if node.get("mobile_candidate") else 0), *_quality(node)) if prefer_mobile else _quality(node)
        if cur is None:
            best[ident] = node
            continue
        cur_rank = ((1 if cur.get("mobile_candidate") else 0), *_quality(cur)) if prefer_mobile else _quality(cur)
        if rank > cur_rank:
            best[ident] = node
    return list(best.values())


def _diverse_pick(nodes, limit, *, per_network_limit=4, per_source_limit=20, prefer_mobile=False):
    if limit <= 0:
        return []

    def rank(node):
        mobile = 1 if prefer_mobile and node.get("mobile_candidate") else 0
        return (mobile, *_quality(node))

    ordered = sorted(nodes, key=rank, reverse=True)
    selected = []
    selected_ids = set()
    network_counts = defaultdict(int)
    source_counts = defaultdict(int)

    # First pass: favor different networks and sources so a single provider or
    # /24 cannot occupy the entire visible subscription.
    for node in ordered:
        if len(selected) >= limit:
            break
        ident = logical_id(node)
        if ident in selected_ids:
            continue
        network = _network_bucket(node)
        source = str(node.get("source", "") or "unknown")
        if network_counts[network] >= per_network_limit:
            continue
        if source_counts[source] >= per_source_limit:
            continue
        selected.append(node)
        selected_ids.add(ident)
        network_counts[network] += 1
        source_counts[source] += 1

    # Second pass: if the diverse pool is too small, relax the diversity caps
    # rather than publishing fewer candidates than are actually available.
    if len(selected) < limit:
        for node in ordered:
            if len(selected) >= limit:
                break
            ident = logical_id(node)
            if ident in selected_ids:
                continue
            selected.append(node)
            selected_ids.add(ident)

    return selected


def select_candidates(normal, whitelist, mobile, total_limit=100, whitelist_limit=40):
    """Return one representative per logical backend with diversity-first ordering.

    Mobile whitelist entries are allowed without Azure metrics. Whitelist/mobile
    candidates consume at most ``whitelist_limit`` slots; normal candidates fill
    the rest. A final identity check prevents the same logical cluster from
    appearing in both pools.
    """
    total_limit = max(0, int(total_limit))
    whitelist_limit = max(0, min(int(whitelist_limit), total_limit))

    white_unique = _dedupe_best(list(mobile) + list(whitelist), prefer_mobile=True)
    white_selected = _diverse_pick(
        white_unique,
        whitelist_limit,
        prefer_mobile=True,
    )

    used = {logical_id(x) for x in white_selected}
    normal_unique = [
        x for x in _dedupe_best(normal)
        if logical_id(x) not in used
    ]
    normal_selected = _diverse_pick(normal_unique, total_limit - len(white_selected))

    return white_selected + normal_selected
