#!/usr/bin/env python3
import asyncio
import base64
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

UA = "romlik-speed-selector/2.0"
PROTOS = ("vless://", "vmess://", "trojan://", "ss://")
TEST_URL = os.environ.get("SPEED_TEST_URL", "https://speed.cloudflare.com/__down?bytes=1500000")
TOP_N = int(os.environ.get("TOP_N", "20"))
SOURCE_LIMIT = int(os.environ.get("SOURCE_LIMIT", "500"))
FETCH_WORKERS = int(os.environ.get("FETCH_WORKERS", "8"))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "12"))
TCP_TIMEOUT = float(os.environ.get("TCP_TIMEOUT", "1.25"))
TCP_KEEP = int(os.environ.get("TCP_KEEP", "100"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "350"))
XRAY_TEST_KEEP = int(os.environ.get("XRAY_TEST_KEEP", "40"))
XRAY_BATCH = int(os.environ.get("XRAY_BATCH", "16"))
SPEED_TIMEOUT = float(os.environ.get("SPEED_TIMEOUT", "6"))
ROTATION_SECONDS = int(os.environ.get("ROTATION_SECONDS", "300"))


@dataclass
class Node:
    uri: str
    protocol: str
    host: str
    port: int
    source: str
    pool: str
    remark: str = ""
    tcp_ms: Optional[float] = None
    latency_ms: Optional[float] = None
    mbps: Optional[float] = None
    score: Optional[float] = None
    ok: bool = False
    error: str = ""

    def key(self):
        raw = self.uri.split("#", 1)[0]
        return hashlib.sha256(raw.encode()).hexdigest()


def log(*args):
    print(*args, flush=True)


def b64decode(s: str) -> str:
    s = s.strip().replace("\n", "").replace("\r", "")
    s += "=" * ((4 - len(s) % 4) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(s).decode("utf-8", "ignore")
        except Exception:
            pass
    return ""


def parse_uri(uri, source, pool):
    uri = uri.strip()
    try:
        if uri.startswith("vmess://"):
            d = json.loads(b64decode(uri[8:].split("#")[0]))
            return Node(uri, "vmess", str(d.get("add", "")), int(d.get("port", 0)), source, pool, str(d.get("ps", "")))
        p = urllib.parse.urlparse(uri)
        if p.scheme in ("vless", "trojan") and p.hostname and p.port:
            return Node(uri, p.scheme, p.hostname, p.port, source, pool, urllib.parse.unquote(p.fragment or ""))
        if p.scheme == "ss":
            if p.hostname and p.port:
                return Node(uri, "ss", p.hostname, p.port, source, pool, urllib.parse.unquote(p.fragment or ""))
            raw = uri[5:].split("#")[0]
            dec = b64decode(raw)
            if "@" in dec:
                hp = dec.rsplit("@", 1)[1]
                h, po = hp.rsplit(":", 1)
                return Node(uri, "ss", h, int(po), source, pool)
    except Exception:
        return None
    return None


def rotate_lines(lines, source, limit):
    if limit <= 0 or len(lines) <= limit:
        return lines
    slot = int(time.time() // max(60, ROTATION_SECONDS))
    source_offset = int(hashlib.sha256(source.encode()).hexdigest()[:8], 16)
    start = (slot * limit + source_offset) % len(lines)
    end = start + limit
    if end <= len(lines):
        return lines[start:end]
    return lines[start:] + lines[: end - len(lines)]


def extract(text, source, pool):
    if not any(x in text for x in PROTOS):
        decoded = b64decode(text)
        if any(x in decoded for x in PROTOS):
            text = decoded
    lines = [x.strip() for x in re.split(r"[\r\n]+", text) if x.strip()]
    candidates = [x for x in lines if x.startswith(PROTOS)]
    sampled = rotate_lines(candidates, source, SOURCE_LIMIT)
    out = []
    for line in sampled:
        n = parse_uri(line, source, pool)
        if n and n.host and n.port:
            out.append(n)
    return out, len(candidates)


def fetch(url, timeout=FETCH_TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def load_one(src, pool):
    try:
        text = fetch(src["url"])
        nodes, raw_count = extract(text, src["name"], pool)
        return src["name"], pool, nodes, raw_count, None
    except Exception as e:
        return src["name"], pool, [], 0, f"{type(e).__name__}: {e}"


def load_sources():
    cfg = json.loads(Path("sources.json").read_text())
    jobs = [(src, pool) for pool in ("normal", "whitelist") for src in cfg.get(pool, [])]
    nodes = []
    stats = {"sources": {}, "raw_seen": 0, "sampled": 0}
    with concurrent.futures.ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futures = [ex.submit(load_one, src, pool) for src, pool in jobs]
        for fut in concurrent.futures.as_completed(futures):
            name, pool, got, raw_count, err = fut.result()
            stats["sources"][name] = {"pool": pool, "raw": raw_count, "sampled": len(got), "error": err}
            stats["raw_seen"] += raw_count
            stats["sampled"] += len(got)
            if err:
                log(f"source {name}: FAILED {err}")
            else:
                log(f"source {name}: raw={raw_count} sampled={len(got)}")
                nodes.extend(got)
    ded = {}
    for n in nodes:
        ded.setdefault((n.pool, n.key()), n)
    result = list(ded.values())
    stats["unique_sampled"] = len(result)
    return result, stats


async def tcp_probe(n, sem):
    async with sem:
        st = time.perf_counter()
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(n.host, n.port), TCP_TIMEOUT)
            n.tcp_ms = (time.perf_counter() - st) * 1000
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return True
        except Exception as e:
            n.error = f"tcp:{type(e).__name__}"
            return False


def qdict(uri):
    p = urllib.parse.urlparse(uri)
    return p, {k: (v[0] if v else "") for k, v in urllib.parse.parse_qs(p.query.replace("&amp;", "&")).items()}


def stream_settings(q):
    net = q.get("type", "tcp") or "tcp"
    sec = q.get("security", "none") or "none"
    s = {"network": net, "security": sec}
    if sec == "tls":
        s["tlsSettings"] = {"serverName": q.get("sni") or q.get("serverName") or "", "allowInsecure": True}
    elif sec == "reality":
        s["realitySettings"] = {
            "serverName": q.get("sni", ""),
            "fingerprint": q.get("fp", "chrome"),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", "") or "/",
        }
    if net == "ws":
        s["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", "")}}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": q.get("serviceName") or q.get("service") or ""}
    elif net == "xhttp":
        s["xhttpSettings"] = {"path": q.get("path", "/"), "host": q.get("host", "") or None}
        if s["xhttpSettings"]["host"] is None:
            s["xhttpSettings"].pop("host")
    return s


def outbound(n):
    if n.protocol in ("vless", "trojan"):
        p, q = qdict(n.uri)
        if n.protocol == "vless":
            user = {"id": urllib.parse.unquote(p.username or ""), "encryption": q.get("encryption", "none") or "none"}
            if q.get("flow"):
                user["flow"] = q["flow"]
            settings = {"vnext": [{"address": p.hostname, "port": p.port, "users": [user]}]}
        else:
            settings = {"servers": [{"address": p.hostname, "port": p.port, "password": urllib.parse.unquote(p.username or "")}]} 
        return {"protocol": n.protocol, "settings": settings, "streamSettings": stream_settings(q)}
    if n.protocol == "vmess":
        d = json.loads(b64decode(n.uri[8:].split("#")[0]))
        user = {"id": str(d.get("id", "")), "alterId": int(d.get("aid", 0) or 0), "security": d.get("scy", "auto") or "auto"}
        q = {
            "type": d.get("net", "tcp"),
            "security": d.get("tls", "none"),
            "sni": d.get("sni", ""),
            "host": d.get("host", ""),
            "path": d.get("path", "/"),
        }
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": str(d.get("add", "")), "port": int(d.get("port", 0)), "users": [user]}]},
            "streamSettings": stream_settings(q),
        }
    if n.protocol == "ss":
        p = urllib.parse.urlparse(n.uri)
        if p.hostname and p.port and p.username:
            user = urllib.parse.unquote(p.username)
            dec = b64decode(user)
            if ":" in dec:
                user = dec
            method, password = user.split(":", 1)
            return {"protocol": "shadowsocks", "settings": {"servers": [{"address": p.hostname, "port": p.port, "method": method, "password": password}]}}
    raise ValueError("unsupported")


def test_with_xray(n, idx):
    port = 20000 + (idx % 20000)
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [outbound(n)],
    }
    with tempfile.TemporaryDirectory() as td:
        fp = Path(td) / "x.json"
        fp.write_text(json.dumps(cfg))
        proc = subprocess.Popen(["xray", "run", "-c", str(fp)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.15)
            cmd = [
                "curl", "-L", "--silent", "--show-error", "--fail",
                "--max-time", str(SPEED_TIMEOUT), "--connect-timeout", "2.5",
                "--socks5-hostname", f"127.0.0.1:{port}", "-o", os.devnull,
                "-w", "%{time_starttransfer} %{speed_download}", TEST_URL,
            ]
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=SPEED_TIMEOUT + 2)
            if cp.returncode != 0:
                raise RuntimeError(cp.stderr.strip()[:120])
            ttfb, spd = cp.stdout.strip().split()[:2]
            n.latency_ms = float(ttfb) * 1000
            n.mbps = float(spd) * 8 / 1_000_000
            n.score = round(n.mbps / (1.0 + n.latency_ms / 600.0), 3)
            n.ok = n.mbps >= 0.1
            return n.ok
        except Exception as e:
            n.error = f"xray:{type(e).__name__}"
            return False
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=0.8)
            except Exception:
                proc.kill()


def decorate(n, rank):
    p = urllib.parse.urlsplit(n.uri)
    label = f"#{rank:02d} {n.pool} | {n.mbps:.1f}Mbps | {n.latency_ms:.0f}ms | {n.source}"
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, p.query, urllib.parse.quote(label, safe=" |:.#"))) if p.scheme != "vmess" else n.uri


def save(nodes, source_stats, started_at):
    Path("out").mkdir(exist_ok=True)
    pool_stats = {}
    for pool in ("normal", "whitelist"):
        arr = [n for n in nodes if n.ok and n.pool == pool]
        arr.sort(key=lambda x: (x.score or 0, x.mbps or 0, -(x.latency_ms or 9999)), reverse=True)
        pool_stats[pool] = {"working_tested": len(arr)}
        arr = arr[:TOP_N]
        uris = [decorate(n, i + 1) for i, n in enumerate(arr)]
        Path(f"out/{pool}.txt").write_text("\n".join(uris) + ("\n" if uris else ""))
        Path(f"out/{pool}.b64").write_text(base64.b64encode(("\n".join(uris) + ("\n" if uris else "")).encode()).decode())
        Path(f"out/{pool}.json").write_text(json.dumps([asdict(n) for n in arr], ensure_ascii=False, indent=2))
    all_ok = [n for n in nodes if n.ok]
    all_ok.sort(key=lambda x: (x.score or 0, x.mbps or 0), reverse=True)
    status = {
        "updated_at": int(time.time()),
        "duration_sec": round(time.time() - started_at, 2),
        "source_stats": source_stats,
        "pool_stats": pool_stats,
        "xray_tested": len(nodes),
        "working": len(all_ok),
        "top": [asdict(n) for n in all_ok[:30]],
    }
    Path("out/status.json").write_text(json.dumps(status, ensure_ascii=False, indent=2))


async def main():
    started_at = time.time()
    nodes, source_stats = load_sources()
    log("unique sampled", len(nodes), "raw advertised", source_stats["raw_seen"])

    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [asyncio.create_task(tcp_probe(n, sem)) for n in nodes]
    rs = await asyncio.gather(*tasks)
    good = [n for n, ok in zip(nodes, rs) if ok]
    log("tcp alive", len(good), "/", len(nodes))

    tested = []
    for pool in ("normal", "whitelist"):
        pool_good = sorted((n for n in good if n.pool == pool), key=lambda n: n.tcp_ms or 999999)[:TCP_KEEP]
        subset = pool_good[:XRAY_TEST_KEEP]
        log(pool, "xray candidates", len(subset))
        for i in range(0, len(subset), XRAY_BATCH):
            batch = subset[i:i + XRAY_BATCH]
            base = 0 if pool == "normal" else 10000
            await asyncio.gather(*[
                asyncio.to_thread(test_with_xray, n, base + i + j)
                for j, n in enumerate(batch)
            ])
            tested.extend(batch)
            log(pool, min(i + len(batch), len(subset)), "/", len(subset), "working", sum(1 for n in tested if n.ok and n.pool == pool))

    save(tested, source_stats, started_at)
    log("DONE", "working", sum(1 for n in tested if n.ok), "duration_sec", round(time.time() - started_at, 2))


if __name__ == "__main__":
    asyncio.run(main())
