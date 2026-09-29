#!/usr/bin/env python3
import asyncio
import copy
import os
import time

import scanner
from server_identity import server_identity


def logical_key(self):
    return server_identity(self.uri, self.protocol, self.host, self.port)


scanner.Node.key = logical_key

TARGET_NORMAL = int(os.environ.get("TARGET_NORMAL", "100"))
TARGET_WHITELIST = int(os.environ.get("TARGET_WHITELIST", "40"))
MAX_XRAY_PER_POOL = int(os.environ.get("MAX_XRAY_PER_POOL", "1200"))
HAPP_PROBE_URL = os.environ.get("HAPP_PROBE_URL", "https://cp.cloudflare.com/generate_204")
HAPP_PROBE_TIMEOUT = float(os.environ.get("HAPP_PROBE_TIMEOUT", "6"))
FULL_TEST_URL = os.environ.get("SPEED_TEST_URL", "https://speed.cloudflare.com/__down?bytes=3000000")
FULL_TIMEOUT = float(os.environ.get("SPEED_TIMEOUT", "12"))


def target_for(pool: str) -> int:
    return TARGET_WHITELIST if pool == "whitelist" else TARGET_NORMAL


async def run_batch(batch, base_idx, test_fn=scanner.test_with_xray):
    await asyncio.gather(*[
        asyncio.to_thread(test_fn, n, base_idx + i)
        for i, n in enumerate(batch)
    ])


async def main():
    started_at = time.time()
    nodes, source_stats = scanner.load_sources()
    scanner.log("logical unique sampled", len(nodes), "raw advertised", source_stats["raw_seen"])

    sem = asyncio.Semaphore(scanner.CONCURRENCY)
    tasks = [asyncio.create_task(scanner.tcp_probe(n, sem)) for n in nodes]
    rs = await asyncio.gather(*tasks)
    good = [n for n, ok in zip(nodes, rs) if ok]
    scanner.log("tcp alive logical", len(good), "/", len(nodes))

    tested = []
    for pool in ("normal", "whitelist"):
        candidates = sorted(
            (n for n in good if n.pool == pool),
            key=lambda n: n.tcp_ms or 999999,
        )[:MAX_XRAY_PER_POOL]
        target = target_for(pool)
        scanner.log(pool, "availability candidates", len(candidates), "target", target)

        working = []
        for i in range(0, len(candidates), scanner.XRAY_BATCH):
            batch = candidates[i:i + scanner.XRAY_BATCH]
            base = 0 if pool == "normal" else 12000
            await asyncio.gather(*[
                asyncio.to_thread(
                    scanner.test_happ_with_xray,
                    n,
                    base + i + j,
                    HAPP_PROBE_URL,
                    HAPP_PROBE_TIMEOUT,
                )
                for j, n in enumerate(batch)
            ])
            tested.extend(batch)
            working.extend(n for n in batch if n.happ_probe_ok)
            scanner.log(
                pool,
                "availability",
                min(i + len(batch), len(candidates)),
                "/",
                len(candidates),
                "working",
                len(working),
            )
            if len(working) >= target:
                break

        # Re-test the best available unique servers with the larger payload for
        # more meaningful ranking. If a full speed retest fails, keep the node
        # as available using its short-test metrics instead of deleting it.
        working.sort(
            key=lambda n: (n.score or 0, n.mbps or 0, -(n.latency_ms or 999999)),
            reverse=True,
        )
        finalists = working[:target]
        scanner.TEST_URL = FULL_TEST_URL
        scanner.SPEED_TIMEOUT = FULL_TIMEOUT
        for i in range(0, len(finalists), scanner.XRAY_BATCH):
            originals = finalists[i:i + scanner.XRAY_BATCH]
            clones = [copy.deepcopy(n) for n in originals]
            base = 6000 if pool == "normal" else 18000
            await run_batch(clones, base + i)
            for original, clone in zip(originals, clones):
                if clone.ok:
                    original.latency_ms = clone.latency_ms
                    original.mbps = clone.mbps
                    original.score = clone.score
                    original.error = clone.error
            scanner.log(
                pool,
                "full-speed",
                min(i + len(originals), len(finalists)),
                "/",
                len(finalists),
            )

    scanner.TEST_URL = FULL_TEST_URL
    scanner.SPEED_TIMEOUT = FULL_TIMEOUT
    scanner.save(tested, source_stats, started_at)
    scanner.log(
        "DONE logical working",
        sum(1 for n in tested if n.ok),
        "duration_sec",
        round(time.time() - started_at, 2),
    )


if __name__ == "__main__":
    asyncio.run(main())
