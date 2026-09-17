#!/usr/bin/env python3
import json
import subprocess
import time
from pathlib import Path

URI_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://")
TOTAL_LIMIT = 100
WHITELIST_LIMIT = 40


def uri_lines(text: str):
    return [line.strip() for line in text.splitlines() if line.strip().startswith(URI_PREFIXES)]


def read_lines(path: str):
    p = Path(path)
    if not p.exists():
        return []
    return uri_lines(p.read_text(errors="ignore"))


def previous_lines(path: str):
    try:
        cp = subprocess.run(
            ["git", "show", f"HEAD:{path}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if cp.returncode == 0:
            return uri_lines(cp.stdout)
    except Exception:
        pass
    return []


def emit(kind: str, message: str):
    print(f"::{kind}::{message}", flush=True)


def main():
    combined = read_lines("out/happ.txt")
    normal = read_lines("out/normal.txt")
    whitelist = read_lines("out/whitelist.txt")
    prev_combined = previous_lines("out/happ.txt")
    prev_whitelist = previous_lines("out/happ-whitelist.txt")

    flagged = sum("%F0%9F%87" in line or "🇦" <= line[-1:] <= "🇿" for line in combined)
    lightning = sum("%E2%9A%A1" in line or "⚡" in line for line in combined)

    warnings = []
    errors = []

    if not combined:
        errors.append("Combined HAPP subscription is empty")
    if len(combined) > TOTAL_LIMIT:
        errors.append(f"Combined subscription has {len(combined)} servers; limit is {TOTAL_LIMIT}")
    if len(whitelist) > WHITELIST_LIMIT:
        errors.append(f"Whitelist has {len(whitelist)} servers; limit is {WHITELIST_LIMIT}")

    if len(combined) < 20:
        warnings.append(f"Combined subscription is small: {len(combined)} servers")
    if not whitelist:
        warnings.append("Current scan found 0 whitelist servers")

    if prev_combined and len(combined) < max(5, int(len(prev_combined) * 0.5)):
        warnings.append(
            f"Sharp combined-list drop: {len(prev_combined)} -> {len(combined)}"
        )
    if prev_whitelist and len(whitelist) < int(len(prev_whitelist) * 0.25):
        warnings.append(
            f"Sharp whitelist drop: {len(prev_whitelist)} -> {len(whitelist)}"
        )

    for message in warnings:
        emit("warning", message)
    for message in errors:
        emit("error", message)

    health = {
        "checked_at": int(time.time()),
        "status": "error" if errors else ("warning" if warnings else "healthy"),
        "combined": len(combined),
        "normal": len(normal),
        "whitelist": len(whitelist),
        "limits": {"combined": TOTAL_LIMIT, "whitelist": WHITELIST_LIMIT},
        "previous": {
            "combined": len(prev_combined),
            "whitelist": len(prev_whitelist),
        },
        "decorations": {
            "lightning_entries": lightning,
            "flagged_entries_approx": flagged,
        },
        "warnings": warnings,
        "errors": errors,
    }
    Path("out/health.json").write_text(json.dumps(health, ensure_ascii=False, indent=2))

    print(
        "HEALTH",
        health["status"],
        "combined", len(combined),
        "normal", len(normal),
        "whitelist", len(whitelist),
        flush=True,
    )

    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
