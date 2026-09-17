#!/usr/bin/env python3
import json
import subprocess
import time
from collections import Counter
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


def read_json_list(path: str):
    try:
        data = json.loads(Path(path).read_text(errors="ignore"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


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


def validate_visible_records(
    records,
    expected_count=None,
    total_limit=TOTAL_LIMIT,
    whitelist_limit=WHITELIST_LIMIT,
):
    """Validate the exact logical servers exposed through the combined feed."""
    records = list(records or [])
    identities = [str(r.get("identity") or "").strip() for r in records]
    identity_counts = Counter(i for i in identities if i)
    duplicates = sorted(i for i, count in identity_counts.items() if count > 1)

    visible = len(records)
    unique = len(identity_counts)
    whitelist = sum(1 for r in records if r.get("pool") == "whitelist")
    mobile = sum(1 for r in records if bool(r.get("mobile_candidate")))
    normal = visible - whitelist

    errors = []
    if duplicates:
        errors.append(
            f"Visible subscription has duplicate logical identities: {len(duplicates)}"
        )
    missing = sum(1 for i in identities if not i)
    if missing:
        errors.append(f"Visible server records contain {missing} missing identities")
    if visible > total_limit:
        errors.append(
            f"Visible subscription has {visible} servers; limit is {total_limit}"
        )
    if whitelist > whitelist_limit:
        errors.append(
            f"Visible whitelist has {whitelist} servers; limit is {whitelist_limit}"
        )
    if expected_count is not None and visible != int(expected_count):
        errors.append(
            f"Visible record count mismatch: happ={int(expected_count)} real_servers={visible}"
        )

    return {
        "visible": visible,
        "unique": unique,
        "normal": normal,
        "whitelist": whitelist,
        "mobile": mobile,
        "duplicates": duplicates,
        "missing_identities": missing,
        "errors": errors,
    }


def emit(kind: str, message: str):
    print(f"::{kind}::{message}", flush=True)


def main():
    combined = read_lines("out/happ.txt")
    normal_pool = read_lines("out/normal.txt")
    whitelist_pool = read_lines("out/whitelist.txt")
    visible_records = read_json_list("out/real-servers.json")
    prev_combined = previous_lines("out/happ.txt")
    prev_whitelist = previous_lines("out/happ-whitelist.txt")

    visible = validate_visible_records(
        visible_records,
        expected_count=len(combined),
        total_limit=TOTAL_LIMIT,
        whitelist_limit=WHITELIST_LIMIT,
    )

    flagged = sum("%F0%9F%87" in line or "🇦" <= line[-1:] <= "🇿" for line in combined)
    lightning = sum("%E2%9A%A1" in line or "⚡" in line for line in combined)

    warnings = []
    errors = list(visible["errors"])

    if not combined:
        errors.append("Combined HAPP subscription is empty")
    if len(combined) > TOTAL_LIMIT:
        errors.append(f"Combined subscription has {len(combined)} servers; limit is {TOTAL_LIMIT}")
    if len(whitelist_pool) > WHITELIST_LIMIT:
        errors.append(f"Whitelist pool has {len(whitelist_pool)} servers; limit is {WHITELIST_LIMIT}")

    if len(combined) < 20:
        warnings.append(f"Combined subscription is small: {len(combined)} servers")
    if not whitelist_pool:
        warnings.append("Current scan found 0 whitelist servers")

    if prev_combined and len(combined) < max(5, int(len(prev_combined) * 0.5)):
        warnings.append(
            f"Sharp combined-list drop: {len(prev_combined)} -> {len(combined)}"
        )
    if prev_whitelist and len(whitelist_pool) < int(len(prev_whitelist) * 0.25):
        warnings.append(
            f"Sharp whitelist drop: {len(prev_whitelist)} -> {len(whitelist_pool)}"
        )

    for message in warnings:
        emit("warning", message)
    for message in errors:
        emit("error", message)

    health = {
        "checked_at": int(time.time()),
        "status": "error" if errors else ("warning" if warnings else "healthy"),
        "combined": len(combined),
        "normal": visible["normal"],
        "whitelist": visible["whitelist"],
        "mobile": visible["mobile"],
        "unique_identities": visible["unique"],
        "duplicate_identities": visible["duplicates"],
        "candidate_pools": {
            "normal": len(normal_pool),
            "whitelist": len(whitelist_pool),
        },
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
        "unique", visible["unique"],
        "normal", visible["normal"],
        "whitelist", visible["whitelist"],
        "mobile", visible["mobile"],
        flush=True,
    )

    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
