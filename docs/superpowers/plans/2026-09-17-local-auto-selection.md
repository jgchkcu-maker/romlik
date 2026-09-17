# Local Auto-Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish up to 100 genuinely distinct server groups while letting HAPP measure availability and latency on the phone's current network instead of treating GitHub/Azure ranking as the final truth.

**Architecture:** Keep raw variants long enough to group them into logical backends, collapse repeated Reality/CDN variants into one visible candidate, select a diversity-first pool, and emit HAPP local-proxy-ping metadata in the subscription. GitHub validation remains a coarse health signal; mobile/whitelist candidates are not removed solely because Azure cannot reach them.

**Tech Stack:** Python 3.12 standard library, Xray CLI, GitHub Actions, HAPP standard text subscriptions.

**Spec:** `docs/superpowers/specs/2026-09-17-local-auto-selection-design.md`

## Global Constraints

- Publish at most 100 visible candidates.
- Publish at most 40 mobile/whitelist candidates.
- One logical backend/cluster must appear only once in the visible subscription.
- HAPP must receive local proxy-ping settings in the subscription body.
- Existing `out/happ.txt` URL remains the primary subscription URL.
- GitHub speed/latency is a coarse quality input only, not the final network-specific choice.

---

### Task 1: Logical server grouping

**Files:**
- Modify: `server_identity.py`
- Create: `tests/test_server_identity.py`

**Interfaces:**
- Consumes: VLESS/VMess/Trojan/Shadowsocks URIs.
- Produces: `server_identity(uri, protocol, fallback_host, fallback_port) -> str` where repeated Reality endpoints sharing the same UUID/public key/short-id/SNI/transport identity collapse into one cluster.

- [ ] **Step 1: Write failing grouping tests**

Add tests proving that two VLESS Reality links with the same UUID, public key, short-id, SNI, flow and transport but different endpoint IPs produce the same identity, while links with a different public key or transport service produce different identities.

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m unittest tests.test_server_identity -v`
Expected: at least the same-cluster Reality test fails under the current host:port identity logic.

- [ ] **Step 3: Implement cluster identity**

For Reality VLESS/Trojan, prefer a stable cluster key built from protocol, user credential, public key, short-id, SNI, flow, transport, path/service and port class; fall back to direct host:port only when those identifying fields are absent. Preserve existing CDN host/path grouping for non-Reality transports.

- [ ] **Step 4: Run tests and verify pass**

Run: `python -m unittest tests.test_server_identity -v`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message: `Group repeated proxy variants by logical backend`.

### Task 2: Diversity-first candidate pool

**Files:**
- Create: `candidate_pool.py`
- Create: `tests/test_candidate_pool.py`
- Modify: `decorate_subscription.py`

**Interfaces:**
- Consumes: normal, whitelist and mobile candidate dictionaries containing `uri`, `protocol`, `host`, `port`, `source`, `score`, `mbps`, and `pool`.
- Produces: `select_candidates(normal, whitelist, mobile, total_limit=100, whitelist_limit=40) -> list[dict]` with no duplicate logical identities and caps that prevent one network/provider cluster from dominating.

- [ ] **Step 1: Write failing selection tests**

Cover: duplicate identities collapse; whitelist/mobile never exceed 40; total never exceeds 100; a large block from the same IPv4 /24 is capped before lower-ranked candidates from other networks are exhausted; mobile candidates survive even with missing Azure speed metrics.

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m unittest tests.test_candidate_pool -v`
Expected: FAIL because `candidate_pool.py` does not exist.

- [ ] **Step 3: Implement selection**

Add deterministic grouping, representative choice, /24 IPv4 and /48 IPv6 diversity buckets, source caps, and fallback passes that relax diversity only when required to fill the requested limit. Prefer tested high-quality representatives inside each logical group, but do not require Azure speed for mobile candidates.

- [ ] **Step 4: Integrate publication**

Change `decorate_subscription.py` so `out/happ.txt` is built from `select_candidates(...)` instead of taking the first whitelist and normal rows after Azure ranking. `out/real-servers.json` must record exactly the visible selected candidates and their logical identities.

- [ ] **Step 5: Run tests and verify pass**

Run: `python -m unittest tests.test_candidate_pool tests.test_server_identity -v`
Expected: PASS.

- [ ] **Step 6: Commit**

Commit message: `Select a diverse pool of unique server groups`.

### Task 3: Local HAPP auto-selection metadata

**Files:**
- Modify: `decorate_subscription.py`
- Create: `tests/test_happ_subscription.py`

**Interfaces:**
- Produces: subscription text headed by HAPP management parameters followed by proxy URIs.

- [ ] **Step 1: Write failing subscription-header test**

Assert that generated HAPP text contains `#profile-update-interval: 1`, `#subscription-auto-update-open-enable: 1`, `#ping-type: proxy`, `#check-url-via-proxy: https://cp.cloudflare.com/generate_204`, `#subscription-ping-onopen-enabled: 1`, `#subscriptions-sort-type: ping`, and `#subscription-autoconnect-type: lowestdelay`.

- [ ] **Step 2: Run test and verify failure**

Run: `python -m unittest tests.test_happ_subscription -v`
Expected: FAIL because current `happ_text()` lacks local proxy-ping/sort/lowest-delay metadata.

- [ ] **Step 3: Implement metadata**

Update `happ_text()` with the HAPP parameters above. Keep parameters in the standard subscription body format using leading `#`. Do not remove individual server entries; HAPP must have the candidates locally so its own ping can react to Wi-Fi versus mobile data.

- [ ] **Step 4: Run tests and verify pass**

Run: `python -m unittest tests.test_happ_subscription -v`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message: `Enable local HAPP proxy ping and lowest-delay sorting`.

### Task 4: Workflow validation and observability

**Files:**
- Modify: `.github/workflows/refresh.yml`
- Modify: `healthcheck.py`

**Interfaces:**
- Produces: CI that runs unit tests before scanning and health data that distinguishes source lines, logical groups, visible candidates, normal candidates, and whitelist/mobile candidates.

- [ ] **Step 1: Add unit-test step before network scan**

Run `python -m unittest discover -s tests -v` immediately after Python setup. A grouping/selection regression must fail the workflow before spending time on Xray tests.

- [ ] **Step 2: Update health reporting**

Record visible unique identities and fail if `out/happ.txt` contains duplicate logical identities or exceeds 100 total / 40 whitelist-mobile candidates.

- [ ] **Step 3: Run workflow**

Push the changes and inspect the triggered GitHub Action until completion.
Expected: unit tests PASS; collector and decorator complete; health check reports no duplicate visible identities.

- [ ] **Step 4: Verify published output**

Inspect `out/happ.txt`, `out/real-servers.json`, `out/health.json`, and workflow logs. Confirm that repeated Reality IP variants no longer occupy separate visible slots and that HAPP local-ping headers are present.

- [ ] **Step 5: Commit**

Commit message: `Validate local auto-selection subscription in CI`.
