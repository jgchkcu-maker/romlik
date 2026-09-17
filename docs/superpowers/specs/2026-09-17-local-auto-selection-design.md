# Romlik local auto-selection design

Date: 2026-09-17

## Problem

The current pipeline ranks servers from GitHub-hosted runners. That proves a server works from Azure, not that it works from the user's current mobile carrier or Wi-Fi. Source lists also contain many variants of the same logical backend, so raw source counts are much larger than the number of distinct useful servers.

The desired behavior is the same model used by mature VPN clients: maintain a pool of distinct candidate backends, test them from the client network, and select the best currently reachable route locally.

## Goals

- One subscription URL should work on both mobile data and Wi-Fi.
- Duplicate variants of the same backend should not appear as separate visible servers.
- GitHub should validate syntax and maintain a diverse candidate pool, but should not decide the final best server for the user's network.
- The client should test availability through the proxy path and prefer the currently lowest-latency working server.
- Keep at most 100 published candidate servers, including up to 40 mobile/whitelist candidates.
- Preserve readable flags and unique names.

## Architecture

### 1. Candidate collection on GitHub

GitHub Actions continues to fetch all configured public sources. It parses supported VLESS, VMess, Trojan and Shadowsocks configurations and groups them by logical backend identity.

For direct Reality/TCP servers, identity is based on the real endpoint plus transport/service characteristics. Credentials and cosmetic fingerprint variants do not create separate visible servers unless they represent a materially different transport/service.

For CDN-backed WS/gRPC/XHTTP servers, edge IP changes are treated as variants of one logical backend when Host/SNI/path/service identify the same backend.

The collector stores variants inside each logical group instead of counting every variant as a new server.

### 2. Diversity-first publication

The published pool is not simply the 100 fastest Azure results. GitHub uses cloud tests only to reject malformed or obviously dead configurations and to provide a coarse quality signal.

The final pool is selected for diversity so it is not dominated by one provider, IP prefix, country or transport. Mobile whitelist candidates are allowed into the pool even when Azure cannot reach them, because Azure reachability is not evidence of mobile-carrier reachability.

Target composition:

- up to 40 mobile/whitelist logical backends;
- remaining slots filled with ordinary logical backends;
- maximum total 100.

### 3. Local HAPP testing

The normal text subscription will include HAPP management hints for local testing:

- proxy-based ping, not ICMP-only or TCP-only;
- ping all servers when the app opens;
- sort by local ping;
- request automatic connection to the lowest-delay reachable server when supported;
- update the subscription when the app opens.

The proxy check URL will use an HTTP 204 endpoint so the measurement exercises the whole proxy path.

HAPP documents `ping-type: proxy`, `check-url-via-proxy`, `subscription-ping-onopen-enabled`, `subscriptions-sort-type: ping`, and `subscription-autoconnect-type: lowestdelay`. Some app-management parameters require a HAPP Provider ID. Therefore the subscription will include the supported hints, but the design must not depend solely on provider-managed settings being accepted. If HAPP ignores those advanced hints, the same behavior can be enabled once in HAPP settings using Ping via Proxy + Ping on Launch.

### 4. Optional single AUTO profile

A later phase can generate a single Xray JSON AUTO profile using multiple outbound tags, `observatory`, and a `leastPing` balancer. Xray officially supports local HTTP probing of outbounds and a least-ping routing balancer. This would provide one visible AUTO connection whose selected outbound changes locally with the network.

This phase is intentionally separate because HAPP's standard URL subscription flow is already proven in the repo, while a full JSON multi-outbound profile needs compatibility validation on HAPP Android before replacing the normal subscription.

## Data flow

1. Fetch source lists.
2. Parse configs.
3. Build logical backend groups and retain useful variants.
4. Run syntax/TCP/Xray validation from GitHub where meaningful.
5. Score for coarse quality only.
6. Select a diverse set of up to 100 logical groups.
7. Publish one representative config per group to `out/happ.txt`.
8. HAPP updates the subscription on the device.
9. HAPP performs proxy ping using the device's current network.
10. HAPP sorts/selects the locally reachable lowest-latency server.

## Validation

Automated tests must cover:

- CDN edge-IP variants collapse into one logical group.
- Direct endpoints with materially different transport/service are not incorrectly collapsed.
- Published list contains no duplicate logical identities.
- Published list contains at most 100 entries and at most 40 whitelist/mobile entries.
- Candidate selection enforces diversity caps rather than taking one large block of the same network.
- Subscription body contains the intended HAPP local-ping settings.
- Existing subscription URLs remain valid.

Runtime verification after deployment:

- GitHub Action completes successfully.
- `out/real-servers.json` reports the same number of unique identities as visible entries.
- `out/happ.txt` contains at most 100 unique candidates.
- On HAPP Android, switching between Wi-Fi and mobile data triggers a new local proxy ping and causes unavailable servers to fall to the bottom while reachable low-latency servers rise to the top.

## Non-goals

- GitHub will not claim that a server works on Tele2 solely because it works from Azure.
- Raw source line count will not be presented as real server count.
- Azure speed will not be used as the final user-facing server ranking.
