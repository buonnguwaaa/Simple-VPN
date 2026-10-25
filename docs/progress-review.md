# Simple-VPN progress review

**Date:** 25 Oct 2026 (was 22 Aug 2026)

Userspace request and response loops are wired. HMAC auth, `[]byte` framing, both TUN↔UDP directions, client full-tunnel `/1` routes, server TUN without a default route, `ip_forward`, and MASQUERADE all exist. This is not a proven VPN: no ping has completed, and client+server on one WSL host will fight over routing.

| Metric | Value |
| --- | --- |
| Toward a working tunnel | ~70% |
| Subsystems done | 4 / 9 |
| Critical-path items remaining | 3 (prove ping, session lookup, session gate) |

Subsystem mix: 4 done · 4 partial · 1 missing.

## Snapshot

`Run()` opens the server TUN (`10.0.0.2/24` only), enables forwarding, and installs MASQUERADE `-s 10.0.0.0/24 -o eth0`. Client is full tunnel (`0.0.0.0/1` + `128.0.0.0/1`) with `ProtectHost` for a remote server IP (no-op on localhost). `Packet.Payload` is `[]byte` (JSON base64). Server `tunToUDP` still picks the first session in the map, not inner dest IP.

## Data path

Live hops have code that can succeed on real IP traffic. Partial hops are implemented but unproven or stubbed. Dead hops have no implementation.

| # | Hop | Status | Reality |
| --- | --- | --- | --- |
| 1 | Client TUN read | Live | water TUN + `10.0.0.1/24`, full tunnel `0.0.0.0/1` + `128.0.0.0/1` |
| 2 | Client TUN → UDP | Live | `tunToUDP` wraps IP bytes as `DataPacket`; `[]byte` payload is binary-safe |
| 3 | Server receives | Live | `handleDataPacket` `tun.Write`s payload (no session check) |
| 4 | Server TUN | Live | `setupServerTUN` from `Run`; connected `10.0.0.0/24` only |
| 5 | NAT / internet | Partial | `ip_forward` + FORWARD ACCEPT + MASQUERADE; iface hardcoded `eth0`; unproven |
| 6 | Return path | Partial | Server `tunToUDP` + client `tun.Write`; first-session stub, not dest-IP lookup |

**Request:** client TUN → UDP → server `tun.Write` → kernel route/forward/NAT → `eth0`.  
**Response:** WAN reply → conntrack dest `10.0.0.1` → server TUN `Read` → UDP → client `tun.Write` → app.

Why the server injects into the TUN instead of sending to `eth0`: [doc.md](doc.md#why-the-server-tunwrites-instead-of-sending-to-eth0).

## Subsystem status

| Area | Status | Reality in the repo |
| --- | --- | --- |
| UDP transport | Done | Listen/dial, graceful SIGINT shutdown |
| HMAC handshake | Done | Request → challenge → HMAC → success/failure |
| Client TUN | Done | Full tunnel `/1`s; outbound `tunToUDP`; inbound `tun.Write` |
| Server TUN | Done | Opened from `Run`; write-on-receive; `tunToUDP` reads replies |
| Bidirectional data plane | Partial | Both loops exist; return addr is “first session”; never ping-tested |
| Internet forwarding | Partial | NAT/forward code is in; needs two netns/hosts + correct WAN iface |
| Data encryption | Missing | HMAC is auth-only; payload is plaintext UDP (base64 JSON) |
| Session / keepalive | Stub | Map filled on auth; data path ignores session ID; heartbeat logs only |
| Config / tests / docs | Thin | Hardcoded secret + localhost; no tests; architecture in `doc.md` |

## Moved since 22 Aug

| Item | Then | Now |
| --- | --- | --- |
| Server TUN in `Run` | Never called | Called; `10.0.0.2/24`, no extra route |
| Empty `ip route add` | Would fail | `Open` skips empty routes |
| Framing | `json.RawMessage` (invalid JSON for IP) | `[]byte` (base64 on the wire) |
| Client routes | Split `10.10.0.0/24` | Full tunnel `/1` + `ProtectHost` |
| Bidirectional relay | Missing | Both TUN↔UDP loops |
| MASQUERADE | Missing | POSTROUTING `-s 10.0.0.0/24 -o eth0` |
| Compile | Built | `syns`/`exes` typos were fixed |

## Already in place

### Handshake (`internal/app/*/auth.go`)

Shared-secret HMAC-SHA256 over a random nonce. Server tracks pending challenges by UDP address and issues incrementing session IDs.

```
AUTH_REQUEST → AUTH_CHALLENGE → AUTH_RESPONSE → AUTH_SUCCESS
```

### Client TUN (`internal/app/client/client.go`, `internal/tunnel/tunnel.go`)

Creates a TUN, assigns `10.0.0.1/24`, installs `0.0.0.0/1` and `128.0.0.0/1` (beats default `0.0.0.0/0` without replacing it). `ProtectHost` adds a `/32` via the original gateway when the server is not loopback. Client does **not** enable `ip_forward`: apps → TUN (or `eth0` if a dest is more specific); encapsulation is in-process.

### Server kernel plumbing (`internal/app/server/server.go`)

TUN is a virtual NIC so Linux routes/forwards/NATs the inner packet. Do not put `0.0.0.0/0` on the server TUN — that loops dests back into the TUN instead of `eth0`.

## What to do next

Do these in order. First real proof is `ping 8.8.8.8` from the **client** namespace/host, with the server on a **different** netns or machine.

### Critical path

1. **Prove the tunnel** — Root, `PORT=51820`, WAN iface `eth0` (or fix `-o`). Two netns/hosts. Same-machine WSL + full tunnel will steal server forwards into the client TUN.
2. **Session lookup** — Parse IPv4 dest `payload[16:20]`, map to `ClientSession.tunIP` / `clientAddr`. Stop ranging the map and taking the first addr.
3. **Session gate** — Reject `DataPacket` from UDP addrs that never completed handshake; keep the client session ID.

### After a ping returns

- Encrypt and authenticate the data plane (handshake HMAC does not protect `DataPacket`).
- UDP buffers larger than 4096 (JSON+base64 inflates TUN MTU).
- Do not `return` from `tunToUDP` on a single send error; close server TUN in `Stop()`.
- Heartbeat send/timeout; expire pending challenges.
- Load `SECRET_KEY` from env; stop hardcoding `localhost` (server `PORT` has no default; client uses `51820`).
- Per-client TUN IPs; one `10.0.0.1` / `10.0.0.2` pair cannot serve more than one peer.
- IPv6 still leaks off-tunnel.
- Unit tests for HMAC, codec, loopback data path.
- README, fix `launch.json` (Debug Server points at `cmd/client`), clean golangci leftovers from another repo.

## Bugs that will bite during the next step

- Client and server on one routing table with `/1` routes: forwarded internet packets match the client TUN, not `eth0`.
- Return path: first session in `s.sessions`, not inner dest IP. Fine for one peer; wrong as a design.
- Inbound `handleDataPacket` does not require an authenticated `addr`.
- MASQUERADE `-A` duplicates on every restart; `-o eth0` misses other iface names.
- Secret is `secret`. Payload is plaintext. `iptables`/`sysctl`/TUN need `CAP_NET_ADMIN`.

## Related

- Target architecture (handshake, TUN/NAT, why server `tun.Write`): [doc.md](doc.md)
- Code reviewed: `cmd/`, `internal/app`, `internal/protocol`, `internal/tunnel`, `internal/crypto`
