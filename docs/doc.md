# Simple-VPN

Intended protocol and data path. Implementation status: [progress-review.md](progress-review.md).

## Handshake

| Step | Direction | Message |
| ---: | --- | --- |
| 1 | Client → Server | `AUTH_REQUEST` |
| 2 | Server → Client | `AUTH_CHALLENGE` (nonce) |
| 3 | Client → Server | `AUTH_RESPONSE` (HMAC) |
| 4 | Server → Client | `AUTH_SUCCESS` |

```text
Client                                          Server
  |                                                |
  |  AUTH_REQUEST                                  |
  |----------------------------------------------->|
  |                                                |
  |                     AUTH_CHALLENGE (nonce)     |
  |<-----------------------------------------------|
  |                                                |
  |  AUTH_RESPONSE (HMAC)                          |
  |----------------------------------------------->|
  |                                                |
  |                     AUTH_SUCCESS               |
  |<-----------------------------------------------|
```

## Data path

Traffic enters the client TUN, crosses UDP to the server, is written into the server TUN, then forwarded and NAT'd out to the internet.

| Stage | Where | What happens |
| ---: | --- | --- |
| 1 | Client `tun0` `10.0.0.1` | Kernel delivers IP packets into the VPN process |
| 2 | Client VPN process | Encrypt, send as UDP |
| 3 | Server VPN process | Receive UDP, decrypt |
| 4 | Server `tun0` `10.0.0.2` | `tun.Write()` injects the packet |
| 5 | Linux kernel | Routing, forwarding, NAT |
| 6 | `eth0` → internet | Packet reaches the destination |

```text
 Client                         Server                      Outside
 -------                        ------                      -------

 tun0 10.0.0.1                  tun0 10.0.0.2
      |                              ^
      v                              |
 encrypt                         decrypt
      |                              ^
      v                              |
 UDP socket  ================  UDP socket
                                     |
                                     |  tun.Write()
                                     v
                               Linux kernel
                               route / forward / NAT
                                     |
                                     v
                                   eth0
                                     |
                                     v
                                 Internet
                                     |
                                     v
                                Destination
```

## Why the server `tun.Write`s instead of sending to `eth0`

The server TUN is **not** the VPN you just arrived on. UDP is the tunnel from the client. The server TUN is a virtual NIC so Linux will treat the inner IP packet as if it arrived on an interface.

After `ReadFromUDP` and parse, Go holds the **client’s** packet (`src 10.0.0.1 → dst 8.8.8.8`). That must leave the machine as that packet (then NAT rewrites the source). A normal socket send on `eth0` cannot do that:

- `WriteToUDP` / `Dial` from Go builds a **new** packet from the **server**. Source, ports, and the flow are yours. The client’s ping/TCP is gone.
- To emit the **same** inner bytes on the wire you need a raw / `AF_PACKET` socket, then you must NAT, track replies, and map them back to the client yourself.

`tun.Write` means: pretend this frame arrived on `tun0`. The kernel then:

1. Looks up dest (`8.8.8.8` misses `10.0.0.0/24` → default via `eth0`)
2. Forwards TUN → `eth0` (`ip_forward=1`)
3. MASQUERADE in POSTROUTING (`-s 10.0.0.0/24 -o eth0`) rewrites src to the `eth0` address and stores the 5-tuple in conntrack

**Request:** UDP payload → `tun.Write` → kernel route/forward/NAT → `eth0`.  
**Response:** reply hits the WAN IP → conntrack restores dest `10.0.0.1` → kernel transmits into the TUN → `tun.Read` → UDP to the client.

The extra step is inject into the stack, not “send through the tunnel again.” UDP → TUN → kernel → `eth0` reuses Linux routing and NAT instead of reimplementing them in Go.

