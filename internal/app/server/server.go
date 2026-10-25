package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"

	"Simple-VPN/internal/constants"
	"Simple-VPN/internal/protocol"
	"Simple-VPN/internal/tunnel"
)

type ClientSession struct {
	SessionID  int
	clientAddr *net.UDPAddr
}

type vpnServer struct {
	conn       *net.UDPConn
	sessions   map[int]*ClientSession
	mu         sync.Mutex
	handshaker ServerHandshaker
	tunnel     tunnel.Tunnel
}

type VPNServer interface {
	Run(context.Context) error
	Stop() error
}

func NewVPNServer(port string) *vpnServer {
	// Set up IP forwarding
	if err := setupIPForwarding(); err != nil {
		log.Fatal(err)
	}

	addr, err := net.ResolveUDPAddr("udp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("UDP server listening on %s", addr.String())

	return &vpnServer{
		conn:       conn,
		sessions:   make(map[int]*ClientSession),
		handshaker: NewServerHandshaker(conn, constants.SECRET_KEY),
	}
}

func (s *vpnServer) Run(ctx context.Context) error {
	buffer := make([]byte, 4096)

	if err := s.setupServerTUN(ctx); err != nil {
		return fmt.Errorf("Set up server TUN failed: %v", err)
	}

	if err := s.setupMasquerade(ctx, "10.0.0.0/24"); err != nil {
		return fmt.Errorf("Set up MASQUERADE failed: %v", err)
	}

	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}

		var packet protocol.Packet

		if err := packet.Decode(buffer[:n]); err != nil {
			log.Println("failed to parse packet:", err)
			continue
		}

		switch packet.Type { //nolint:exhaustive
		case protocol.AuthRequest, protocol.AuthResponse:
			session, err := s.handshaker.Handshake(ctx, packet, remoteAddr)
			if err != nil {
				log.Println(err)
				continue
			}

			if session == nil {
				continue
			}

			s.mu.Lock()
			s.sessions[session.SessionID] = session
			s.mu.Unlock()

		case protocol.Heartbeat:
			s.handleHeartbeat(remoteAddr)

		case protocol.DataPacket:
			s.handleDataPacket(packet, remoteAddr)

		default:
			log.Printf("unknown packet type: %d\n", packet.Type)
		}
	}
}

func (s *vpnServer) Stop() error {
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.sessions = make(map[int]*ClientSession)
	s.mu.Unlock()

	return nil
}

func (s *vpnServer) handleHeartbeat(addr *net.UDPAddr) {
	log.Printf("Received heartbeat from %s", addr.String())
}

// Request: UDP DataPacket from the client → tun.Write. Kernel routes dest
// (miss TUN subnet → default via eth0) and forwards TUN → eth0.
func (s *vpnServer) handleDataPacket(packet protocol.Packet, addr *net.UDPAddr) {
	if _, err := s.tunnel.Write(packet.Payload); err != nil {
		log.Println("failed to write packet to TUN: ", err)
	}
}

func sendPacket(conn *net.UDPConn, addr *net.UDPAddr, packet protocol.Packet) error {
	data, err := packet.Encode()
	if err != nil {
		return err
	}

	_, err = conn.WriteToUDP(data, addr)

	return err
}

// Request: allow the kernel to forward packets that arrived on the TUN
// out eth0 toward dest (usually the default gateway). FORWARD ACCEPT
// is the filter policy for that forwarded traffic.
func setupIPForwarding() error {
	if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
		return err
	}

	if err := exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run(); err != nil {
		return err
	}

	return nil
}

// Request: tun.Write in handleDataPacket injects client packets.
// Response: connected 10.0.0.0/24 delivers dest 10.0.0.1 into this TUN
// for tunToUDP (no extra 0.0.0.0/0 — internet stays on eth0).
func (s *vpnServer) setupServerTUN(ctx context.Context) error {
	tun, err := tunnel.Open(ctx, "10.0.0.2/24")
	if err != nil {
		return err
	}

	s.tunnel = tun

	go func() {
		s.tunToUDP()
	}()

	return nil
}

// Request: POSTROUTING MASQUERADE rewrites src 10.0.0.0/24 to the eth0
// address when leaving for the internet. Conntrack stores the 5-tuple.
// Response: matching replies to the WAN IP are dest-rewritten back to
// 10.0.0.1 and then routed into the TUN (not masqueraded: -o eth0 only).
func (s *vpnServer) setupMasquerade(ctx context.Context, srcIP string) error {
	if err := exec.CommandContext(ctx, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", srcIP, "-o", "eth0", "-j", "MASQUERADE").Run(); err != nil {
		return err
	}

	return nil
}

// Response: kernel has already un-NATed dest to 10.0.0.1 and transmitted
// into the TUN. Read those bytes and UDP-send them to the client.
func (s *vpnServer) tunToUDP() {
	if s.tunnel == nil {
		log.Println("Server TUN interface not set up yet")
		return
	}

	buffer := make([]byte, 4096)

	for {
		n, err := s.tunnel.Read(buffer)
		if err != nil {
			log.Println("failed to read from TUN interface:", err)
			return
		}

		packet := protocol.Packet{
			Type:    protocol.DataPacket,
			Payload: buffer[:n],
		}

		var addr *net.UDPAddr

		s.mu.Lock()
		// Temporarily assume that there's only 1 session at a time
		// TODO: Determine client UDP Addr per client IPs later (parse payload to get client IP)
		for _, clientSession := range s.sessions {
			if clientSession.clientAddr != nil {
				addr = clientSession.clientAddr
				break
			}
		}
		s.mu.Unlock()

		if addr == nil {
			continue
		}
		if err := sendPacket(s.conn, addr, packet); err != nil {
			log.Println("failed to send data packet:", err)
			return
		}
	}
}
