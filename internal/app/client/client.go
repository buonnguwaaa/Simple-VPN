package client

import (
	"context"
	"log"
	"net"
	"time"

	"Simple-VPN/internal/constants"
	"Simple-VPN/internal/protocol"
	"Simple-VPN/internal/tunnel"
)

type vpnClient struct {
	conn       *net.UDPConn
	tunnel     tunnel.Tunnel
	handshaker ClientHandshaker
}

type VPNClient interface {
	Run(context.Context) error
	Stop() error
}

func NewVPNClient(port string) *vpnClient {
	if port == "" {
		port = "51820"
	}

	addr, err := net.ResolveUDPAddr("udp", "localhost:"+port)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatal(err)
	}

	return &vpnClient{
		conn:       conn,
		tunnel:     nil,
		handshaker: NewClientHandshaker(conn, constants.SECRET_KEY),
	}
}

func (c *vpnClient) Run(ctx context.Context) error {
	handshakeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if _, err := c.handshaker.Handshake(handshakeCtx); err != nil {
		return err
	}

	if err := c.setupClientTUN(ctx); err != nil {
		return err
	}

	buffer := make([]byte, 4096) // This is receive buffer

	for {
		n, err := c.conn.Read(buffer)
		if err != nil {
			return err
		}

		var packet protocol.Packet

		if err := packet.Decode(buffer[:n]); err != nil {
			log.Println("failed to parse packet:", err)
			continue
		}

		switch packet.Type { //nolint:exhaustive
		case protocol.Heartbeat:
			c.handleHeartbeat()

		case protocol.DataPacket:
			c.handleDataPacket(packet)

		default:
			log.Printf("unknown packet type: %d\n", packet.Type)
		}
	}
}

func (c *vpnClient) Stop() error {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return err
		}
	}

	if c.tunnel != nil {
		if err := c.tunnel.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Request: /1 routes send local app traffic into this TUN (full tunnel).
// ProtectHost keeps the VPN UDP envelope on the physical NIC / loopback.
// Response: dest 10.0.0.1 is local on this TUN; handleDataPacket tun.Write
// delivers replies to the app. No ip_forward — TUN never forwards to eth0.
func (c *vpnClient) setupClientTUN(ctx context.Context) error {
	if err := tunnel.ProtectHost(ctx, udpRemoteIP(c.conn)); err != nil {
		return err
	}

	// Request: two /1 routes beat the existing default (0.0.0.0/0) without replacing it.
	tun, err := tunnel.Open(ctx, "10.0.0.1/24", "0.0.0.0/1", "128.0.0.0/1")
	if err != nil {
		return err
	}

	c.tunnel = tun

	go func() {
		c.tunToUDP()
	}()

	return nil
}

func (c *vpnClient) handleHeartbeat() {
	log.Println("Received heartbeat")
}

// Response: UDP DataPacket from the server → tun.Write. Kernel delivers
// dest 10.0.0.1 to the local app.
func (c *vpnClient) handleDataPacket(packet protocol.Packet) {
	if _, err := c.tunnel.Write(packet.Payload); err != nil {
		log.Println("failed to write packet to TUN: ", err)
	}
}

// Request: read inner packets the kernel sent into this TUN (app traffic
// matching the /1 routes) and UDP-send them to the server. Not forwarded
// to eth0 — encapsulation happens in this process.
func (c *vpnClient) tunToUDP() {
	if c.tunnel == nil {
		log.Println("TUN interface not set up yet")
		return
	}

	buffer := make([]byte, 4096)

	for {
		n, err := c.tunnel.Read(buffer)
		if err != nil {
			log.Println("failed to read from TUN interface:", err)
			return
		}

		packet := protocol.Packet{
			Type:    protocol.DataPacket,
			Payload: buffer[:n],
		}

		if err := sendPacket(c.conn, packet); err != nil {
			log.Println("failed to send data packet:", err)
			return
		}
	}
}

func sendPacket(conn *net.UDPConn, packet protocol.Packet) error {
	data, err := packet.Encode()
	if err != nil {
		return err
	}

	_, err = conn.Write(data)

	return err
}

func udpRemoteIP(conn *net.UDPConn) net.IP {
	if conn == nil {
		return nil
	}

	addr, ok := conn.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}

	return addr.IP
}
