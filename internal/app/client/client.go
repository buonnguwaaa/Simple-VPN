package client

import (
	"log"
	"net"

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
	Start()
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

func (c *vpnClient) Start() {
	if _, err := c.handshaker.Handshake(); err != nil {
		log.Fatal(err)
	}

	c.setupTUN()

	buffer := make([]byte, 4096)

	for {
		n, err := c.conn.Read(buffer)
		if err != nil {
			log.Fatal(err)
		}

		var packet protocol.Packet

		if err := packet.Decode(buffer[:n]); err != nil {
			log.Println("failed to parse packet:", err)
			continue
		}

		switch packet.Type {

		case protocol.Heartbeat:
			c.handleHeartbeat()

		case protocol.DataPacket:
			c.handleDataPacket(packet)

		default:
			log.Printf("unknown packet type: %d\n", packet.Type)
		}
	}
}

func (c *vpnClient) setupTUN() {
	tun := tunnel.Open("10.0.0.1/24", "10.10.0.0/24")
	if tun == nil {
		log.Fatal("failed to open TUN interface")
	}

	c.tunnel = tun

	go c.tunToUDP()
}

func (c *vpnClient) handleHeartbeat() {
	log.Println("Received heartbeat")
}

func (c *vpnClient) handleDataPacket(packet protocol.Packet) {
	log.Println("Received data packet")
}

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
