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
	Run() error
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

func (c *vpnClient) Run() error {
	if _, err := c.handshaker.Handshake(); err != nil {
		return err
	}

	c.setupTUN()

	buffer := make([]byte, 4096)

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

func (c *vpnClient) setupTUN() error {
	tun, err := tunnel.Open("10.0.0.1/24", "10.10.0.0/24")
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
