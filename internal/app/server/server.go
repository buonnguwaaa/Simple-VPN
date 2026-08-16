package server

import (
	"log"
	"net"
	"sync"

	"Simple-VPN/internal/constants"
	"Simple-VPN/internal/protocol"
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
}

type VPNServer interface {
	Run() error
	Stop() error
}

func NewVPNServer(port string) *vpnServer {
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

func (s *vpnServer) Run() error {
	buffer := make([]byte, 4096)

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

		switch packet.Type {
		case protocol.AuthRequest, protocol.AuthResponse:
			session, err := s.handshaker.Handshake(packet, remoteAddr)
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

func (s *vpnServer) handleDataPacket(packet protocol.Packet, addr *net.UDPAddr) {
	log.Printf("Received data packet from %s", addr.String())
}

func sendPacket(conn *net.UDPConn, addr *net.UDPAddr, packet protocol.Packet) error {
	data, err := packet.Encode()
	if err != nil {
		return err
	}

	_, err = conn.WriteToUDP(data, addr)

	return err
}
