package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"strconv"
	"sync"

	"Simple-VPN/internal/constants"
	"Simple-VPN/internal/models"
)

type ClientSession struct {
	SessionID  int
	clientAddr *net.UDPAddr
}

type vpnServer struct {
	conn              *net.UDPConn
	sessions          map[int]*ClientSession
	pendingChallenges map[string]string
	mu                sync.Mutex
}

type VPNServer interface {
	Start()
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
	defer conn.Close()

	log.Printf("UDP server listening on %s", addr.String())

	return &vpnServer{
		conn:              conn,
		sessions:          make(map[int]*ClientSession),
		pendingChallenges: make(map[string]string),
	}
}

func (s *vpnServer) Start() {
	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}

		packet := &models.Packet{}
		err = json.Unmarshal(buffer[:n], packet)
		if err != nil {
			log.Printf("Error unmarshaling packet: %v", err)
			continue
		}

		switch packet.Type {
		case models.AuthRequest:
			payload := &models.AuthRequestPayload{}
			err = json.Unmarshal(packet.Payload, payload)
			if err != nil {
				log.Printf("Error unmarshaling authentication request payload: %v", err)
				continue
			}

			if payload.Message == constants.HELLO_MESSAGE {
				nonce, err := randomNonce()
				if err != nil {
					log.Printf("Error generating nonce: %v", err)
					continue
				}

				s.mu.Lock()
				s.pendingChallenges[remoteAddr.String()] = nonce
				s.mu.Unlock()

				authChallenge := models.Packet{
					Type:    models.AuthChallenge,
					Payload: json.RawMessage([]byte(`{"nonce":"` + nonce + `"}`)),
				}
				if err := sendPacket(s.conn, remoteAddr, authChallenge); err != nil {
					log.Printf("Error writing auth challenge to UDP: %v", err)
				}
				log.Printf("Sent auth challenge to %s", remoteAddr.String())
			}
		case models.AuthResponse:
			payload := &models.AuthResponsePayload{}
			err = json.Unmarshal(packet.Payload, payload)
			if err != nil {
				log.Printf("Error unmarshaling authentication response payload: %v", err)
				continue
			}

			s.mu.Lock()
			nonce, ok := s.pendingChallenges[remoteAddr.String()]
			if ok {
				delete(s.pendingChallenges, remoteAddr.String())
			}
			s.mu.Unlock()

			if !ok {
				failure := models.Packet{Type: models.AuthFailure, Payload: json.RawMessage([]byte(`{"error":"no pending challenge"}`))}
				if err := sendPacket(s.conn, remoteAddr, failure); err != nil {
					log.Printf("Error writing auth failure: %v", err)
				}
				continue
			}

			expectedHMAC := computeHMAC(nonce)
			if !hmac.Equal([]byte(expectedHMAC), []byte(payload.HMAC)) {
				failure := models.Packet{Type: models.AuthFailure, Payload: json.RawMessage([]byte(`{"error":"invalid hmac"}`))}
				if err := sendPacket(s.conn, remoteAddr, failure); err != nil {
					log.Printf("Error writing auth failure: %v", err)
				}
				continue
			}

			s.mu.Lock()
			sessionID := len(s.sessions) + 1
			s.sessions[sessionID] = &ClientSession{SessionID: sessionID, clientAddr: remoteAddr}
			s.mu.Unlock()

			success := models.Packet{
				Type:    models.AuthSuccess,
				Payload: json.RawMessage([]byte(`{"session_id":` + strconv.Itoa(sessionID) + `}`)),
			}
			if err := sendPacket(s.conn, remoteAddr, success); err != nil {
				log.Printf("Error writing auth success: %v", err)
				continue
			}
			log.Printf("Authentication successful for %s, session ID: %d", remoteAddr.String(), sessionID)
		}

		log.Printf("Received %d bytes from %s: %s", n, remoteAddr.String(), string(buffer[:n]))
	}
}

func computeHMAC(message string) string {
	mac := hmac.New(sha256.New, []byte(constants.SECRET_KEY))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomNonce() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func sendPacket(conn *net.UDPConn, addr *net.UDPAddr, packet models.Packet) error {
	messageBytes, err := json.Marshal(packet)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(messageBytes, addr)
	return err
}
