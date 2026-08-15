package server

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"

	"Simple-VPN/internal/constants"
	"Simple-VPN/internal/crypto"
	"Simple-VPN/internal/protocol"
)

type serverHandshaker struct {
	conn              *net.UDPConn
	secretKey         string
	pendingChallenges map[string]string
	nextSessionID     int
	mu                sync.Mutex
}

func NewServerHandshaker(conn *net.UDPConn, secretKey string) ServerHandshaker {
	return &serverHandshaker{
		conn:              conn,
		secretKey:         secretKey,
		pendingChallenges: make(map[string]string),
	}
}

type ServerHandshaker interface {
	Handshake(packet protocol.Packet, addr *net.UDPAddr) (*ClientSession, error)
}

func (h *serverHandshaker) Handshake(packet protocol.Packet, addr *net.UDPAddr) (*ClientSession, error) {
	switch packet.Type {

	case protocol.AuthRequest:
		return nil, h.handleRequest(packet, addr)

	case protocol.AuthResponse:
		return h.handleResponse(packet, addr)

	default:
		return nil, fmt.Errorf("unexpected packet type during handshake: %d", packet.Type)
	}
}

func (h *serverHandshaker) handleRequest(packet protocol.Packet, addr *net.UDPAddr) error {
	var payload protocol.AuthRequestPayload

	if err := json.Unmarshal(packet.Payload, &payload); err != nil {
		return fmt.Errorf("invalid auth request payload: %w", err)
	}

	if payload.Message != constants.HELLO_MESSAGE {
		return fmt.Errorf("unexpected hello message from %s", addr.String())
	}

	nonce, err := randomNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	h.mu.Lock()
	h.pendingChallenges[addr.String()] = nonce
	h.mu.Unlock()

	challengePayload, err := json.Marshal(protocol.AuthChallengePayload{
		Nonce: nonce,
	})
	if err != nil {
		return fmt.Errorf("marshal auth challenge: %w", err)
	}

	if err := sendPacket(h.conn, addr, protocol.Packet{
		Type:    protocol.AuthChallenge,
		Payload: challengePayload,
	}); err != nil {
		return fmt.Errorf("send auth challenge: %w", err)
	}

	log.Printf("Sent auth challenge to %s", addr.String())
	return nil
}

func (h *serverHandshaker) handleResponse(packet protocol.Packet, addr *net.UDPAddr) (*ClientSession, error) {
	var payload protocol.AuthResponsePayload

	if err := json.Unmarshal(packet.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid auth response payload: %w", err)
	}

	h.mu.Lock()
	nonce, ok := h.pendingChallenges[addr.String()]
	if ok {
		delete(h.pendingChallenges, addr.String())
	}
	h.mu.Unlock()

	if !ok {
		if err := h.handleFailure(addr, "no pending challenge"); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("no pending challenge for %s", addr.String())
	}

	expectedHMAC := crypto.ComputeHMAC(nonce, h.secretKey)
	if !hmac.Equal([]byte(expectedHMAC), []byte(payload.HMAC)) {
		if err := h.handleFailure(addr, "invalid hmac"); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("invalid hmac from %s", addr.String())
	}

	return h.handleSuccess(addr)
}

func (h *serverHandshaker) handleSuccess(addr *net.UDPAddr) (*ClientSession, error) {
	h.mu.Lock()
	h.nextSessionID++
	sessionID := h.nextSessionID
	h.mu.Unlock()

	successPayload, err := json.Marshal(protocol.AuthSuccessPayload{
		SessionID: sessionID,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal auth success: %w", err)
	}

	if err := sendPacket(h.conn, addr, protocol.Packet{
		Type:    protocol.AuthSuccess,
		Payload: successPayload,
	}); err != nil {
		return nil, fmt.Errorf("send auth success: %w", err)
	}

	log.Printf("Authentication successful for %s, session ID: %d", addr.String(), sessionID)

	return &ClientSession{
		SessionID:  sessionID,
		clientAddr: addr,
	}, nil
}

func (h *serverHandshaker) handleFailure(addr *net.UDPAddr, message string) error {
	failurePayload, err := json.Marshal(protocol.AuthFailurePayload{
		Error: message,
	})
	if err != nil {
		return fmt.Errorf("marshal auth failure: %w", err)
	}

	if err := sendPacket(h.conn, addr, protocol.Packet{
		Type:    protocol.AuthFailure,
		Payload: failurePayload,
	}); err != nil {
		return fmt.Errorf("send auth failure: %w", err)
	}

	return nil
}

func randomNonce() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
