package client

import (
	"encoding/json"
	"fmt"
	"log"
	"net"

	"Simple-VPN/internal/constants"
	"Simple-VPN/internal/crypto"
	"Simple-VPN/internal/protocol"
)

type clientHandshaker struct {
	conn      *net.UDPConn
	secretKey string
}

func NewClientHandshaker(conn *net.UDPConn, secretKey string) ClientHandshaker {
	return &clientHandshaker{
		conn:      conn,
		secretKey: secretKey,
	}
}

type ClientHandshaker interface {
	Handshake() (sessionID int, err error)
}

func (h *clientHandshaker) Handshake() (int, error) {
	if err := h.authRequest(); err != nil {
		return 0, err
	}

	buffer := make([]byte, 4096)

	for {
		n, err := h.conn.Read(buffer)
		if err != nil {
			return 0, err
		}

		var packet protocol.Packet

		if err := packet.Decode(buffer[:n]); err != nil {
			log.Println("failed to parse packet:", err)
			continue
		}

		switch packet.Type {
		case protocol.AuthChallenge:
			if err := h.handleChallenge(packet); err != nil {
				log.Println(err)
			}

		case protocol.AuthSuccess:
			return h.handleSuccess(packet)

		case protocol.AuthFailure:
			return 0, h.handleFailure(packet)

		default:
			log.Printf("unexpected packet type during handshake: %d\n", packet.Type)
		}
	}
}

func (h *clientHandshaker) authRequest() error {
	payload, err := json.Marshal(protocol.AuthRequestPayload{
		Message: constants.HELLO_MESSAGE,
	})
	if err != nil {
		return fmt.Errorf("marshal auth request: %w", err)
	}

	if err := sendPacket(h.conn, protocol.Packet{
		Type:    protocol.AuthRequest,
		Payload: payload,
	}); err != nil {
		return fmt.Errorf("send auth request: %w", err)
	}

	log.Println("Sent auth request")

	return nil
}

func (h *clientHandshaker) handleChallenge(packet protocol.Packet) error {
	var payload protocol.AuthChallengePayload

	if err := json.Unmarshal(packet.Payload, &payload); err != nil {
		return fmt.Errorf("invalid auth challenge payload: %w", err)
	}

	log.Printf("Received challenge nonce: %s\n", payload.Nonce)

	hmacValue := crypto.ComputeHMAC(payload.Nonce, h.secretKey)

	responsePayload, err := json.Marshal(protocol.AuthResponsePayload{
		HMAC: hmacValue,
	})
	if err != nil {
		return fmt.Errorf("marshal auth response: %w", err)
	}

	if err := sendPacket(h.conn, protocol.Packet{
		Type:    protocol.AuthResponse,
		Payload: responsePayload,
	}); err != nil {
		return fmt.Errorf("send auth response: %w", err)
	}

	log.Println("Sent auth response")

	return nil
}

func (h *clientHandshaker) handleSuccess(packet protocol.Packet) (int, error) {
	var payload protocol.AuthSuccessPayload

	if err := json.Unmarshal(packet.Payload, &payload); err != nil {
		return 0, fmt.Errorf("invalid auth success payload: %w", err)
	}

	log.Printf(
		"Authentication successful! Session ID: %d\n",
		payload.SessionID,
	)

	return payload.SessionID, nil
}

func (h *clientHandshaker) handleFailure(packet protocol.Packet) error {
	var payload protocol.AuthFailurePayload

	if err := json.Unmarshal(packet.Payload, &payload); err != nil {
		return fmt.Errorf("invalid auth failure payload: %w", err)
	}

	return fmt.Errorf("authentication failed: %s", payload.Error)
}
