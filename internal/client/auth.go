package client

import (
	"encoding/json"
	"log"
	"os/exec"

	"my-vpn/internal/models"

	"github.com/songgao/water"
)

func (c *vpnClient) handleAuthChallenge(packet models.Packet) {
	var payload models.AuthChallengePayload

	if err := json.Unmarshal(packet.Payload, &payload); err != nil {
		log.Println("invalid auth challenge payload:", err)
		return
	}

	log.Printf("Received challenge nonce: %s\n", payload.Nonce)

	hmacValue := computeHMAC(payload.Nonce)

	response := models.Packet{
		Type: models.AuthResponse,
		Payload: mustMarshal(models.AuthResponsePayload{
			HMAC: hmacValue,
		}),
	}

	if err := sendPacket(c.conn, response); err != nil {
		log.Println("failed to send auth response:", err)
		return
	}

	log.Println("Sent auth response")
}

func (c *vpnClient) handleAuthSuccess(packet models.Packet) {
	var payload models.AuthSuccessPayload

	if err := json.Unmarshal(packet.Payload, &payload); err != nil {
		log.Println("invalid auth success payload:", err)
		return
	}

	log.Printf(
		"Authentication successful! Session ID: %d\n",
		payload.SessionID,
	)

	// Set up TUN interface
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		log.Fatal(err)
	}

	ifName := tun.Name()
	log.Printf("Created TUN interface: %s\n", ifName)

	exec.Command(
		"ip", "addr", "add", "10.0.0.1/24", "dev", ifName,
	).Run()
}

func (c *vpnClient) handleAuthFailure(packet models.Packet) {
	var payload models.AuthFailurePayload

	if err := json.Unmarshal(packet.Payload, &payload); err != nil {
		log.Println("invalid auth failure payload:", err)
		return
	}

	log.Printf(
		"Authentication failed: %s\n",
		payload.Error,
	)
}

func (c *vpnClient) handleHeartbeat() {
	log.Println("Received heartbeat")
}

func (c *vpnClient) handleDataPacket(packet models.Packet) {
	log.Println("Received data packet")
}
