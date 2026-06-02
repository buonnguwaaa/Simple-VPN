package client

import (
	"encoding/json"
	"log"
	"os/exec"

	"github.com/songgao/water"

	"Simple-VPN/internal/models"
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

	exec.Command(
		"ip", "link", "set", "dev", ifName, "up",
	).Run()

	log.Printf("TUN interface %s configured and up\n", ifName)

	exec.Command(
		"ip", "route", "add", "10.10.0.0/24", "dev", ifName,
	).Run()
	c.tun = tun
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

func (c *vpnClient) tunToUDP() {
	if c.tun == nil {
		log.Println("TUN interface not set up yet")
		return
	}

	buffer := make([]byte, 4096)

	for {
		n, err := c.tun.Read(buffer)
		if err != nil {
			log.Println("failed to read from TUN interface:", err)
			return
		}

		packet := models.Packet{
			Type:    models.DataPacket,
			Payload: buffer[:n],
		}

		if err := sendPacket(c.conn, packet); err != nil {
			log.Println("failed to send data packet:", err)
			return
		}
	}
}
