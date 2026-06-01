package client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"

	"my-vpn/internal/constants"
	"my-vpn/internal/models"
)

type vpnClient struct {
	conn *net.UDPConn
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
	defer conn.Close()

	return &vpnClient{
		conn: conn,
	}
}

func (c *vpnClient) Start() {
	// Send initial auth request
	authReq := models.Packet{
		Type: models.AuthRequest,
		Payload: mustMarshal(models.AuthRequestPayload{
			Message: constants.HELLO_MESSAGE,
		}),
	}

	if err := sendPacket(c.conn, authReq); err != nil {
		log.Fatal(err)
	}

	log.Println("Sent auth request")

	buffer := make([]byte, 4096)

	for {
		n, err := c.conn.Read(buffer)
		if err != nil {
			log.Fatal(err)
		}

		var packet models.Packet

		if err := json.Unmarshal(buffer[:n], &packet); err != nil {
			log.Println("failed to parse packet:", err)
			continue
		}

		switch packet.Type {

		case models.AuthChallenge:
			c.handleAuthChallenge(packet)

		case models.AuthSuccess:
			c.handleAuthSuccess(packet)

			// stop demo client after auth success
			return

		case models.AuthFailure:
			c.handleAuthFailure(packet)

			return

		case models.Heartbeat:
			c.handleHeartbeat()

		case models.DataPacket:
			c.handleDataPacket(packet)

		default:
			log.Printf("unknown packet type: %d\n", packet.Type)
		}
	}
}

func computeHMAC(message string) string {
	mac := hmac.New(sha256.New, []byte(constants.SECRET_KEY))
	mac.Write([]byte(message))

	return hex.EncodeToString(mac.Sum(nil))
}

func sendPacket(conn *net.UDPConn, packet models.Packet) error {
	data, err := json.Marshal(packet)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)

	return err
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	return json.RawMessage(b)
}
