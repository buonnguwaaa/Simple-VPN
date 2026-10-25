package protocol

type Packet struct {
	Type    MessageType `json:"type"`
	Payload []byte      `json:"payload"`
}
