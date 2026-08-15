package protocol

import (
	"encoding/json"
)

type Packet struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload"`
}
