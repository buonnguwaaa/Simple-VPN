package protocol

import (
	"encoding/json"
)

func (p *Packet) Encode() ([]byte, error) {
	return json.Marshal(p)
}

func (p *Packet) Decode(data []byte) error {
	return json.Unmarshal(data, p)
}
