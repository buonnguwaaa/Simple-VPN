package protocol

type MessageType int

const (
	AuthRequest MessageType = iota + 1
	AuthChallenge
	AuthResponse
	AuthSuccess
	AuthFailure
	DataPacket
	Heartbeat
)
