package protocol

// Uncomment this if you want each client to have a unique secret key for HMAC authentication
//
//	var clientSecrets = map[string]string{
//		"client1": "secret1",
//		"client2": "secret2",
//	}
type AuthRequestPayload struct {
	// ClientID int `json:"client_id"`
	Message string `json:"message"`
}

type AuthChallengePayload struct {
	Nonce string `json:"nonce"`
}

type AuthResponsePayload struct {
	HMAC string `json:"hmac"`
}

type AuthSuccessPayload struct {
	SessionID int `json:"session_id"`
}

type AuthFailurePayload struct {
	Error string `json:"error"`
}
