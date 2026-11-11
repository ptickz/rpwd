package agent

import "time"

const (
	opGetKey = "get_key"
	opStatus = "status"
	opLock   = "lock"
)

type request struct {
	Op string `json:"op"`
}

type response struct {
	Key       []byte    `json:"key,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	Error     string    `json:"error,omitempty"`
}
