// Package settings holds fixed application constants: session TTL, clipboard timeout and backup count.
package settings

import "time"

const (
	SessionTTL       = time.Hour
	ClipboardClearIn = 15 * time.Second
	BackupsKeep      = 20
)
