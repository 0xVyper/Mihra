package sessions

import (
	"sync"

	"github.com/0xvyper/mihra/core/connector"
)

type SessionInfo struct {
	SessionID *connector.SecureBytes
	Host      *connector.SecureBytes
	Port      *connector.SecureBytes
	UseTLS    *connector.SecureBytes
}

var (
	sessions []SessionInfo
	mu       sync.Mutex
)

func AddSession(s SessionInfo) {
	mu.Lock()
	defer mu.Unlock()
	sessions = append(sessions, s)
}

func ListSessions() []SessionInfo {
	mu.Lock()
	defer mu.Unlock()
	return append([]SessionInfo(nil), sessions...) // cópia segura
}
