package fleet

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// Role defines the functional role of a logical endpoint.
type Role string

const (
	RoleWorkstation      Role = "Workstation"
	RoleDomainController Role = "DomainController"
	RoleLinuxServer      Role = "LinuxServer"
	RoleFirewall         Role = "Firewall"
	RoleDNSServer        Role = "DNSServer"
	RoleWebServer        Role = "WebServer"
)

// ActiveUser represents a simulated user session currently authenticated on an endpoint.
type ActiveUser struct {
	Username  string    `json:"username"`
	Domain    string    `json:"domain"`
	UserSID   string    `json:"user_sid"`
	LogonID   string    `json:"logon_id"`
	LogonTime time.Time `json:"logon_time"`
}

// Endpoint represents a simulated enterprise node with full identity context.
type Endpoint struct {
	ID             string          `json:"id"`
	Hostname       string          `json:"hostname"`
	Domain         string          `json:"domain"`
	IP             net.IP          `json:"ip"`
	MAC            net.HardwareAddr`json:"mac"`
	Role           Role            `json:"role"`
	OSFamily       string          `json:"os_family"`
	OSVersion      string          `json:"os_version"`
	Department     string          `json:"department"`
	ActiveUsers    []ActiveUser    `json:"active_users"`
	EnabledSources []string        `json:"enabled_sources"`
	Weight         float64         `json:"weight"`

	// Thread-safe state progression counters
	currentPID     uint32
	currentLogonID uint64
}

// NextPID returns a monotonically increasing process ID (PID) for this endpoint.
func (e *Endpoint) NextPID() uint32 {
	pid := atomic.AddUint32(&e.currentPID, 4)
	if pid < 1000 {
		atomic.StoreUint32(&e.currentPID, 1024)
		return 1024
	}
	return pid
}

// NextLogonHex returns a realistic Windows hex logon ID (e.g., 0x1A2B3C).
func (e *Endpoint) NextLogonHex() string {
	id := atomic.AddUint64(&e.currentLogonID, 1)
	return fmt.Sprintf("0x%X", id)
}

// PrimaryUser returns the default active user on this endpoint or a synthetic fallback.
func (e *Endpoint) PrimaryUser() ActiveUser {
	if len(e.ActiveUsers) > 0 {
		return e.ActiveUsers[0]
	}
	return ActiveUser{
		Username:  "system",
		Domain:    e.Domain,
		UserSID:   "S-1-5-18",
		LogonID:   "0x3E7",
		LogonTime: time.Now().UTC().Add(-8 * time.Hour),
	}
}

