package fleet

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/config"
)

// FleetManager manages logical endpoint generation, role routing, and IP allocation.
type FleetManager struct {
	mu              sync.RWMutex
	rngMu           sync.Mutex
	endpoints       []*Endpoint
	endpointsByID   map[string]*Endpoint
	endpointsByRole map[Role][]*Endpoint
	subnets         map[SubnetZone]*SubnetPool
	rng             *rand.Rand
	sampleCounter   uint64
}

// NewFleetManager initializes a FleetManager with isolated subnet pools.
func NewFleetManager(seed int64) (*FleetManager, error) {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	fm := &FleetManager{
		endpoints:       make([]*Endpoint, 0),
		endpointsByID:   make(map[string]*Endpoint),
		endpointsByRole: make(map[Role][]*Endpoint),
		subnets:         make(map[SubnetZone]*SubnetPool),
		rng:             rand.New(rand.NewSource(seed)),
	}

	// Initialize standard enterprise subnets
	workstations, err := NewSubnetPool(ZoneWorkstations, "10.100.0.0/16", "10.100.0.1")
	if err != nil {
		return nil, err
	}
	dcPool, err := NewSubnetPool(ZoneDomainCtrls, "10.200.10.0/24", "10.200.10.1")
	if err != nil {
		return nil, err
	}
	linuxPool, err := NewSubnetPool(ZoneLinuxServers, "10.200.20.0/24", "10.200.20.1")
	if err != nil {
		return nil, err
	}
	dmzPool, err := NewSubnetPool(ZoneDMZWeb, "172.16.10.0/24", "172.16.10.1")
	if err != nil {
		return nil, err
	}
	fwPool, err := NewSubnetPool(ZoneFirewalls, "192.168.1.0/24", "192.168.1.1")
	if err != nil {
		return nil, err
	}

	fm.subnets[ZoneWorkstations] = workstations
	fm.subnets[ZoneDomainCtrls] = dcPool
	fm.subnets[ZoneLinuxServers] = linuxPool
	fm.subnets[ZoneDMZWeb] = dmzPool
	fm.subnets[ZoneFirewalls] = fwPool

	return fm, nil
}

// GenerateFleet creates logical endpoints according to the provided configuration.
func (fm *FleetManager) GenerateFleet(cfg config.FleetConfig) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	// Reset existing fleet and pools
	fm.endpoints = make([]*Endpoint, 0, cfg.TotalEndpoints)
	fm.endpointsByID = make(map[string]*Endpoint)
	fm.endpointsByRole = make(map[Role][]*Endpoint)
	for _, pool := range fm.subnets {
		pool.Reset()
	}

	dist := cfg.Distribution
	if dist.WindowsWorkstations < 0 || dist.LinuxServers < 0 || dist.Firewalls < 0 || dist.DNSServers < 0 || dist.WebServers < 0 {
		return fmt.Errorf("role percentages cannot be negative")
	}

	wksCount := (cfg.TotalEndpoints * dist.WindowsWorkstations) / 100
	linuxCount := (cfg.TotalEndpoints * dist.LinuxServers) / 100
	fwCount := (cfg.TotalEndpoints * dist.Firewalls) / 100
	dnsCount := (cfg.TotalEndpoints * dist.DNSServers) / 100
	webCount := (cfg.TotalEndpoints * dist.WebServers) / 100

	// Rounding adjustment
	totalCalculated := wksCount + linuxCount + fwCount + dnsCount + webCount
	if remainder := cfg.TotalEndpoints - totalCalculated; remainder > 0 {
		wksCount += remainder
	}

	// 1. Generate Windows Workstations
	for i := 1; i <= wksCount; i++ {
		ip, err := fm.subnets[ZoneWorkstations].NextIP()
		if err != nil {
			return fmt.Errorf("failed to allocate IP for workstation %d: %w", i, err)
		}
		ep := fm.buildWorkstation(i, ip)
		fm.addEndpoint(ep)
	}

	// 2. Generate Linux Servers
	for i := 1; i <= linuxCount; i++ {
		ip, err := fm.subnets[ZoneLinuxServers].NextIP()
		if err != nil {
			return fmt.Errorf("failed to allocate IP for linux server %d: %w", i, err)
		}
		ep := fm.buildLinuxServer(i, ip)
		fm.addEndpoint(ep)
	}

	// 3. Generate Firewalls
	for i := 1; i <= fwCount; i++ {
		ip, err := fm.subnets[ZoneFirewalls].NextIP()
		if err != nil {
			return fmt.Errorf("failed to allocate IP for firewall %d: %w", i, err)
		}
		ep := fm.buildFirewall(i, ip)
		fm.addEndpoint(ep)
	}

	// 4. Generate DNS Servers
	for i := 1; i <= dnsCount; i++ {
		ip, err := fm.subnets[ZoneDomainCtrls].NextIP()
		if err != nil {
			return fmt.Errorf("failed to allocate IP for DNS server %d: %w", i, err)
		}
		ep := fm.buildDNSServer(i, ip)
		fm.addEndpoint(ep)
	}

	// 5. Generate Web Servers
	for i := 1; i <= webCount; i++ {
		ip, err := fm.subnets[ZoneDMZWeb].NextIP()
		if err != nil {
			return fmt.Errorf("failed to allocate IP for web server %d: %w", i, err)
		}
		ep := fm.buildWebServer(i, ip)
		fm.addEndpoint(ep)
	}

	return nil
}

func (fm *FleetManager) addEndpoint(ep *Endpoint) {
	fm.endpoints = append(fm.endpoints, ep)
	fm.endpointsByID[ep.ID] = ep
	fm.endpointsByRole[ep.Role] = append(fm.endpointsByRole[ep.Role], ep)
}

func (fm *FleetManager) buildWorkstation(idx int, ip net.IP) *Endpoint {
	deptMap := map[string]string{
		"Finance":     "FIN",
		"Engineering": "ENG",
		"HR":          "HRD",
		"Sales":       "SAL",
		"Legal":       "LEG",
		"Marketing":   "MKT",
	}
	depts := []string{"Finance", "Engineering", "HR", "Sales", "Legal", "Marketing"}
	dept := depts[fm.rng.Intn(len(depts))]
	deptCode := deptMap[dept]
	userSIDs := map[string]string{
		"alice.smith": "S-1-5-21-3623811015-3361044348-30300820-1101",
		"bob.jones":   "S-1-5-21-3623811015-3361044348-30300820-1102",
		"carol.white": "S-1-5-21-3623811015-3361044348-30300820-1103",
		"david.clark": "S-1-5-21-3623811015-3361044348-30300820-1104",
		"emma.davis":  "S-1-5-21-3623811015-3361044348-30300820-1105",
	}
	userList := []string{"alice.smith", "bob.jones", "carol.white", "david.clark", "emma.davis"}
	userName := userList[fm.rng.Intn(len(userList))]
	userSID := userSIDs[userName]

	initialLogonID := uint64(0x100000 + idx*16)

	return &Endpoint{
		ID:             fmt.Sprintf("EP-WIN-WKS-%04d", idx),
		Hostname:       fmt.Sprintf("WKS-%s-%03d.corp.local", deptCode, idx),
		Domain:         "CORP.LOCAL",
		IP:             ip,
		MAC:            fm.generateMAC(0x00, 0x50, 0x56), // VMware OUI
		Role:           RoleWorkstation,
		OSFamily:       "Windows",
		OSVersion:      "Windows 11 Enterprise 23H2 (Build 22631.3007)",
		Department:     dept,
		ActiveUsers: []ActiveUser{
			{
				Username:  userName,
				Domain:    "CORP",
				UserSID:   userSID,
				LogonID:   fmt.Sprintf("0x%X", initialLogonID),
				LogonTime: time.Now().UTC().Add(-4 * time.Hour),
			},
		},
		EnabledSources: []string{"windows_security_xml", "windows_sysmon"},
		Weight:         1.0,
		currentPID:     2048,
		currentLogonID: initialLogonID + 1,
	}
}

func (fm *FleetManager) buildLinuxServer(idx int, ip net.IP) *Endpoint {
	return &Endpoint{
		ID:             fmt.Sprintf("EP-LNX-SRV-%04d", idx),
		Hostname:       fmt.Sprintf("srv-prod-app%02d.corp.local", idx),
		Domain:         "corp.local",
		IP:             ip,
		MAC:            fm.generateMAC(0x52, 0x54, 0x00), // QEMU/KVM OUI
		Role:           RoleLinuxServer,
		OSFamily:       "Linux",
		OSVersion:      "Ubuntu 22.04.4 LTS (Jammy Jellyfish)",
		Department:     "IT Operations",
		ActiveUsers: []ActiveUser{
			{
				Username:  "sysadmin",
				Domain:    "corp.local",
				UserSID:   "1000",
				LogonID:   "pts/0",
				LogonTime: time.Now().UTC().Add(-12 * time.Hour),
			},
		},
		EnabledSources: []string{"linux_auth_syslog", "auditd"},
		Weight:         1.5,
		currentPID:     14200,
	}
}

func (fm *FleetManager) buildFirewall(idx int, ip net.IP) *Endpoint {
	return &Endpoint{
		ID:             fmt.Sprintf("EP-FW-PERIM-%04d", idx),
		Hostname:       fmt.Sprintf("pa-perim-fw%02d.corp.local", idx),
		Domain:         "corp.local",
		IP:             ip,
		MAC:            fm.generateMAC(0x00, 0x1B, 0x17), // Palo Alto Networks OUI
		Role:           RoleFirewall,
		OSFamily:       "PAN-OS",
		OSVersion:      "PAN-OS 11.0.2-h1",
		Department:     "Network Security",
		ActiveUsers:    []ActiveUser{},
		EnabledSources: []string{"paloalto_traffic_csv", "paloalto_threat_csv"},
		Weight:         2.0,
	}
}

func (fm *FleetManager) buildDNSServer(idx int, ip net.IP) *Endpoint {
	return &Endpoint{
		ID:             fmt.Sprintf("EP-DNS-CORE-%04d", idx),
		Hostname:       fmt.Sprintf("ns%02d.corp.local", idx),
		Domain:         "corp.local",
		IP:             ip,
		MAC:            fm.generateMAC(0x00, 0x0C, 0x29), // VMware OUI
		Role:           RoleDNSServer,
		OSFamily:       "Linux",
		OSVersion:      "Debian GNU/Linux 12 (bookworm)",
		Department:     "Core Infrastructure",
		ActiveUsers:    []ActiveUser{},
		EnabledSources: []string{"bind9_dns_query"},
		Weight:         2.5,
	}
}

func (fm *FleetManager) buildWebServer(idx int, ip net.IP) *Endpoint {
	return &Endpoint{
		ID:             fmt.Sprintf("EP-WEB-DMZ-%04d", idx),
		Hostname:       fmt.Sprintf("portal-web%02d.corp.local", idx),
		Domain:         "corp.local",
		IP:             ip,
		MAC:            fm.generateMAC(0x00, 0x16, 0x3E), // Xen OUI
		Role:           RoleWebServer,
		OSFamily:       "Linux",
		OSVersion:      "Ubuntu 22.04.4 LTS",
		Department:     "Digital Services",
		ActiveUsers:    []ActiveUser{},
		EnabledSources: []string{"nginx_combined_access"},
		Weight:         1.8,
	}
}

func (fm *FleetManager) generateMAC(b1, b2, b3 byte) net.HardwareAddr {
	return net.HardwareAddr{
		b1, b2, b3,
		byte(fm.rng.Intn(256)),
		byte(fm.rng.Intn(256)),
		byte(fm.rng.Intn(256)),
	}
}

// SampleRandom returns an endpoint from the fleet in a thread-safe, lock-free round-robin manner.
func (fm *FleetManager) SampleRandom() *Endpoint {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	n := len(fm.endpoints)
	if n == 0 {
		return nil
	}
	idx := atomic.AddUint64(&fm.sampleCounter, 1) % uint64(n)
	return fm.endpoints[idx]
}

// SampleWeighted selects an endpoint based on assigned Endpoint.Weight.
func (fm *FleetManager) SampleWeighted() *Endpoint {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	if len(fm.endpoints) == 0 {
		return nil
	}
	var totalWeight float64
	for _, ep := range fm.endpoints {
		totalWeight += ep.Weight
	}
	if totalWeight <= 0 {
		return fm.SampleRandom()
	}
	fm.rngMu.Lock()
	r := fm.rng.Float64() * totalWeight
	fm.rngMu.Unlock()

	for _, ep := range fm.endpoints {
		r -= ep.Weight
		if r <= 0 {
			return ep
		}
	}
	return fm.endpoints[len(fm.endpoints)-1]
}

// SampleByRole returns an endpoint matching the specified role in a thread-safe, lock-free manner.
func (fm *FleetManager) SampleByRole(role Role) (*Endpoint, error) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	group := fm.endpointsByRole[role]
	n := len(group)
	if n == 0 {
		return nil, fmt.Errorf("no endpoints found for role %s", role)
	}
	idx := atomic.AddUint64(&fm.sampleCounter, 1) % uint64(n)
	return group[idx], nil
}

// GetEndpoint retrieves an endpoint by its unique identifier.
func (fm *FleetManager) GetEndpoint(id string) (*Endpoint, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	ep, exists := fm.endpointsByID[id]
	return ep, exists
}

// Endpoints returns a slice of all logical endpoints in the fleet.
func (fm *FleetManager) Endpoints() []*Endpoint {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	result := make([]*Endpoint, len(fm.endpoints))
	copy(result, fm.endpoints)
	return result
}

// TotalCount returns the current count of logical endpoints in the fleet.
func (fm *FleetManager) TotalCount() int {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return len(fm.endpoints)
}
