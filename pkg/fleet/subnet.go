package fleet

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// SubnetZone represents an enterprise network zone.
type SubnetZone string

const (
	ZoneWorkstations SubnetZone = "Workstations"
	ZoneDomainCtrls  SubnetZone = "DomainControllers"
	ZoneLinuxServers SubnetZone = "LinuxServers"
	ZoneDMZWeb       SubnetZone = "DMZWeb"
	ZoneFirewalls    SubnetZone = "PerimeterFirewalls"
)

// SubnetPool manages IP address allocation within a specific CIDR block.
type SubnetPool struct {
	Zone       SubnetZone
	CIDR       string
	Network    *net.IPNet
	Gateway    net.IP
	mu         sync.Mutex
	allocated  map[string]bool
	currentIdx uint32
}

// NewSubnetPool initializes a managed subnet pool.
func NewSubnetPool(zone SubnetZone, cidrStr string, gatewayStr string) (*SubnetPool, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
	}

	if ipNet.IP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 subnets are currently supported, got %q", cidrStr)
	}

	gw := net.ParseIP(gatewayStr).To4()
	if gw == nil {
		return nil, fmt.Errorf("invalid gateway IP %q", gatewayStr)
	}

	pool := &SubnetPool{
		Zone:       zone,
		CIDR:       cidrStr,
		Network:    ipNet,
		Gateway:    gw,
		allocated:  make(map[string]bool),
		currentIdx: 1, // Start at offset 1, skip network (.0), and let allocated map exclude gateway
	}
	pool.allocated[gw.String()] = true

	return pool, nil
}

// NextIP allocates the next sequential, unique IP from the pool.
func (p *SubnetPool) NextIP() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	baseInt := binary.BigEndian.Uint32(p.Network.IP.To4())
	maskInt := binary.BigEndian.Uint32(p.Network.Mask)
	broadcastInt := baseInt | (^maskInt)

	for {
		targetInt := baseInt + p.currentIdx
		p.currentIdx++

		if targetInt >= broadcastInt {
			return nil, fmt.Errorf("subnet pool %s (%s) exhausted", p.Zone, p.CIDR)
		}

		ipBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ipBytes, targetInt)
		ip := net.IP(ipBytes)

		if !p.allocated[ip.String()] {
			p.allocated[ip.String()] = true
			return ip, nil
		}
	}
}

// Reset clears all allocations in the pool.
func (p *SubnetPool) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allocated = make(map[string]bool)
	p.allocated[p.Gateway.String()] = true
	p.currentIdx = 1
}

