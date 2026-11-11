package formatter

import (
	"math/rand"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// PaloAltoTrafficParams holds configuration for PAN-OS Traffic Log CSV generation.
type PaloAltoTrafficParams struct {
	Action             string // "allow", "deny", "drop", "reset-client", "reset-server"
	SourceIP           string
	DestinationIP      string
	SourcePort         int
	DestinationPort    int
	Protocol           string // "tcp", "udp", "icmp"
	Application        string // "ssl", "web-browsing", "dns", "ssh", "ping"
	SourceZone         string // "trust", "untrust", "dmz"
	DestinationZone    string // "untrust", "dmz", "trust"
	InboundInterface   string // "ethernet1/1"
	OutboundInterface  string // "ethernet1/2"
	RuleName           string // "Allow-Corp-Web", "Drop-Untrusted-Inbound"
	SourceUser         string
	DestinationUser    string
	SessionID          uint64
	BytesSent          uint64
	BytesReceived      uint64
	PacketsSent        uint64
	PacketsReceived    uint64
	ElapsedTimeSec     uint32
	SessionEndReason   string // "aged-out", "tcp-fin", "policy-deny", "threat"
	URLCategory        string // "business-and-economy", "computer-and-internet-info", "any"
}

// PaloAltoThreatParams holds configuration for PAN-OS Threat Log CSV generation.
type PaloAltoThreatParams struct {
	ThreatType       string // "vulnerability", "virus", "spyware", "scan"
	ThreatID         string // "99999(Port Scan detected)"
	Severity         string // "informational", "low", "medium", "high", "critical"
	SourceIP         string
	DestinationIP    string
	SourcePort       int
	DestinationPort  int
	Protocol         string
	Application      string
	SourceZone       string
	DestinationZone  string
	InboundInterface string
	RuleName         string
	SessionID        uint64
}

// PaloAltoFormatter synthesizes authentic PAN-OS 10.x/11.x Traffic and Threat CSV records.
type PaloAltoFormatter struct {
	serialNumber string
}

// NewPaloAltoFormatter constructs a Palo Alto formatter.
func NewPaloAltoFormatter() *PaloAltoFormatter {
	return &PaloAltoFormatter{
		serialNumber: "001801004215",
	}
}

// FormatTraffic serializes a 54-column PAN-OS Traffic log in zero allocations.
func (f *PaloAltoFormatter) FormatTraffic(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params PaloAltoTrafficParams, seq uint64, ts time.Time) {
	// Column 1: FUTURE_USE / Log format marker
	buf.AppendString("1,")

	// Column 2: ReceiveTime (YYYY/MM/DD HH:MM:SS)
	buf.AppendTimePANOS(ts)
	buf.AppendByte(',')

	// Column 3: SerialNumber
	buf.AppendString(f.serialNumber)
	buf.AppendByte(',')

	// Column 4: Type
	buf.AppendString("TRAFFIC,")

	// Column 5: Subtype
	action := defaultVal(params.Action, "allow")
	buf.AppendString(action)
	buf.AppendByte(',')

	// Column 6: FUTURE_USE_2 / Config version
	buf.AppendString("2304,")

	// Column 7: GeneratedTime
	buf.AppendTimePANOS(ts)
	buf.AppendByte(',')

	// Column 8: SourceIP
	srcIP := params.SourceIP
	if srcIP == "" {
		srcIP = "10.100.1.15"
	}
	buf.AppendString(srcIP)
	buf.AppendByte(',')

	// Column 9: DestinationIP
	dstIP := params.DestinationIP
	if dstIP == "" {
		dstIP = "172.16.10.15"
	}
	buf.AppendString(dstIP)
	buf.AppendByte(',')

	// Column 10: NATSourceIP
	buf.AppendString("0.0.0.0,")

	// Column 11: NATDestinationIP
	buf.AppendString("0.0.0.0,")

	// Column 12: RuleName
	buf.AppendString(defaultVal(params.RuleName, "Default-Allow-Web"))
	buf.AppendByte(',')

	// Column 13: SourceUser
	buf.AppendString(params.SourceUser)
	buf.AppendByte(',')

	// Column 14: DestinationUser
	buf.AppendString(params.DestinationUser)
	buf.AppendByte(',')

	// Column 15: Application
	buf.AppendString(defaultVal(params.Application, "ssl"))
	buf.AppendByte(',')

	// Column 16: VirtualSystem
	buf.AppendString("vsys1,")

	// Column 17: SourceZone
	buf.AppendString(defaultVal(params.SourceZone, "trust"))
	buf.AppendByte(',')

	// Column 18: DestinationZone
	buf.AppendString(defaultVal(params.DestinationZone, "untrust"))
	buf.AppendByte(',')

	// Column 19: InboundInterface
	buf.AppendString(defaultVal(params.InboundInterface, "ethernet1/1"))
	buf.AppendByte(',')

	// Column 20: OutboundInterface
	buf.AppendString(defaultVal(params.OutboundInterface, "ethernet1/2"))
	buf.AppendByte(',')

	// Column 21: LogForwardingProfile
	buf.AppendString("Forward-All,")

	// Column 22: TimeLogged
	buf.AppendTimePANOS(ts)
	buf.AppendByte(',')

	// Column 23: SessionID
	sessionID := params.SessionID
	if sessionID == 0 {
		sessionID = 100000 + (seq % 800000)
	}
	buf.AppendUint(sessionID)
	buf.AppendByte(',')

	// Column 24: RepeatCount
	buf.AppendString("1,")

	// Column 25: SourcePort
	srcPort := params.SourcePort
	if srcPort == 0 {
		srcPort = 50000 + int(seq%15000)
	}
	buf.AppendInt(int64(srcPort))
	buf.AppendByte(',')

	// Column 26: DestinationPort
	dstPort := params.DestinationPort
	if dstPort == 0 {
		dstPort = 443
	}
	buf.AppendInt(int64(dstPort))
	buf.AppendByte(',')

	// Column 27: NATSourcePort
	buf.AppendString("0,")

	// Column 28: NATDestinationPort
	buf.AppendString("0,")

	// Column 29: Flags
	buf.AppendString("0x0,")

	// Column 30: Protocol
	buf.AppendString(defaultVal(params.Protocol, "tcp"))
	buf.AppendByte(',')

	// Column 31: Action
	buf.AppendString(action)
	buf.AppendByte(',')

	// Column 32: Total Bytes
	bytesSent := params.BytesSent
	if bytesSent == 0 && action == "allow" {
		bytesSent = 840
	}
	bytesRecv := params.BytesReceived
	if bytesRecv == 0 && action == "allow" {
		bytesRecv = 580
	}
	totalBytes := bytesSent + bytesRecv
	buf.AppendUint(totalBytes)
	buf.AppendByte(',')

	// Column 33: BytesSent
	buf.AppendUint(bytesSent)
	buf.AppendByte(',')

	// Column 34: BytesReceived
	buf.AppendUint(bytesRecv)
	buf.AppendByte(',')

	// Column 35: Packets
	packetsSent := params.PacketsSent
	if packetsSent == 0 && action == "allow" {
		packetsSent = 7
	}
	packetsRecv := params.PacketsReceived
	if packetsRecv == 0 && action == "allow" {
		packetsRecv = 5
	}
	totalPackets := packetsSent + packetsRecv
	buf.AppendUint(totalPackets)
	buf.AppendByte(',')

	// Column 36: StartTime
	buf.AppendTimePANOS(ts)
	buf.AppendByte(',')

	// Column 37: ElapsedTime (seconds)
	buf.AppendUint(uint64(params.ElapsedTimeSec))
	buf.AppendByte(',')

	// Column 38: URLCategory
	buf.AppendString(defaultVal(params.URLCategory, "any"))
	buf.AppendByte(',')

	// Column 39: FUTURE_USE_4
	buf.AppendString("0,")

	// Column 40: SequenceNumber
	buf.AppendUint(seq)
	buf.AppendByte(',')

	// Column 41: ActionFlags
	buf.AppendString("0x0,")

	// Column 42: SourceLocation
	buf.AppendString("US,")

	// Column 43: DestinationLocation
	buf.AppendString("US,")

	// Column 44: FUTURE_USE_5
	buf.AppendString("0,")

	// Column 45: PacketsSent
	buf.AppendUint(packetsSent)
	buf.AppendByte(',')

	// Column 46: PacketsReceived
	buf.AppendUint(packetsRecv)
	buf.AppendByte(',')

	// Column 47: SessionEndReason
	endReason := params.SessionEndReason
	if endReason == "" {
		if action == "allow" {
			endReason = "tcp-fin"
		} else {
			endReason = "policy-deny"
		}
	}
	buf.AppendString(endReason)
	buf.AppendByte(',')

	// Column 48-51: DeviceGroupHierarchyL1-L4
	buf.AppendString("0,0,0,0,,")

	// Column 53: DeviceName
	buf.AppendString(ep.Hostname)
	buf.AppendByte(',')

	// Column 54: ActionSource
	buf.AppendString("from-policy\n")
}

// FormatThreat serializes a PAN-OS Threat Log CSV record.
func (f *PaloAltoFormatter) FormatThreat(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params PaloAltoThreatParams, seq uint64, ts time.Time) {
	buf.AppendString("1,")
	buf.AppendTimePANOS(ts)
	buf.AppendByte(',')
	buf.AppendString(f.serialNumber)
	buf.AppendString(",THREAT,")
	buf.AppendString(defaultVal(params.ThreatType, "vulnerability"))
	buf.AppendString(",2304,")
	buf.AppendTimePANOS(ts)
	buf.AppendByte(',')

	srcIP := defaultVal(params.SourceIP, "192.168.1.105")
	dstIP := defaultVal(params.DestinationIP, "10.200.10.15")
	buf.AppendString(srcIP)
	buf.AppendByte(',')
	buf.AppendString(dstIP)
	buf.AppendString(",0.0.0.0,0.0.0.0,")
	buf.AppendString(defaultVal(params.RuleName, "Alert-Threats"))
	buf.AppendString(",,,,")
	buf.AppendString(defaultVal(params.Application, "web-browsing"))
	buf.AppendString(",vsys1,")
	buf.AppendString(defaultVal(params.SourceZone, "untrust"))
	buf.AppendByte(',')
	buf.AppendString(defaultVal(params.DestinationZone, "dmz"))
	buf.AppendByte(',')
	buf.AppendString(defaultVal(params.InboundInterface, "ethernet1/1"))
	buf.AppendString(",ethernet1/2,Forward-All,")
	buf.AppendTimePANOS(ts)
	buf.AppendByte(',')

	sessionID := params.SessionID
	if sessionID == 0 {
		sessionID = 200000 + (seq % 700000)
	}
	buf.AppendUint(sessionID)
	buf.AppendString(",1,")

	srcPort := params.SourcePort
	if srcPort == 0 {
		srcPort = 45123
	}
	buf.AppendInt(int64(srcPort))
	buf.AppendByte(',')

	dstPort := params.DestinationPort
	if dstPort == 0 {
		dstPort = 80
	}
	buf.AppendInt(int64(dstPort))
	buf.AppendString(",0,0,0x0,")
	buf.AppendString(defaultVal(params.Protocol, "tcp"))
	buf.AppendString(",alert,\"")
	buf.AppendString(defaultVal(params.ThreatID, "99999(Port Scan detected)"))
	buf.AppendString("\",,0,any,0,")
	buf.AppendUint(seq)
	buf.AppendString(",0x0,US,US,0,0,0,")
	buf.AppendString(defaultVal(params.Severity, "medium"))
	buf.AppendString(",0,0,0,0,,")
	buf.AppendString(ep.Hostname)
	buf.AppendString(",from-policy\n")
}

// FormatRandomFirewallEvent generates a realistic stream of traffic and threat records.
func (f *PaloAltoFormatter) FormatRandomFirewallEvent(buf *buffer.ByteBuffer, ep *fleet.Endpoint, seq uint64, ts time.Time, rng *rand.Rand) {
	// Standard network operational weighting:
	// Allow: 80%
	// Deny/Drop: 18%
	// Threat alert: 2%
	r := rng.Intn(100)
	switch {
	case r < 80:
		// Normal traffic allow
		apps := []struct {
			name string
			port int
		}{
			{"ssl", 443},
			{"web-browsing", 80},
			{"dns", 53},
			{"ssh", 22},
		}
		app := apps[rng.Intn(len(apps))]
		f.FormatTraffic(buf, ep, PaloAltoTrafficParams{
			Action:          "allow",
			SourceIP:        "10.100.1.15",
			DestinationIP:   "172.16.10.10",
			DestinationPort: app.port,
			Application:     app.name,
			SourceZone:      "trust",
			DestinationZone: "untrust",
			RuleName:        "Allow-Web-Outbound",
			BytesSent:       uint64(500 + rng.Intn(2000)),
			BytesReceived:   uint64(1000 + rng.Intn(50000)),
		}, seq, ts)

	case r < 98:
		// Dropped inbound traffic
		f.FormatTraffic(buf, ep, PaloAltoTrafficParams{
			Action:          "drop",
			SourceIP:        "192.168.1.100",
			DestinationIP:   "172.16.10.15",
			DestinationPort: 1024 + rng.Intn(60000),
			Application:     "incomplete",
			SourceZone:      "untrust",
			DestinationZone: "dmz",
			RuleName:        "Default-Deny-Untrusted",
			BytesSent:       64,
			BytesReceived:   0,
			PacketsSent:     1,
			PacketsReceived: 0,
		}, seq, ts)

	default:
		// Threat Alert
		threats := []struct {
			id       string
			severity string
		}{
			{"99999(Port Scan detected)", "medium"},
			{"30003(SQL Injection Attempt)", "high"},
			{"40001(SSH Brute Force Detected)", "critical"},
		}
		t := threats[rng.Intn(len(threats))]
		f.FormatThreat(buf, ep, PaloAltoThreatParams{
			ThreatType: "scan",
			ThreatID:   t.id,
			Severity:   t.severity,
			SourceIP:   "192.168.1.200",
		}, seq, ts)
	}
}
