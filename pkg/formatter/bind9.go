package formatter

import (
	"math/rand"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/fleet"
)

// DNSQueryParams holds parameters for a BIND9 query record.
type DNSQueryParams struct {
	ClientIP   string
	ClientPort int
	Domain     string
	RecordType string // "A", "AAAA", "TXT", "MX", "PTR", "CNAME"
	ServerIP   string
	Status     string // "OK", "NXDOMAIN", "SERVFAIL"
}

// BIND9Formatter synthesizes standard BIND9 DNS query and resolution logs.
type BIND9Formatter struct{}

// NewBIND9Formatter constructs a BIND9 formatter.
func NewBIND9Formatter() *BIND9Formatter {
	return &BIND9Formatter{}
}

// FormatQuery serializes a BIND9 query line directly into the buffer in zero allocations.
func (f *BIND9Formatter) FormatQuery(buf *buffer.ByteBuffer, ep *fleet.Endpoint, params DNSQueryParams, ts time.Time) {
	// Timestamp: 02-Jan-2006 15:04:05.000
	buf.AppendTimeBIND9(ts)
	buf.AppendString(" client @0x7f481014a000 ")

	clientIP := params.ClientIP
	if clientIP == "" {
		clientIP = "10.100.1.15"
	}
	buf.AppendString(clientIP)
	buf.AppendByte('#')

	port := params.ClientPort
	if port <= 0 {
		port = 51920
	}
	buf.AppendInt(int64(port))

	domain := params.Domain
	if domain == "" {
		domain = "portal.corp.local"
	}

	buf.AppendString(" (")
	buf.AppendString(domain)
	buf.AppendString("): ")

	recordType := params.RecordType
	if recordType == "" {
		recordType = "A"
	}

	serverIP := params.ServerIP
	if serverIP == "" {
		if ep.IPStr != "" {
			serverIP = ep.IPStr
		} else {
			serverIP = "10.200.10.1"
		}
	}

	switch params.Status {
	case "NXDOMAIN":
		buf.AppendString("query failed (NXDOMAIN) for ")
		buf.AppendString(domain)
		buf.AppendString("/IN/")
		buf.AppendString(recordType)
		buf.AppendString(" at ")
		buf.AppendString(serverIP)

	case "SERVFAIL":
		buf.AppendString("query failed (SERVFAIL) for ")
		buf.AppendString(domain)
		buf.AppendString("/IN/")
		buf.AppendString(recordType)
		buf.AppendString(" at ")
		buf.AppendString(serverIP)

	default: // "OK" / Standard Query
		buf.AppendString("query: ")
		buf.AppendString(domain)
		buf.AppendString(" IN ")
		buf.AppendString(recordType)
		buf.AppendString(" + (")
		buf.AppendString(serverIP)
		buf.AppendByte(')')
	}
	buf.AppendByte('\n')
}

// FormatRandomDNSQuery synthesizes realistic enterprise name resolution traffic.
func (f *BIND9Formatter) FormatRandomDNSQuery(buf *buffer.ByteBuffer, ep *fleet.Endpoint, ts time.Time, rng *rand.Rand) {
	// Standard DNS distribution:
	// Internal service lookup: 60%
	// External internet lookup: 30%
	// NXDOMAIN failure: 10%
	r := rng.Intn(100)
	switch {
	case r < 60:
		internalDomains := []string{
			"portal.corp.local",
			"mail.corp.local",
			"dc01.corp.local",
			"git.corp.local",
			"fs01.corp.local",
		}
		d := internalDomains[rng.Intn(len(internalDomains))]
		f.FormatQuery(buf, ep, DNSQueryParams{
			Domain:     d,
			RecordType: "A",
			Status:     "OK",
			ClientIP:   "10.100.1.20",
			ClientPort: 49000 + rng.Intn(15000),
		}, ts)

	case r < 90:
		externalDomains := []string{
			"www.google.com",
			"api.github.com",
			"login.microsoftonline.com",
			"aws.amazon.com",
			"updates.ubuntu.com",
		}
		d := externalDomains[rng.Intn(len(externalDomains))]
		f.FormatQuery(buf, ep, DNSQueryParams{
			Domain:     d,
			RecordType: "A",
			Status:     "OK",
			ClientIP:   "10.100.1.22",
			ClientPort: 49000 + rng.Intn(15000),
		}, ts)

	default:
		// NXDOMAIN
		nxDomains := []string{
			"oldserver.corp.local",
			"wks-missing-99.corp.local",
			"test-dev-typo.corp.local",
			"invalid-endpoint.corp.local",
		}
		d := nxDomains[rng.Intn(len(nxDomains))]
		f.FormatQuery(buf, ep, DNSQueryParams{
			Domain:     d,
			RecordType: "A",
			Status:     "NXDOMAIN",
			ClientIP:   "10.100.1.25",
			ClientPort: 49000 + rng.Intn(15000),
		}, ts)
	}
}
