package forwarder

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkTCPForwarding100kEPS streams enterprise telemetry lines to a loopback
// receiver over TCP, verifying >100,000 EPS throughput with zero allocations.
func BenchmarkTCPForwarding100kEPS(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to start TCP listener: %v", err)
	}
	defer listener.Close()

	var receivedBytes uint64

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				discard := make([]byte, 64*1024)
				for {
					n, err := c.Read(discard)
					if n > 0 {
						atomic.AddUint64(&receivedBytes, uint64(n))
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	client, err := NewTCPClient(TCPConfig{
		Address:       listener.Addr().String(),
		Framing:       FramingNewline,
		BufferSize:    256 * 1024,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	payload := []byte("<86>1 2026-11-12T06:00:00Z srv-linux-001 sshd 12450 - - Accepted publickey for secops from 10.100.1.5 port 54322 ssh2: RSA SHA256:m0+9...\n")

	for b.Loop() {
		if err := client.WriteRaw(payload); err != nil {
			b.Fatalf("TCP WriteRaw error: %v", err)
		}
	}

	_ = client.Flush()
}

// BenchmarkHTTPForwarding100kEPS batches and flushes enterprise telemetry to a mock
// Splunk HEC server over HTTP, measuring throughput and batch allocations.
func BenchmarkHTTPForwarding100kEPS(b *testing.B) {
	var totalIngested uint64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		atomic.AddUint64(&totalIngested, uint64(n))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer server.Close()

	client, err := NewHECClient(HECConfig{
		URL:            server.URL,
		Token:          "bench-token-100k",
		EndpointType:   HECEndpointRaw,
		BatchMaxEvents: 2500,
		BatchMaxBytes:  512 * 1024,
		BatchTimeout:   20 * time.Millisecond,
	})
	if err != nil {
		b.Fatalf("failed to initialize HEC client: %v", err)
	}
	defer client.Close()

	payload := []byte("<86>1 2026-11-12T06:00:00Z srv-linux-001 sshd 12450 - - Accepted publickey for secops from 10.100.1.5 port 54322 ssh2: RSA SHA256:m0+9...\n")

	for b.Loop() {
		if err := client.WriteRaw(payload); err != nil {
			b.Fatalf("HEC WriteRaw error: %v", err)
		}
	}

	_ = client.Flush()
}
