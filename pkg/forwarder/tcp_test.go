package forwarder

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
)

func startMockTCPListener(t *testing.T) (net.Listener, string) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	return l, l.Addr().String()
}

func TestTCPForwarderNewlineFraming(t *testing.T) {
	listener, addr := startMockTCPListener(t)
	defer listener.Close()

	var receivedLines []string
	var mu sync.Mutex
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			mu.Lock()
			receivedLines = append(receivedLines, scanner.Text())
			mu.Unlock()
		}
	}()

	client, err := NewTCPClient(TCPConfig{
		Address:       addr,
		Framing:       FramingNewline,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	buf := buffer.GetBuffer()
	buf.AppendString("<86>Nov 12 05:00:00 srv01 sshd[100]: Accepted publickey")
	if err := client.WriteEvent(buf); err != nil {
		t.Fatalf("WriteEvent 1 failed: %v", err)
	}
	buf.Release()

	buf = buffer.GetBuffer()
	buf.AppendString("<85>Nov 12 05:00:01 srv01 sshd[101]: Failed password")
	if err := client.WriteEvent(buf); err != nil {
		t.Fatalf("WriteEvent 2 failed: %v", err)
	}
	buf.Release()

	if err := client.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Close client to signal EOF to receiver and wait for clean receiver termination
	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for receiver goroutine")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(receivedLines) != 2 {
		t.Fatalf("expected 2 received lines, got %d", len(receivedLines))
	}
	if !strings.Contains(receivedLines[0], "Accepted publickey") {
		t.Errorf("line 1 mismatch: %s", receivedLines[0])
	}
	if !strings.Contains(receivedLines[1], "Failed password") {
		t.Errorf("line 2 mismatch: %s", receivedLines[1])
	}

	stats := client.Stats()
	if stats.EventsSubmitted != 2 {
		t.Errorf("expected 2 events submitted, got %d", stats.EventsSubmitted)
	}
}

func TestTCPForwarderEmbeddedNewlineRejected(t *testing.T) {
	listener, addr := startMockTCPListener(t)
	defer listener.Close()

	client, err := NewTCPClient(TCPConfig{
		Address: addr,
		Framing: FramingNewline,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// Internal newline must be rejected
	err = client.WriteRaw([]byte("<86>Line1\nLine2"))
	if !errors.Is(err, ErrEmbeddedNewline) {
		t.Fatalf("expected ErrEmbeddedNewline, got %v", err)
	}

	// Trailing single newline must be accepted
	err = client.WriteRaw([]byte("<86>Line1 Single\n"))
	if err != nil {
		t.Fatalf("expected nil for trailing newline, got %v", err)
	}
}

func TestTCPForwarderOctetCountingFraming(t *testing.T) {
	listener, addr := startMockTCPListener(t)
	defer listener.Close()

	var receivedMessages []string
	var mu sync.Mutex
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for {
			lenStr, err := reader.ReadString(' ')
			if err != nil {
				return
			}
			length, err := strconv.Atoi(strings.TrimSpace(lenStr))
			if err != nil {
				return
			}
			msgBytes := make([]byte, length)
			if _, err := io.ReadFull(reader, msgBytes); err != nil {
				return
			}
			mu.Lock()
			receivedMessages = append(receivedMessages, string(msgBytes))
			mu.Unlock()
		}
	}()

	client, err := NewTCPClient(TCPConfig{
		Address:       addr,
		Framing:       FramingOctetCounting,
		FlushInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	payload1 := "<86>1 2026-11-12T05:00:00Z srv01 app 1 - - test message 1"
	payload2 := "<86>1 2026-11-12T05:00:01Z srv01 app 2 - - test message 2"

	if err := client.WriteRaw([]byte(payload1)); err != nil {
		t.Fatalf("WriteRaw 1 failed: %v", err)
	}
	if err := client.WriteRaw([]byte(payload2)); err != nil {
		t.Fatalf("WriteRaw 2 failed: %v", err)
	}
	if err := client.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Close client to signal EOF to receiver
	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for octet-counting receiver")
	}

	mu.Lock()
	defer mu.Unlock()

	if len(receivedMessages) != 2 {
		t.Fatalf("expected 2 octet-counted messages, got %d", len(receivedMessages))
	}
	if receivedMessages[0] != payload1 {
		t.Errorf("msg 1 mismatch: %s", receivedMessages[0])
	}
	if receivedMessages[1] != payload2 {
		t.Errorf("msg 2 mismatch: %s", receivedMessages[1])
	}
}

func TestTCPForwarderPool(t *testing.T) {
	listener, addr := startMockTCPListener(t)
	defer listener.Close()

	var count uint64
	const totalEvents = 2000
	receivedAll := make(chan struct{})
	var once sync.Once

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					if atomic.AddUint64(&count, 1) == totalEvents {
						once.Do(func() { close(receivedAll) })
					}
				}
			}(conn)
		}
	}()

	pool, err := NewTCPForwarderPool(TCPConfig{
		Address:        addr,
		Framing:        FramingNewline,
		FlushInterval:  10 * time.Millisecond,
		ReconnectDelay: 10 * time.Millisecond,
	}, 4)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	var wg sync.WaitGroup
	wg.Add(4)

	for w := 0; w < 4; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < totalEvents/4; i++ {
				buf := buffer.GetBuffer()
				buf.AppendString("<86>Log line from worker ")
				buf.AppendInt(int64(workerID))
				buf.AppendString(" iteration ")
				buf.AppendInt(int64(i))
				if err := pool.WriteEvent(buf); err != nil {
					t.Errorf("WriteEvent failed: %v", err)
				}
				buf.Release()
			}
		}(w)
	}

	wg.Wait()
	if err := pool.Flush(); err != nil {
		t.Fatalf("pool Flush failed: %v", err)
	}

	select {
	case <-receivedAll:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %d events, got %d", totalEvents, atomic.LoadUint64(&count))
	}

	stats := pool.Stats()
	if stats.EventsSubmitted != totalEvents {
		t.Errorf("expected %d events submitted in pool stats, got %d", totalEvents, stats.EventsSubmitted)
	}
	if atomic.LoadUint64(&count) != totalEvents {
		t.Errorf("expected %d events received by mock listener, got %d", totalEvents, atomic.LoadUint64(&count))
	}
}

func BenchmarkTCPStreamingThroughput(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	var receivedBytes uint64
	var serverWg sync.WaitGroup

	// Blackhole receiver with byte accounting
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serverWg.Add(1)
			go func(c net.Conn) {
				defer serverWg.Done()
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

	pool, err := NewTCPForwarderPool(TCPConfig{
		Address:       listener.Addr().String(),
		Framing:       FramingNewline,
		BufferSize:    256 * 1024,
		FlushInterval: 10 * time.Millisecond,
	}, 4)
	if err != nil {
		b.Fatalf("failed to create forwarder pool: %v", err)
	}
	defer pool.Close()

	samplePayload := []byte("<86>Nov 12 05:00:00 srv-prod-app01 sshd[14205]: Accepted publickey for sysadmin from 10.100.1.25 port 54321 ssh2: RSA SHA256:4t7Xg617B5B6x44k9Z1X2Y3Z\n")

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := pool.WriteRaw(samplePayload); err != nil {
				b.Fatalf("WriteRaw error in benchmark: %v", err)
			}
		}
	})

	if err := pool.Flush(); err != nil {
		b.Fatalf("final Flush failed: %v", err)
	}

	// Validate delivery accounting
	stats := pool.Stats()
	if stats.ErrorsCount > 0 {
		b.Fatalf("benchmark recorded %d transmission errors", stats.ErrorsCount)
	}
	if stats.EventsSubmitted == 0 {
		b.Fatal("benchmark recorded 0 submitted events")
	}
}

