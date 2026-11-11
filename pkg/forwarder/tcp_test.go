package forwarder

import (
	"bufio"
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

	go func() {
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
	defer client.Close()

	buf := buffer.GetBuffer()
	buf.AppendString("<86>Nov 12 05:00:00 srv01 sshd[100]: Accepted publickey")
	_ = client.WriteEvent(buf)
	buf.Release()

	buf = buffer.GetBuffer()
	buf.AppendString("<85>Nov 12 05:00:01 srv01 sshd[101]: Failed password")
	_ = client.WriteEvent(buf)
	buf.Release()

	_ = client.Flush()
	time.Sleep(50 * time.Millisecond)

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

func TestTCPForwarderOctetCountingFraming(t *testing.T) {
	listener, addr := startMockTCPListener(t)
	defer listener.Close()

	var receivedMessages []string
	var mu sync.Mutex

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for {
			// Read length prefix up to ' '
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
	defer client.Close()

	payload1 := "<86>1 2026-11-12T05:00:00Z srv01 app 1 - - test message 1"
	payload2 := "<86>1 2026-11-12T05:00:01Z srv01 app 2 - - test message 2"

	_ = client.WriteRaw([]byte(payload1))
	_ = client.WriteRaw([]byte(payload2))
	_ = client.Flush()

	time.Sleep(50 * time.Millisecond)

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
					atomic.AddUint64(&count, 1)
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

	const totalEvents = 2000
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
				_ = pool.WriteEvent(buf)
				buf.Release()
			}
		}(w)
	}

	wg.Wait()
	_ = pool.Flush()
	time.Sleep(100 * time.Millisecond)

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

	// Blackhole receiver
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
					if _, err := c.Read(discard); err != nil {
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
			_ = pool.WriteRaw(samplePayload)
		}
	})

	_ = pool.Flush()
}
