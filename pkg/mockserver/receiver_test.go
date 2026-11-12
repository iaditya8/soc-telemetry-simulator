package mockserver

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
	"github.com/iaditya8/soc-telemetry-simulator/pkg/forwarder"
)

func TestMockReceiverTCPStreaming(t *testing.T) {
	rcv := NewMockReceiver(ReceiverConfig{
		TCPAddr: "127.0.0.1:0",
	})
	if err := rcv.Start(); err != nil {
		t.Fatalf("failed to start receiver: %v", err)
	}
	defer rcv.Close()

	pool, err := forwarder.NewTCPForwarderPool(forwarder.TCPConfig{
		Address:       rcv.TCPAddr(),
		Framing:       forwarder.FramingNewline,
		BufferSize:    64 * 1024,
		FlushInterval: 10 * time.Millisecond,
	}, 4)
	if err != nil {
		t.Fatalf("failed to create forwarder pool: %v", err)
	}
	defer pool.Close()

	const totalEvents = 1000
	var wg sync.WaitGroup
	wg.Add(4)

	for w := 0; w < 4; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < totalEvents/4; i++ {
				buf := buffer.GetBuffer()
				buf.AppendString("<86>Nov 12 05:00:00 srv01 test event ")
				buf.AppendInt(int64(workerID))
				buf.AppendString(":")
				buf.AppendInt(int64(i))
				_ = pool.WriteEvent(buf)
				buf.Release()
			}
		}(w)
	}

	wg.Wait()
	_ = pool.Flush()

	// Wait for receiver to tally all events
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rcv.Stats().EventsReceived >= totalEvents {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	stats := rcv.Stats()
	if stats.EventsReceived != totalEvents {
		t.Fatalf("expected %d events received, got %d", totalEvents, stats.EventsReceived)
	}
	if stats.BytesReceived == 0 {
		t.Error("expected non-zero bytes received")
	}
}

func TestMockReceiverHECRawAndEvent(t *testing.T) {
	const validToken = "mock-hec-secret-token"

	rcv := NewMockReceiver(ReceiverConfig{
		HECAddr:       "127.0.0.1:0",
		ExpectedToken: validToken,
	})
	if err := rcv.Start(); err != nil {
		t.Fatalf("failed to start receiver: %v", err)
	}
	defer rcv.Close()

	// 1. Raw endpoint client
	rawClient, err := forwarder.NewHECClient(forwarder.HECConfig{
		URL:            fmt.Sprintf("http://%s/services/collector/raw", rcv.HECAddr()),
		Token:          validToken,
		EndpointType:   forwarder.HECEndpointRaw,
		BatchMaxEvents: 50,
		BatchTimeout:   20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create raw client: %v", err)
	}

	for i := 0; i < 150; i++ {
		buf := buffer.GetBuffer()
		buf.AppendString("<86>Nov 12 05:00:00 fire01 allow tcp 10.0.0.1 10.0.0.2")
		_ = rawClient.WriteEvent(buf)
		buf.Release()
	}
	_ = rawClient.Close()

	// 2. Event endpoint client with Gzip
	eventClient, err := forwarder.NewHECClient(forwarder.HECConfig{
		URL:            fmt.Sprintf("http://%s/services/collector/event", rcv.HECAddr()),
		Token:          validToken,
		EndpointType:   forwarder.HECEndpointEvent,
		BatchMaxEvents: 50,
		EnableGzip:     true,
		Source:         "audit",
		Sourcetype:     "linux_secure",
	})
	if err != nil {
		t.Fatalf("failed to create event client: %v", err)
	}

	for i := 0; i < 100; i++ {
		_ = eventClient.WriteRaw([]byte(`{"action":"login","status":"success"}`))
	}
	_ = eventClient.Close()

	// Wait for tally
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rcv.Stats().EventsReceived >= 250 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	stats := rcv.Stats()
	if stats.EventsReceived != 250 {
		t.Fatalf("expected 250 events received, got %d", stats.EventsReceived)
	}
	if stats.BatchesReceived < 4 {
		t.Errorf("expected at least 4 batches, got %d", stats.BatchesReceived)
	}
}

func TestMockReceiverAuthRejection(t *testing.T) {
	rcv := NewMockReceiver(ReceiverConfig{
		HECAddr:       "127.0.0.1:0",
		ExpectedToken: "correct-secret",
	})
	if err := rcv.Start(); err != nil {
		t.Fatalf("failed to start receiver: %v", err)
	}
	defer rcv.Close()

	client, err := forwarder.NewHECClient(forwarder.HECConfig{
		URL:            fmt.Sprintf("http://%s/services/collector/raw", rcv.HECAddr()),
		Token:          "wrong-secret",
		BatchMaxEvents: 10,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_ = client.WriteRaw([]byte("unauthorized line"))
	_ = client.Close()

	stats := client.Stats()
	if stats.EventsRejected != 1 {
		t.Errorf("expected 1 event rejected by receiver, got %d", stats.EventsRejected)
	}
}

func BenchmarkMockReceiverIngestionThroughput(b *testing.B) {
	rcv := NewMockReceiver(ReceiverConfig{
		TCPAddr: "127.0.0.1:0",
	})
	if err := rcv.Start(); err != nil {
		b.Fatalf("failed to start receiver: %v", err)
	}
	defer rcv.Close()

	pool, err := forwarder.NewTCPForwarderPool(forwarder.TCPConfig{
		Address:       rcv.TCPAddr(),
		Framing:       forwarder.FramingNewline,
		BufferSize:    256 * 1024,
		FlushInterval: 10 * time.Millisecond,
	}, 4)
	if err != nil {
		b.Fatalf("failed to create pool: %v", err)
	}
	defer pool.Close()

	sample := []byte("<86>Nov 12 05:00:00 srv01 audit: event for benchmark\n")

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = pool.WriteRaw(sample)
		}
	})

	_ = pool.Flush()
}
