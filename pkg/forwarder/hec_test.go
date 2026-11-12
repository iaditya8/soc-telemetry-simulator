package forwarder

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
)

func TestHECRawBatching(t *testing.T) {
	var receivedBatches int64
	var receivedLines int64
	expectedToken := "test-hec-token-12345"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Splunk "+expectedToken {
			http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusUnauthorized)
			return
		}

		if r.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
			http.Error(w, "invalid content type", http.StatusBadRequest)
			return
		}

		atomic.AddInt64(&receivedBatches, 1)
		scanner := bufio.NewScanner(r.Body)
		for scanner.Scan() {
			atomic.AddInt64(&receivedLines, 1)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer server.Close()

	client, err := NewHECClient(HECConfig{
		URL:            server.URL,
		Token:          expectedToken,
		EndpointType:   HECEndpointRaw,
		BatchMaxEvents: 20,
		BatchTimeout:   20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create HEC client: %v", err)
	}

	for i := 0; i < 50; i++ {
		buf := buffer.GetBuffer()
		buf.AppendString("<86>Raw event line ")
		buf.AppendInt(int64(i))
		if err := client.WriteEvent(buf); err != nil {
			t.Fatalf("WriteEvent failed: %v", err)
		}
		buf.Release()
	}

	if err := client.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	stats := client.Stats()
	if stats.EventsEnqueued != 50 {
		t.Errorf("expected 50 events enqueued, got %d", stats.EventsEnqueued)
	}
	if stats.EventsAcknowledged != 50 {
		t.Errorf("expected 50 events acknowledged, got %d", stats.EventsAcknowledged)
	}
	if stats.EventsRejected != 0 || stats.EventsFailed != 0 {
		t.Errorf("unexpected errors: rejected=%d, failed=%d", stats.EventsRejected, stats.EventsFailed)
	}

	if atomic.LoadInt64(&receivedLines) != 50 {
		t.Errorf("server received %d lines, expected 50", atomic.LoadInt64(&receivedLines))
	}
	// With BatchMaxEvents=20 and 50 events, should produce 3 batches (20 + 20 + 10)
	if atomic.LoadInt64(&receivedBatches) != 3 {
		t.Errorf("expected 3 batches, got %d", atomic.LoadInt64(&receivedBatches))
	}
}

func TestHECEventJSONWrapping(t *testing.T) {
	var receivedEvents int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/services/collector/event") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		scanner := bufio.NewScanner(r.Body)
		for scanner.Scan() {
			var obj map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &obj); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			if _, ok := obj["event"]; !ok {
				http.Error(w, "missing event field", http.StatusBadRequest)
				return
			}
			atomic.AddInt64(&receivedEvents, 1)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer server.Close()

	client, err := NewHECClient(HECConfig{
		URL:            server.URL,
		Token:          "fake-token",
		EndpointType:   HECEndpointEvent,
		BatchMaxEvents: 10,
		BatchTimeout:   20 * time.Millisecond,
		Source:         "test-source",
		Sourcetype:     "test-sourcetype",
	})
	if err != nil {
		t.Fatalf("failed to create HEC client: %v", err)
	}

	for i := 0; i < 25; i++ {
		err := client.WriteRaw([]byte(`{"metric": "cpu", "value": 42}`))
		if err != nil {
			t.Fatalf("WriteRaw failed: %v", err)
		}
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if atomic.LoadInt64(&receivedEvents) != 25 {
		t.Fatalf("server received %d events, expected 25", atomic.LoadInt64(&receivedEvents))
	}

	stats := client.Stats()
	if stats.EventsAcknowledged != 25 {
		t.Errorf("expected 25 events acknowledged, got %d", stats.EventsAcknowledged)
	}
}

func TestHECGzipCompression(t *testing.T) {
	var totalUncompressedBytes int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" {
			http.Error(w, "gzip required", http.StatusBadRequest)
			return
		}

		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "invalid gzip", http.StatusBadRequest)
			return
		}
		defer gz.Close()

		decompressed, err := io.ReadAll(gz)
		if err != nil {
			http.Error(w, "decompression error", http.StatusBadRequest)
			return
		}
		atomic.AddInt64(&totalUncompressedBytes, int64(len(decompressed)))

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer server.Close()

	client, err := NewHECClient(HECConfig{
		URL:            server.URL,
		Token:          "token-gzip",
		EndpointType:   HECEndpointRaw,
		BatchMaxEvents: 50,
		EnableGzip:     true,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	payload := []byte("<86>Nov 12 05:00:00 srv01 test message for gzip compression testing")
	for i := 0; i < 100; i++ {
		if err := client.WriteRaw(payload); err != nil {
			t.Fatalf("WriteRaw failed: %v", err)
		}
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	stats := client.Stats()
	if stats.EventsAcknowledged != 100 {
		t.Errorf("expected 100 acknowledged events, got %d", stats.EventsAcknowledged)
	}

	expectedMinBytes := int64(len(payload) * 100)
	if atomic.LoadInt64(&totalUncompressedBytes) < expectedMinBytes {
		t.Errorf("expected at least %d uncompressed bytes, got %d", expectedMinBytes, atomic.LoadInt64(&totalUncompressedBytes))
	}
}

func TestHECDeliveryAccountingRejectionAndFailure(t *testing.T) {
	var shouldFail500 int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Splunk valid-token" {
			http.Error(w, `{"text":"Invalid token","code":4}`, http.StatusForbidden)
			return
		}

		if atomic.LoadInt32(&shouldFail500) == 1 {
			http.Error(w, `{"text":"Server Error","code":9}`, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer server.Close()

	// 1. Test 403 Forbidden Rejection
	badClient, err := NewHECClient(HECConfig{
		URL:            server.URL,
		Token:          "bad-token",
		BatchMaxEvents: 10,
	})
	if err != nil {
		t.Fatalf("failed to create bad client: %v", err)
	}

	for i := 0; i < 10; i++ {
		_ = badClient.WriteRaw([]byte("test line"))
	}
	_ = badClient.Close()

	badStats := badClient.Stats()
	if badStats.EventsRejected != 10 {
		t.Errorf("expected 10 events rejected, got %d", badStats.EventsRejected)
	}

	// 2. Test 500 Server Error Failure
	atomic.StoreInt32(&shouldFail500, 1)
	goodClient, err := NewHECClient(HECConfig{
		URL:            server.URL,
		Token:          "valid-token",
		BatchMaxEvents: 15,
	})
	if err != nil {
		t.Fatalf("failed to create good client: %v", err)
	}

	for i := 0; i < 15; i++ {
		_ = goodClient.WriteRaw([]byte("test line 500"))
	}
	_ = goodClient.Close()

	failStats := goodClient.Stats()
	if failStats.EventsFailed != 15 {
		t.Errorf("expected 15 events failed, got %d", failStats.EventsFailed)
	}
}

func BenchmarkHECThroughput(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer server.Close()

	client, err := NewHECClient(HECConfig{
		URL:            server.URL,
		Token:          "bench-token",
		EndpointType:   HECEndpointRaw,
		BatchMaxEvents: 2000,
		BatchMaxBytes:  512 * 1024,
		BatchTimeout:   20 * time.Millisecond,
	})
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	sample := []byte("<86>Nov 12 05:00:00 srv01 sshd[100]: Accepted publickey for sysadmin from 10.0.0.1 port 54321 ssh2\n")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := client.WriteRaw(sample); err != nil {
			b.Fatalf("WriteRaw failed: %v", err)
		}
	}

	_ = client.Flush()
}
