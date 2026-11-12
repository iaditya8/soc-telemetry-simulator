package web

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWebSocketHandshakeAndStreaming(t *testing.T) {
	s, _ := setupTestServer(t)

	// Dial TCP directly to perform RFC 6455 handshake
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	// Send handshake request
	nonce := "dGhlIHNhbXBsZSBub25jZQ=="
	req := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n", s.Addr(), nonce)

	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("failed to send handshake: %v", err)
	}

	reader := bufio.NewReader(conn)

	// Read handshake response
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read handshake response: %v", err)
	}
	if !strings.Contains(statusLine, "101 Switching Protocols") {
		t.Fatalf("expected 101 Switching Protocols, got %q", statusLine)
	}

	// Read remaining headers until blank line
	expectedAccept := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	hasAccept := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed reading header: %v", err)
		}
		if line == "\r\n" {
			break
		}
		if strings.Contains(line, expectedAccept) {
			hasAccept = true
		}
	}

	if !hasAccept {
		t.Error("handshake response missing valid Sec-WebSocket-Accept")
	}

	// Verify client is registered in hub
	time.Sleep(50 * time.Millisecond)
	if s.hub.ActiveClients() < 1 {
		t.Errorf("expected at least 1 active client, got %d", s.hub.ActiveClients())
	}

	// Read first incoming WebSocket text frame
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		t.Fatalf("failed to read WS frame header: %v", err)
	}

	opcode := header[0] & 0x0F
	if opcode != 0x01 { // Text frame
		t.Fatalf("expected text frame (opcode 1), got %d", opcode)
	}

	payloadLen := int(header[1] & 0x7F)
	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(reader, ext); err != nil {
			t.Fatalf("failed to read 16-bit ext length: %v", err)
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(reader, ext); err != nil {
			t.Fatalf("failed to read 64-bit ext length: %v", err)
		}
		payloadLen = int(binary.BigEndian.Uint64(ext))
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatalf("failed to read WS payload: %v", err)
	}

	var pkt LiveTelemetryPacket
	if err := json.Unmarshal(payload, &pkt); err != nil {
		t.Fatalf("failed to parse LiveTelemetryPacket JSON: %v", err)
	}

	if pkt.State != StateIdle {
		t.Errorf("expected initial state IDLE, got %v", pkt.State)
	}
	if pkt.QueueCapacity != 50000 {
		t.Errorf("expected queue capacity 50000, got %d", pkt.QueueCapacity)
	}

	// Send close frame (opcode 0x08)
	closeFrame := []byte{0x88, 0x00}
	_, _ = conn.Write(closeFrame)

	time.Sleep(100 * time.Millisecond)
	if s.hub.ActiveClients() != 0 {
		t.Errorf("expected 0 active clients after close, got %d", s.hub.ActiveClients())
	}
}

func TestSSEStreaming(t *testing.T) {
	s, _ := setupTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.URL()+"/api/live/stream", nil)
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/live/stream failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Errorf("expected text/event-stream Content-Type, got %s", resp.Header.Get("Content-Type"))
	}

	reader := bufio.NewReader(resp.Body)

	// Read first event
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed reading SSE stream line: %v", err)
	}

	if !strings.HasPrefix(line, "data: ") {
		t.Fatalf("expected SSE data line, got %q", line)
	}

	rawJSON := strings.TrimPrefix(line, "data: ")
	rawJSON = strings.TrimSpace(rawJSON)

	var pkt LiveTelemetryPacket
	if err := json.Unmarshal([]byte(rawJSON), &pkt); err != nil {
		t.Fatalf("failed to decode SSE telemetry packet: %v", err)
	}

	if pkt.State != StateIdle {
		t.Errorf("expected state IDLE, got %v", pkt.State)
	}
}

func TestWebSocketInvalidHandshake(t *testing.T) {
	s, _ := setupTestServer(t)

	// Missing upgrade header
	resp, err := http.Get(s.URL() + "/ws")
	if err != nil {
		t.Fatalf("GET /ws failed: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400 for non-WS request, got %d", resp.StatusCode)
	}
}
