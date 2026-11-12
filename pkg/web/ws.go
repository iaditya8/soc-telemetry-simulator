package web

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/ledger"
)

const (
	websocketGUID    = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsClientChanSize = 64
	wsWriteTimeout   = 5 * time.Second
)

// LiveTelemetryPacket holds instantaneous real-time metrics broadcast to connected dashboards.
type LiveTelemetryPacket struct {
	RunID             string                     `json:"run_id"`
	State             RunState                   `json:"state"`
	Timestamp         time.Time                  `json:"timestamp"`
	ElapsedSeconds    float64                    `json:"elapsed_seconds"`
	RemainingSeconds  float64                    `json:"remaining_seconds"`
	InstantEPS        float64                    `json:"instant_eps"`
	TotalGenerated    uint64                     `json:"total_generated"`
	TotalNormal       uint64                     `json:"total_normal"`
	TotalSuspicious   uint64                     `json:"total_suspicious"`
	TotalEnqueued     uint64                     `json:"total_enqueued"`
	TotalSubmitted    uint64                     `json:"total_submitted"`
	TotalAcknowledged uint64                     `json:"total_acknowledged"`
	TotalRejected     uint64                     `json:"total_rejected"`
	TotalFailed       uint64                     `json:"total_failed"`
	TotalDropped      uint64                     `json:"total_dropped"`
	TotalRetries      uint64                     `json:"total_retries"`
	QueueDepth        int                        `json:"queue_depth"`
	QueueCapacity     int                        `json:"queue_capacity"`
	QueueFillPct      float64                    `json:"queue_fill_pct"`
	BySource          map[string]SourceTelemetry `json:"by_source,omitempty"`
	MemAllocMB        float64                    `json:"mem_alloc_mb"`
	NumGoroutine      int                        `json:"num_goroutine"`
}

// SourceTelemetry reports high-level metrics for an individual source family.
type SourceTelemetry struct {
	Generated    uint64 `json:"generated"`
	Acknowledged uint64 `json:"acknowledged"`
}

type wsClient struct {
	conn net.Conn
	send chan []byte
	done chan struct{}
}

// TelemetryHub manages active WebSocket connections and broadcasts telemetry packets.
type TelemetryHub struct {
	mu            sync.RWMutex
	clients       map[*wsClient]bool
	sseClients    map[chan []byte]bool
	broadcastChan chan []byte
	stopChan      chan struct{}
	clientCount   int64

	server      *Server
	lastSample  time.Time
	lastAckSnap uint64
}

// NewTelemetryHub creates a new streaming hub connected to the given Server.
func NewTelemetryHub(s *Server) *TelemetryHub {
	return &TelemetryHub{
		clients:       make(map[*wsClient]bool),
		sseClients:    make(map[chan []byte]bool),
		broadcastChan: make(chan []byte, 128),
		stopChan:      make(chan struct{}),
		server:        s,
		lastSample:    time.Now(),
	}
}

// Start begins the hub distribution and sampling loop.
func (h *TelemetryHub) Start(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond) // 4 Hz broadcast for smooth 60 FPS charts
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			h.Close()
			return
		case <-h.stopChan:
			return
		case msg := <-h.broadcastChan:
			h.dispatch(msg)
		case <-ticker.C:
			packet := h.generateSnapshot()
			if data, err := json.Marshal(packet); err == nil {
				h.dispatch(data)
			}
		}
	}
}

// Close stops the hub and terminates all client connections.
func (h *TelemetryHub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	select {
	case <-h.stopChan:
		return
	default:
		close(h.stopChan)
	}

	for c := range h.clients {
		close(c.send)
		_ = c.conn.Close()
		delete(h.clients, c)
	}
	for ch := range h.sseClients {
		close(ch)
		delete(h.sseClients, ch)
	}
}

// ActiveClients returns the number of connected WebSocket and SSE streams.
func (h *TelemetryHub) ActiveClients() int {
	return int(atomic.LoadInt64(&h.clientCount))
}

// generateSnapshot compiles instantaneous simulator and host metrics.
func (h *TelemetryHub) generateSnapshot() LiveTelemetryPacket {
	s := h.server
	s.mu.RLock()
	st := s.state
	runID := s.currentRunID
	targetDur := s.activeConfig.Simulation.DurationSeconds
	start := s.startTime
	acct := s.accounting
	s.mu.RUnlock()

	now := time.Now()
	elapsed := now.Sub(start).Seconds()
	remaining := -1.0
	if targetDur > 0 {
		rem := float64(targetDur) - elapsed
		if rem < 0 {
			rem = 0
		}
		remaining = rem
	}

	var snap ledger.AccountingSnapshot
	if acct != nil {
		snap = acct.Snapshot()
	}

	// Calculate instant EPS
	deltaSec := now.Sub(h.lastSample).Seconds()
	var instantEPS float64
	if deltaSec > 0 && snap.TotalAcknowledged >= h.lastAckSnap {
		instantEPS = float64(snap.TotalAcknowledged-h.lastAckSnap) / deltaSec
	}
	h.lastSample = now
	h.lastAckSnap = snap.TotalAcknowledged

	bySrc := make(map[string]SourceTelemetry)
	for k, v := range snap.BySourceFamily {
		bySrc[k] = SourceTelemetry{
			Generated:    v.Generated,
			Acknowledged: v.Acknowledged,
		}
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return LiveTelemetryPacket{
		RunID:             runID,
		State:             st,
		Timestamp:         now,
		ElapsedSeconds:    elapsed,
		RemainingSeconds:  remaining,
		InstantEPS:        instantEPS,
		TotalGenerated:    snap.TotalGenerated,
		TotalNormal:       snap.TotalNormal,
		TotalSuspicious:   snap.TotalSuspicious,
		TotalEnqueued:     snap.TotalEnqueued,
		TotalSubmitted:    snap.TotalSubmitted,
		TotalAcknowledged: snap.TotalAcknowledged,
		TotalRejected:     snap.TotalRejected,
		TotalFailed:       snap.TotalFailed,
		TotalDropped:      snap.TotalDropped,
		TotalRetries:      snap.TotalRetries,
		QueueDepth:        0,
		QueueCapacity:     50000,
		QueueFillPct:      0.0,
		BySource:          bySrc,
		MemAllocMB:        float64(m.Alloc) / (1024 * 1024),
		NumGoroutine:      runtime.NumGoroutine(),
	}
}

// dispatch delivers messages to all active WebSocket and SSE clients.
func (h *TelemetryHub) dispatch(msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for c := range h.clients {
		select {
		case c.send <- msg:
		default:
			// Client write buffer full; drop to prevent head-of-line blocking
		}
	}

	for ch := range h.sseClients {
		select {
		case ch <- msg:
		default:
		}
	}
}

// HandleWS handles RFC 6455 WebSocket upgrades and pumps telemetry messages.
func (h *TelemetryHub) HandleWS(w http.ResponseWriter, r *http.Request) {
	// Verify WebSocket upgrade request
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
		return
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key header", http.StatusBadRequest)
		return
	}

	// Compute accept hash
	hash := sha1.New()
	hash.Write([]byte(key + websocketGUID))
	accept := base64.StdEncoding.EncodeToString(hash.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver does not support hijacking", http.StatusInternalServerError)
		return
	}

	netConn, rw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "failed to hijack connection: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send handshake response
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", accept)

	if _, err := rw.WriteString(resp); err != nil {
		_ = netConn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = netConn.Close()
		return
	}

	client := &wsClient{
		conn: netConn,
		send: make(chan []byte, wsClientChanSize),
		done: make(chan struct{}),
	}

	h.mu.Lock()
	h.clients[client] = true
	atomic.AddInt64(&h.clientCount, 1)
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, client)
		atomic.AddInt64(&h.clientCount, -1)
		h.mu.Unlock()
		_ = netConn.Close()
	}()

	// Read loop to detect disconnect or close frames
	go func() {
		reader := bufio.NewReader(netConn)
		for {
			header := make([]byte, 2)
			if _, err := io.ReadFull(reader, header); err != nil {
				break
			}
			opcode := header[0] & 0x0F
			if opcode == 0x08 { // Close frame
				break
			}
			// Drain payload if any
			payloadLen := int(header[1] & 0x7F)
			if payloadLen == 126 {
				ext := make([]byte, 2)
				if _, err := io.ReadFull(reader, ext); err != nil {
					break
				}
				payloadLen = int(binary.BigEndian.Uint16(ext))
			} else if payloadLen == 127 {
				ext := make([]byte, 8)
				if _, err := io.ReadFull(reader, ext); err != nil {
					break
				}
				payloadLen = int(binary.BigEndian.Uint64(ext))
			}
			masked := (header[1] & 0x80) != 0
			var maskKey []byte
			if masked {
				maskKey = make([]byte, 4)
				if _, err := io.ReadFull(reader, maskKey); err != nil {
					break
				}
			}
			if payloadLen > 0 {
				discard := make([]byte, payloadLen)
				if _, err := io.ReadFull(reader, discard); err != nil {
					break
				}
			}
		}
		close(client.done)
	}()

	// Write loop
	for {
		select {
		case <-client.done:
			return
		case msg, ok := <-client.send:
			if !ok {
				return
			}
			_ = netConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			frame := encodeTextFrame(msg)
			if _, err := netConn.Write(frame); err != nil {
				return
			}
		}
	}
}

// HandleSSE serves live telemetry packets over standard Server-Sent Events (SSE).
func (h *TelemetryHub) HandleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	clientChan := make(chan []byte, wsClientChanSize)

	h.mu.Lock()
	h.sseClients[clientChan] = true
	atomic.AddInt64(&h.clientCount, 1)
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.sseClients, clientChan)
		atomic.AddInt64(&h.clientCount, -1)
		h.mu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-clientChan:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

// encodeTextFrame creates an RFC 6455 unmasked text frame.
func encodeTextFrame(payload []byte) []byte {
	n := len(payload)
	var header []byte

	if n <= 125 {
		header = []byte{0x81, byte(n)}
	} else if n <= 65535 {
		header = make([]byte, 4)
		header[0] = 0x81
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(n))
	} else {
		header = make([]byte, 10)
		header[0] = 0x81
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(n))
	}

	return append(header, payload...)
}
