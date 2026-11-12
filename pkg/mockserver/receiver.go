package mockserver

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ReceiverConfig configures the standalone mock SIEM ingestion receiver.
type ReceiverConfig struct {
	TCPAddr       string // e.g. "127.0.0.1:5140" or ":5140" (empty to disable)
	HECAddr       string // e.g. "127.0.0.1:8088" or ":8088" (empty to disable)
	ExpectedToken string // If set, enforces HEC token auth
	TLSConfig     *tls.Config
}

// ReceiverStats captures real-time receipt accounting.
type ReceiverStats struct {
	EventsReceived  uint64
	BytesReceived   uint64
	BatchesReceived uint64
	TCPConnections  uint64
	ErrorsCount     uint64
	CurrentEPS      float64
}

// MockReceiver runs local streaming TCP and Splunk HEC HTTP ingestion endpoints.
type MockReceiver struct {
	cfg            ReceiverConfig
	tcpListener    net.Listener
	hecServer      *http.Server
	hecListener    net.Listener
	stats          ReceiverStats
	lastEvents     uint64
	lastCalcTime   time.Time
	mu             sync.Mutex
	closed         uint32
	wg             sync.WaitGroup
	tickerStopChan chan struct{}
}

// NewMockReceiver initializes the mock Spectra SIEM ingestion receiver.
func NewMockReceiver(cfg ReceiverConfig) *MockReceiver {
	return &MockReceiver{
		cfg:            cfg,
		lastCalcTime:   time.Now(),
		tickerStopChan: make(chan struct{}),
	}
}

// Start binds listeners and starts ingestion loops.
func (r *MockReceiver) Start() error {
	// 1. Start TCP listener if configured
	if r.cfg.TCPAddr != "" {
		var l net.Listener
		var err error
		if r.cfg.TLSConfig != nil {
			l, err = tls.Listen("tcp", r.cfg.TCPAddr, r.cfg.TLSConfig)
		} else {
			l, err = net.Listen("tcp", r.cfg.TCPAddr)
		}
		if err != nil {
			return fmt.Errorf("mockserver: failed to bind TCP listener on %s: %w", r.cfg.TCPAddr, err)
		}
		r.tcpListener = l

		r.wg.Add(1)
		go r.acceptTCPConnections()
	}

	// 2. Start HEC HTTP listener if configured
	if r.cfg.HECAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/services/collector/raw", r.handleHECRaw)
		mux.HandleFunc("/services/collector/event", r.handleHECEvent)
		mux.HandleFunc("/services/collector", r.handleHECRaw) // Fallback default
		mux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		})

		r.hecServer = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
			TLSConfig:         r.cfg.TLSConfig,
		}

		l, err := net.Listen("tcp", r.cfg.HECAddr)
		if err != nil {
			if r.tcpListener != nil {
				_ = r.tcpListener.Close()
			}
			return fmt.Errorf("mockserver: failed to bind HEC listener on %s: %w", r.cfg.HECAddr, err)
		}
		r.hecListener = l

		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			var sErr error
			if r.cfg.TLSConfig != nil {
				sErr = r.hecServer.ServeTLS(l, "", "")
			} else {
				sErr = r.hecServer.Serve(l)
			}
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				atomic.AddUint64(&r.stats.ErrorsCount, 1)
			}
		}()
	}

	go r.epsCalculatorLoop()
	return nil
}

// TCPAddr returns the bound network address of the TCP listener.
func (r *MockReceiver) TCPAddr() string {
	if r.tcpListener != nil {
		return r.tcpListener.Addr().String()
	}
	return ""
}

// HECAddr returns the bound network address of the HEC listener.
func (r *MockReceiver) HECAddr() string {
	if r.hecListener != nil {
		return r.hecListener.Addr().String()
	}
	return ""
}

func (r *MockReceiver) acceptTCPConnections() {
	defer r.wg.Done()

	for {
		conn, err := r.tcpListener.Accept()
		if err != nil {
			if atomic.LoadUint32(&r.closed) == 1 {
				return
			}
			atomic.AddUint64(&r.stats.ErrorsCount, 1)
			return
		}

		atomic.AddUint64(&r.stats.TCPConnections, 1)
		r.wg.Add(1)
		go r.handleTCPConn(conn)
	}
}

func (r *MockReceiver) handleTCPConn(conn net.Conn) {
	defer r.wg.Done()
	defer conn.Close()

	reader := bufio.NewReaderSize(conn, 256*1024)

	for {
		// Peek first byte to auto-detect RFC 5424 octet counting vs line-delimited
		firstByte, err := reader.Peek(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			atomic.AddUint64(&r.stats.ErrorsCount, 1)
			return
		}

		// Octet-counting starts with ASCII digit ('1'-'9')
		if firstByte[0] >= '1' && firstByte[0] <= '9' {
			lenStr, err := reader.ReadString(' ')
			if err != nil {
				return
			}
			length, err := strconv.Atoi(strings.TrimSpace(lenStr))
			if err != nil {
				atomic.AddUint64(&r.stats.ErrorsCount, 1)
				return
			}
			msg := make([]byte, length)
			n, err := io.ReadFull(reader, msg)
			atomic.AddUint64(&r.stats.BytesReceived, uint64(len(lenStr)+n))
			if err != nil {
				return
			}
			atomic.AddUint64(&r.stats.EventsReceived, 1)
		} else {
			// Line-delimited
			line, err := reader.ReadBytes('\n')
			n := len(line)
			if n > 0 {
				atomic.AddUint64(&r.stats.BytesReceived, uint64(n))
				atomic.AddUint64(&r.stats.EventsReceived, 1)
			}
			if err != nil {
				return
			}
		}
	}
}

func (r *MockReceiver) checkAuth(req *http.Request) bool {
	if r.cfg.ExpectedToken == "" {
		return true
	}

	auth := req.Header.Get("Authorization")
	parts := strings.Fields(auth)
	if len(parts) == 2 && (parts[0] == "Splunk" || parts[0] == "Bearer") {
		return parts[1] == r.cfg.ExpectedToken
	}
	return false
}

func (r *MockReceiver) handleHECRaw(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !r.checkAuth(req) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"text":"Invalid token","code":4}`))
		return
	}

	var reader io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			atomic.AddUint64(&r.stats.ErrorsCount, 1)
			http.Error(w, "invalid gzip body", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		reader = gz
	}

	var eventCount uint64
	var bytesCount uint64

	scanner := bufio.NewScanner(reader)
	// Buffer large batches up to 2 MB lines
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) > 0 {
			eventCount++
			bytesCount += uint64(len(line) + 1)
		}
	}

	if err := scanner.Err(); err != nil {
		atomic.AddUint64(&r.stats.ErrorsCount, 1)
		http.Error(w, fmt.Sprintf("scan error: %v", err), http.StatusBadRequest)
		return
	}

	atomic.AddUint64(&r.stats.EventsReceived, eventCount)
	atomic.AddUint64(&r.stats.BytesReceived, bytesCount)
	atomic.AddUint64(&r.stats.BatchesReceived, 1)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
}

func (r *MockReceiver) handleHECEvent(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if !r.checkAuth(req) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"text":"Invalid token","code":4}`))
		return
	}

	var reader io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			atomic.AddUint64(&r.stats.ErrorsCount, 1)
			http.Error(w, "invalid gzip body", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		reader = gz
	}

	var eventCount uint64
	var bytesCount uint64

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		bytesCount += uint64(len(line) + 1)

		// Fast sanity validation of JSON format
		var js json.RawMessage
		if json.Unmarshal(line, &js) == nil {
			eventCount++
		}
	}

	if err := scanner.Err(); err != nil {
		atomic.AddUint64(&r.stats.ErrorsCount, 1)
		http.Error(w, fmt.Sprintf("scan error: %v", err), http.StatusBadRequest)
		return
	}

	atomic.AddUint64(&r.stats.EventsReceived, eventCount)
	atomic.AddUint64(&r.stats.BytesReceived, bytesCount)
	atomic.AddUint64(&r.stats.BatchesReceived, 1)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
}

func (r *MockReceiver) epsCalculatorLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.tickerStopChan:
			return
		case now := <-ticker.C:
			currentTotal := atomic.LoadUint64(&r.stats.EventsReceived)
			r.mu.Lock()
			elapsed := now.Sub(r.lastCalcTime).Seconds()
			if elapsed > 0 {
				delta := currentTotal - r.lastEvents
				r.stats.CurrentEPS = float64(delta) / elapsed
				r.lastEvents = currentTotal
				r.lastCalcTime = now
			}
			r.mu.Unlock()
		}
	}
}

// Stats returns atomic reception statistics.
func (r *MockReceiver) Stats() ReceiverStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	return ReceiverStats{
		EventsReceived:  atomic.LoadUint64(&r.stats.EventsReceived),
		BytesReceived:   atomic.LoadUint64(&r.stats.BytesReceived),
		BatchesReceived: atomic.LoadUint64(&r.stats.BatchesReceived),
		TCPConnections:  atomic.LoadUint64(&r.stats.TCPConnections),
		ErrorsCount:     atomic.LoadUint64(&r.stats.ErrorsCount),
		CurrentEPS:      r.stats.CurrentEPS,
	}
}

// Close cleanly shuts down all listeners and intake workers.
func (r *MockReceiver) Close() error {
	if !atomic.CompareAndSwapUint32(&r.closed, 0, 1) {
		return nil
	}

	close(r.tickerStopChan)

	var firstErr error
	if r.tcpListener != nil {
		if err := r.tcpListener.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if r.hecServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := r.hecServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	r.wg.Wait()
	return firstErr
}
