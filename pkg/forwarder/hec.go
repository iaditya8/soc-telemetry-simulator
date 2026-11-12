package forwarder

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
)

// HECEndpointType specifies whether raw records or structured JSON events are posted.
type HECEndpointType int

const (
	// HECEndpointRaw delivers raw delimited text to /services/collector/raw.
	HECEndpointRaw HECEndpointType = iota
	// HECEndpointEvent delivers JSON objects to /services/collector/event.
	HECEndpointEvent
	// HECEndpointCustom delivers batches directly to the configured URL path without rewriting.
	HECEndpointCustom
)

// HECConfig defines parameters for Splunk HEC / HTTP Bulk REST forwarder.
type HECConfig struct {
	URL                  string
	Token                string
	EndpointType         HECEndpointType
	AuthHeaderPrefix     string // "Splunk" (default) or "Bearer"
	BatchMaxEvents       int    // Max events per batch (default: 2000)
	BatchMaxBytes        int    // Max uncompressed bytes per batch (default: 512 KB)
	BatchTimeout         time.Duration
	EnableGzip           bool
	GzipCompressionLevel int // e.g. gzip.BestSpeed
	TLSConfig            *tls.Config
	Timeout              time.Duration
	MaxIdleConns         int
	MaxIdleConnsPerHost  int
	Index                string // Optional HEC metadata header/param
	Host                 string
	Source               string
	Sourcetype           string
}

// HECStats holds atomic transmission counters for SIEM accounting.
type HECStats struct {
	EventsEnqueued     uint64
	EventsSubmitted    uint64
	EventsAcknowledged uint64 // HTTP 200 OK
	EventsRejected     uint64 // HTTP 4xx (Authentication / Format error)
	EventsFailed       uint64 // HTTP 5xx / Network connection failure
	BatchesSent        uint64
	BytesSent          uint64
}

// HECClient provides high-speed batched HTTP/HTTPS forwarding to Splunk HEC / Spectra endpoints.
type HECClient struct {
	cfg         HECConfig
	client      *http.Client
	targetURL   string
	authHeader  string
	stats       HECStats
	mu          sync.Mutex
	batchBuf    *bytes.Buffer
	batchEvents int
	closed      uint32
	flushStop   chan struct{}
	gzipPool    sync.Pool
	bufPool     sync.Pool
}

// NewHECClient creates a new Splunk HEC HTTP client with Keep-Alive connection pooling.
func NewHECClient(cfg HECConfig) (*HECClient, error) {
	if cfg.URL == "" {
		return nil, errors.New("forwarder: HEC URL cannot be empty")
	}

	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("forwarder: invalid HEC URL %q: %w", cfg.URL, err)
	}

	// Normalize endpoint path if user supplied base URL without explicit collector path
	if cfg.EndpointType == HECEndpointRaw && !strings.Contains(u.Path, "/services/collector") {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/services/collector/raw"
	} else if cfg.EndpointType == HECEndpointEvent && !strings.Contains(u.Path, "/services/collector") {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/services/collector/event"
	}

	// Append query params for raw endpoint if metadata is specified
	if cfg.EndpointType == HECEndpointRaw {
		q := u.Query()
		if cfg.Index != "" && q.Get("index") == "" {
			q.Set("index", cfg.Index)
		}
		if cfg.Source != "" && q.Get("source") == "" {
			q.Set("source", cfg.Source)
		}
		if cfg.Sourcetype != "" && q.Get("sourcetype") == "" {
			q.Set("sourcetype", cfg.Sourcetype)
		}
		u.RawQuery = q.Encode()
	}

	if cfg.AuthHeaderPrefix == "" {
		cfg.AuthHeaderPrefix = "Splunk"
	}
	if cfg.BatchMaxEvents <= 0 {
		cfg.BatchMaxEvents = 2000
	}
	if cfg.BatchMaxBytes <= 0 {
		cfg.BatchMaxBytes = 512 * 1024 // 512 KB
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 50 * time.Millisecond
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = 500
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = 100
	}

	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	var authHeader string
	if cfg.Token != "" {
		authHeader = fmt.Sprintf("%s %s", cfg.AuthHeaderPrefix, cfg.Token)
	}

	c := &HECClient{
		cfg:        cfg,
		client:     client,
		targetURL:  u.String(),
		authHeader: authHeader,
		batchBuf:   bytes.NewBuffer(make([]byte, 0, cfg.BatchMaxBytes)),
		flushStop:  make(chan struct{}),
		bufPool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, 0, cfg.BatchMaxBytes))
			},
		},
	}

	if cfg.EnableGzip {
		level := cfg.GzipCompressionLevel
		if level < gzip.HuffmanOnly || level > gzip.BestCompression {
			level = gzip.BestSpeed
		}
		c.gzipPool = sync.Pool{
			New: func() any {
				w, _ := gzip.NewWriterLevel(io.Discard, level)
				return w
			},
		}
	}

	go c.flushLoop()
	return c, nil
}

// WriteEvent buffers an event from a ByteBuffer.
func (c *HECClient) WriteEvent(buf *buffer.ByteBuffer) error {
	return c.WriteRaw(buf.Bytes())
}

// WriteRaw appends raw telemetry bytes to the active batch buffer, flushing if thresholds are exceeded.
func (c *HECClient) WriteRaw(data []byte) error {
	if atomic.LoadUint32(&c.closed) == 1 {
		return io.ErrClosedPipe
	}

	c.mu.Lock()
	atomic.AddUint64(&c.stats.EventsEnqueued, 1)

	if c.cfg.EndpointType == HECEndpointEvent || c.cfg.EndpointType == HECEndpointCustom {
		// Wrap event in JSON envelope (HEC / Fluent Bit format)
		c.appendJSONEnvelopeLocked(data)
	} else {
		// Raw endpoint: append data and trailing newline delimiter
		c.batchBuf.Write(data)
		if len(data) == 0 || data[len(data)-1] != '\n' {
			c.batchBuf.WriteByte('\n')
		}
	}

	c.batchEvents++

	var batchData []byte
	var sendEvents int
	if c.batchEvents >= c.cfg.BatchMaxEvents || c.batchBuf.Len() >= c.cfg.BatchMaxBytes {
		batchData, sendEvents = c.prepareBatchLocked()
	}
	c.mu.Unlock()

	if batchData != nil {
		return c.dispatchBatch(batchData, sendEvents)
	}

	return nil
}

func (c *HECClient) appendJSONEnvelopeLocked(data []byte) {
	// Construct Splunk HEC / HTTP event object
	type hecEventEnvelope struct {
		Event      json.RawMessage `json:"event"`
		Message    string          `json:"message,omitempty"`
		Time       float64         `json:"time,omitempty"`
		Host       string          `json:"host,omitempty"`
		Source     string          `json:"source,omitempty"`
		Sourcetype string          `json:"sourcetype,omitempty"`
		Index      string          `json:"index,omitempty"`
	}

	// Validate if data is valid JSON; if not, quote as string
	var rawMsg json.RawMessage
	var rawStr string
	if json.Valid(data) {
		rawMsg = data
	} else {
		quoted, _ := json.Marshal(string(data))
		rawMsg = quoted
		rawStr = string(data)
	}

	env := hecEventEnvelope{
		Event:      rawMsg,
		Message:    rawStr,
		Time:       float64(time.Now().UnixNano()) / 1e9,
		Host:       c.cfg.Host,
		Source:     c.cfg.Source,
		Sourcetype: c.cfg.Sourcetype,
		Index:      c.cfg.Index,
	}

	payload, err := json.Marshal(env)
	if err == nil {
		c.batchBuf.Write(payload)
		c.batchBuf.WriteByte('\n')
	}
}

// Flush dispatches any pending buffered telemetry events.
func (c *HECClient) Flush() error {
	c.mu.Lock()
	batchData, sendEvents := c.prepareBatchLocked()
	c.mu.Unlock()

	if batchData != nil {
		return c.dispatchBatch(batchData, sendEvents)
	}
	return nil
}

func (c *HECClient) prepareBatchLocked() ([]byte, int) {
	if c.batchEvents == 0 || c.batchBuf.Len() == 0 {
		return nil, 0
	}

	events := c.batchEvents
	batchData := make([]byte, c.batchBuf.Len())
	copy(batchData, c.batchBuf.Bytes())

	c.batchBuf.Reset()
	c.batchEvents = 0
	return batchData, events
}

func (c *HECClient) dispatchBatch(batchData []byte, eventCount int) error {
	var reqBody io.Reader
	var contentEncoding string
	var sendBytes int

	if c.cfg.EnableGzip {
		gzBuf := c.bufPool.Get().(*bytes.Buffer)
		gzBuf.Reset()
		defer c.bufPool.Put(gzBuf)

		gw := c.gzipPool.Get().(*gzip.Writer)
		gw.Reset(gzBuf)

		_, _ = gw.Write(batchData)
		_ = gw.Close()
		c.gzipPool.Put(gw)

		sendBytes = gzBuf.Len()
		reqBody = bytes.NewReader(gzBuf.Bytes())
		contentEncoding = "gzip"
	} else {
		sendBytes = len(batchData)
		reqBody = bytes.NewReader(batchData)
	}

	atomic.AddUint64(&c.stats.EventsSubmitted, uint64(eventCount))
	atomic.AddUint64(&c.stats.BatchesSent, 1)
	atomic.AddUint64(&c.stats.BytesSent, uint64(sendBytes))

	return c.postBatch(reqBody, eventCount, contentEncoding)
}

func (c *HECClient) postBatch(body io.Reader, eventCount int, contentEncoding string) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.targetURL, body)
	if err != nil {
		atomic.AddUint64(&c.stats.EventsFailed, uint64(eventCount))
		return fmt.Errorf("forwarder: create HEC request error: %w", err)
	}

	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}

	if c.cfg.EndpointType == HECEndpointEvent || c.cfg.EndpointType == HECEndpointCustom {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	}

	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		atomic.AddUint64(&c.stats.EventsFailed, uint64(eventCount))
		return fmt.Errorf("forwarder: HEC post failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= http.StatusOK && resp.StatusCode < 300 {
		atomic.AddUint64(&c.stats.EventsAcknowledged, uint64(eventCount))
		return nil
	} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		atomic.AddUint64(&c.stats.EventsRejected, uint64(eventCount))
		return fmt.Errorf("forwarder: HEC rejected batch (HTTP %d %s)", resp.StatusCode, resp.Status)
	}

	atomic.AddUint64(&c.stats.EventsFailed, uint64(eventCount))
	return fmt.Errorf("forwarder: HEC server error (HTTP %d %s)", resp.StatusCode, resp.Status)
}

func (c *HECClient) flushLoop() {
	ticker := time.NewTicker(c.cfg.BatchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-c.flushStop:
			return
		case <-ticker.C:
			_ = c.Flush()
		}
	}
}

// Stats returns atomic metrics for SIEM delivery accounting.
func (c *HECClient) Stats() HECStats {
	return HECStats{
		EventsEnqueued:     atomic.LoadUint64(&c.stats.EventsEnqueued),
		EventsSubmitted:    atomic.LoadUint64(&c.stats.EventsSubmitted),
		EventsAcknowledged: atomic.LoadUint64(&c.stats.EventsAcknowledged),
		EventsRejected:     atomic.LoadUint64(&c.stats.EventsRejected),
		EventsFailed:       atomic.LoadUint64(&c.stats.EventsFailed),
		BatchesSent:        atomic.LoadUint64(&c.stats.BatchesSent),
		BytesSent:          atomic.LoadUint64(&c.stats.BytesSent),
	}
}

// Close flushes any pending batch, closes the background ticker, and shuts down idle transport connections.
func (c *HECClient) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}

	close(c.flushStop)
	err := c.Flush()
	c.client.CloseIdleConnections()
	return err
}

