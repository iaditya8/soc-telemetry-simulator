package forwarder

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
)

// FramingType determines line separation over the wire.
type FramingType int

const (
	// FramingNewline delimits records with a trailing '\n' (RFC 3164 / Standard Syslog TCP).
	FramingNewline FramingType = iota
	// FramingOctetCounting prefixes records with their byte length (RFC 5424 octet counting: "123 <message>").
	FramingOctetCounting
)

// TCPConfig configures the TCP/TLS forwarder.
type TCPConfig struct {
	Address            string // "host:port"
	UseTLS             bool
	TLSConfig          *tls.Config
	Framing            FramingType
	ConnectTimeout     time.Duration
	WriteTimeout       time.Duration
	BufferSize         int // Size of internal write buffer per connection (default: 256 KB)
	FlushInterval      time.Duration
	AutoReconnect      bool
	ReconnectDelay     time.Duration
	MaxReconnectDelay  time.Duration
}

// TCPStats holds atomic transmission counters for accounting.
type TCPStats struct {
	EventsSubmitted uint64
	BytesSubmitted  uint64
	ErrorsCount     uint64
	ReconnectsCount uint64
}

// TCPClient manages a single high-performance buffered TCP/TLS streaming socket.
type TCPClient struct {
	cfg       TCPConfig
	conn      net.Conn
	writer    *bufio.Writer
	mu        sync.Mutex
	closed    uint32
	stats     TCPStats
	flushStop chan struct{}
}

// NewTCPClient establishes a buffered streaming TCP or TLS connection.
func NewTCPClient(cfg TCPConfig) (*TCPClient, error) {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Second
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 256 * 1024 // 256 KB buffer for high-throughput batching
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 20 * time.Millisecond
	}
	if cfg.ReconnectDelay <= 0 {
		cfg.ReconnectDelay = 100 * time.Millisecond
	}
	if cfg.MaxReconnectDelay <= 0 {
		cfg.MaxReconnectDelay = 2 * time.Second
	}

	client := &TCPClient{
		cfg:       cfg,
		flushStop: make(chan struct{}),
	}

	if err := client.connect(); err != nil {
		return nil, err
	}

	go client.flushLoop()
	return client, nil
}

func (c *TCPClient) connect() error {
	var conn net.Conn
	var err error

	dialer := &net.Dialer{Timeout: c.cfg.ConnectTimeout}
	if c.cfg.UseTLS {
		tlsConfig := c.cfg.TLSConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{InsecureSkipVerify: true}
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", c.cfg.Address, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", c.cfg.Address)
	}

	if err != nil {
		atomic.AddUint64(&c.stats.ErrorsCount, 1)
		return fmt.Errorf("failed to connect to %s: %w", c.cfg.Address, err)
	}

	// Optimize socket performance
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		_ = tcpConn.SetWriteBuffer(512 * 1024)
	}

	c.conn = conn
	c.writer = bufio.NewWriterSize(conn, c.cfg.BufferSize)
	return nil
}

// WriteEvent streams a single event buffer with configured framing.
func (c *TCPClient) WriteEvent(buf *buffer.ByteBuffer) error {
	if atomic.LoadUint32(&c.closed) == 1 {
		return io.ErrClosedPipe
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.writeLocked(buf.Bytes())
}

// WriteRaw streams raw bytes directly into the buffered socket.
func (c *TCPClient) WriteRaw(data []byte) error {
	if atomic.LoadUint32(&c.closed) == 1 {
		return io.ErrClosedPipe
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.writeLocked(data)
}

func (c *TCPClient) writeLocked(payload []byte) error {
	if c.conn == nil {
		if !c.cfg.AutoReconnect {
			return io.ErrClosedPipe
		}
		if err := c.reconnectLocked(); err != nil {
			return err
		}
	}

	if c.cfg.WriteTimeout > 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
	}

	var bytesWritten int
	var err error

	if c.cfg.Framing == FramingOctetCounting {
		// RFC 5424 octet counting: "<len> <msg>"
		lenStr := strconv.Itoa(len(payload))
		if _, err = c.writer.WriteString(lenStr); err != nil {
			return c.handleWriteErrorLocked(err)
		}
		if err = c.writer.WriteByte(' '); err != nil {
			return c.handleWriteErrorLocked(err)
		}
		bytesWritten += len(lenStr) + 1
	}

	n, err := c.writer.Write(payload)
	bytesWritten += n
	if err != nil {
		return c.handleWriteErrorLocked(err)
	}

	// Ensure line ending for newline framing if not already trailing
	if c.cfg.Framing == FramingNewline && (len(payload) == 0 || payload[len(payload)-1] != '\n') {
		if err = c.writer.WriteByte('\n'); err != nil {
			return c.handleWriteErrorLocked(err)
		}
		bytesWritten++
	}

	atomic.AddUint64(&c.stats.EventsSubmitted, 1)
	atomic.AddUint64(&c.stats.BytesSubmitted, uint64(bytesWritten))
	return nil
}

func (c *TCPClient) handleWriteErrorLocked(err error) error {
	atomic.AddUint64(&c.stats.ErrorsCount, 1)
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	if !c.cfg.AutoReconnect {
		return err
	}
	return c.reconnectLocked()
}

func (c *TCPClient) reconnectLocked() error {
	delay := c.cfg.ReconnectDelay
	for atomic.LoadUint32(&c.closed) == 0 {
		atomic.AddUint64(&c.stats.ReconnectsCount, 1)
		if err := c.connect(); err == nil {
			return nil
		}
		time.Sleep(delay)
		delay *= 2
		if delay > c.cfg.MaxReconnectDelay {
			delay = c.cfg.MaxReconnectDelay
		}
	}
	return io.ErrClosedPipe
}

// Flush flushes any pending buffered bytes to the wire.
func (c *TCPClient) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writer == nil || c.conn == nil {
		return nil
	}
	if c.cfg.WriteTimeout > 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
	}
	return c.writer.Flush()
}

func (c *TCPClient) flushLoop() {
	ticker := time.NewTicker(c.cfg.FlushInterval)
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

// Stats returns atomic metrics for delivery accounting.
func (c *TCPClient) Stats() TCPStats {
	return TCPStats{
		EventsSubmitted: atomic.LoadUint64(&c.stats.EventsSubmitted),
		BytesSubmitted:  atomic.LoadUint64(&c.stats.BytesSubmitted),
		ErrorsCount:     atomic.LoadUint64(&c.stats.ErrorsCount),
		ReconnectsCount: atomic.LoadUint64(&c.stats.ReconnectsCount),
	}
}

// Close flushes buffered bytes and closes the connection.
func (c *TCPClient) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return nil
	}

	close(c.flushStop)

	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	if c.writer != nil {
		firstErr = c.writer.Flush()
	}
	if c.conn != nil {
		if err := c.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.conn = nil
	}
	return firstErr
}

// -------------------------------------------------------------
// TCPForwarderPool manages multiple TCPClients for concurrent pipelines
// -------------------------------------------------------------

// TCPForwarderPool balances streaming load across multiple persistent TCP connections.
type TCPForwarderPool struct {
	clients []*TCPClient
	counter uint64
}

// NewTCPForwarderPool initializes a pool of concurrent TCP streaming clients.
func NewTCPForwarderPool(cfg TCPConfig, poolSize int) (*TCPForwarderPool, error) {
	if poolSize <= 0 {
		poolSize = 4
	}

	clients := make([]*TCPClient, poolSize)
	for i := 0; i < poolSize; i++ {
		client, err := NewTCPClient(cfg)
		if err != nil {
			// Clean up already initialized clients
			for j := 0; j < i; j++ {
				_ = clients[j].Close()
			}
			return nil, fmt.Errorf("failed to initialize pool worker %d: %w", i, err)
		}
		clients[i] = client
	}

	return &TCPForwarderPool{
		clients: clients,
	}, nil
}

// WriteEvent routes an event buffer across the connection pool in a lock-free round-robin fashion.
func (p *TCPForwarderPool) WriteEvent(buf *buffer.ByteBuffer) error {
	idx := atomic.AddUint64(&p.counter, 1) % uint64(len(p.clients))
	return p.clients[idx].WriteEvent(buf)
}

// WriteRaw routes raw bytes across the pool.
func (p *TCPForwarderPool) WriteRaw(data []byte) error {
	idx := atomic.AddUint64(&p.counter, 1) % uint64(len(p.clients))
	return p.clients[idx].WriteRaw(data)
}

// Flush flushes all clients in the pool.
func (p *TCPForwarderPool) Flush() error {
	var firstErr error
	for _, c := range p.clients {
		if err := c.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Stats aggregates transmission stats across all pool clients.
func (p *TCPForwarderPool) Stats() TCPStats {
	var total TCPStats
	for _, c := range p.clients {
		s := c.Stats()
		total.EventsSubmitted += s.EventsSubmitted
		total.BytesSubmitted += s.BytesSubmitted
		total.ErrorsCount += s.ErrorsCount
		total.ReconnectsCount += s.ReconnectsCount
	}
	return total
}

// Close gracefully closes all clients in the pool.
func (p *TCPForwarderPool) Close() error {
	var firstErr error
	for _, c := range p.clients {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
