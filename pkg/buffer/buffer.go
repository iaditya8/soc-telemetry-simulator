package buffer

import (
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultBufferCapacity = 1024 // 1 KB typical security log size
	MaxRecycledCapacity   = 8192 // Don't recycle abnormally large buffers to avoid memory leaks
)

// bufferPool recycles byte slices to eliminate heap allocations during 100k+ EPS runs.
var bufferPool = sync.Pool{
	New: func() interface{} {
		return &ByteBuffer{
			buf: make([]byte, 0, DefaultBufferCapacity),
		}
	},
}

// ByteBuffer provides high-performance, zero-allocation byte appending methods.
type ByteBuffer struct {
	buf []byte
}

// GetBuffer retrieves a recycled ByteBuffer from the global pool.
func GetBuffer() *ByteBuffer {
	b := bufferPool.Get().(*ByteBuffer)
	b.Reset()
	return b
}

// Release returns the buffer to the pool if within acceptable capacity limits.
func (b *ByteBuffer) Release() {
	if cap(b.buf) <= MaxRecycledCapacity {
		b.Reset()
		bufferPool.Put(b)
	}
}

// Reset clears the buffer length without freeing allocated capacity.
func (b *ByteBuffer) Reset() {
	b.buf = b.buf[:0]
}

// Bytes returns the internal byte slice.
func (b *ByteBuffer) Bytes() []byte {
	return b.buf
}

// Len returns the current length of the buffer.
func (b *ByteBuffer) Len() int {
	return len(b.buf)
}

// String returns a string copy of the buffer content.
func (b *ByteBuffer) String() string {
	return string(b.buf)
}

// Append appends raw bytes to the buffer.
func (b *ByteBuffer) Append(p []byte) {
	b.buf = append(b.buf, p...)
}

// AppendByte appends a single byte.
func (b *ByteBuffer) AppendByte(c byte) {
	b.buf = append(b.buf, c)
}

// AppendString appends a string with zero heap allocation.
func (b *ByteBuffer) AppendString(s string) {
	b.buf = append(b.buf, s...)
}

// AppendInt appends a signed integer in decimal format.
func (b *ByteBuffer) AppendInt(n int64) {
	b.buf = strconv.AppendInt(b.buf, n, 10)
}

// AppendUint appends an unsigned integer in decimal format.
func (b *ByteBuffer) AppendUint(n uint64) {
	b.buf = strconv.AppendUint(b.buf, n, 10)
}

// AppendHex appends an unsigned integer in hexadecimal format with 0x prefix (e.g. 0x1a2b).
func (b *ByteBuffer) AppendHex(n uint64) {
	b.buf = append(b.buf, '0', 'x')
	b.buf = strconv.AppendUint(b.buf, n, 16)
}

// AppendIPv4 appends an IPv4 address directly without string allocation.
func (b *ByteBuffer) AppendIPv4(ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		b.buf = strconv.AppendUint(b.buf, uint64(ip4[0]), 10)
		b.buf = append(b.buf, '.')
		b.buf = strconv.AppendUint(b.buf, uint64(ip4[1]), 10)
		b.buf = append(b.buf, '.')
		b.buf = strconv.AppendUint(b.buf, uint64(ip4[2]), 10)
		b.buf = append(b.buf, '.')
		b.buf = strconv.AppendUint(b.buf, uint64(ip4[3]), 10)
		return
	}
	b.AppendString(ip.String())
}

// AppendTimeISO8601 appends UTC ISO 8601 timestamp: 2026-11-12T04:15:30.123456Z
func (b *ByteBuffer) AppendTimeISO8601(t time.Time) {
	b.buf = t.UTC().AppendFormat(b.buf, "2006-01-02T15:04:05.000000Z07:00")
}

// AppendTimeSyslog appends BSD RFC 3164 timestamp: Nov 12 04:15:30
func (b *ByteBuffer) AppendTimeSyslog(t time.Time) {
	b.buf = t.AppendFormat(b.buf, "Jan _2 15:04:05")
}
