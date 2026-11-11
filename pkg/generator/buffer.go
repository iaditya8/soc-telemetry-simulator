package generator

import (
	"github.com/iaditya8/soc-telemetry-simulator/pkg/buffer"
)

// Re-export ByteBuffer and helper functions from pkg/buffer for backwards compatibility.
type ByteBuffer = buffer.ByteBuffer

const (
	DefaultBufferCapacity = buffer.DefaultBufferCapacity
	MaxRecycledCapacity   = buffer.MaxRecycledCapacity
)

// GetBuffer retrieves a recycled ByteBuffer from the global pool.
func GetBuffer() *ByteBuffer {
	return buffer.GetBuffer()
}
