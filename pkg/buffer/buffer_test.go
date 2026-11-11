package buffer

import (
	"net"
	"testing"
	"time"
)

func TestByteBufferOperations(t *testing.T) {
	buf := GetBuffer()
	defer buf.Release()

	buf.AppendString("Hello")
	buf.AppendByte(' ')
	buf.Append([]byte("World"))
	buf.AppendString(" | Number: ")
	buf.AppendInt(-42)
	buf.AppendString(" | Uint: ")
	buf.AppendUint(100)
	buf.AppendString(" | Hex: ")
	buf.AppendHex(255)
	buf.AppendString(" | IP: ")
	buf.AppendIPv4(net.ParseIP("192.168.1.1"))

	expected := "Hello World | Number: -42 | Uint: 100 | Hex: 0xff | IP: 192.168.1.1"
	if buf.String() != expected {
		t.Fatalf("expected:\n%s\ngot:\n%s", expected, buf.String())
	}
	if buf.Len() != len(expected) {
		t.Fatalf("expected length %d, got %d", len(expected), buf.Len())
	}
}

func TestByteBufferTime(t *testing.T) {
	buf := GetBuffer()
	defer buf.Release()

	fixedTime := time.Date(2026, 11, 12, 4, 30, 0, 0, time.UTC)
	buf.AppendTimeISO8601(fixedTime)
	if buf.String() != "2026-11-12T04:30:00.000000Z" {
		t.Fatalf("unexpected ISO time: %s", buf.String())
	}

	buf.Reset()
	buf.AppendTimeSyslog(fixedTime)
	if buf.String() != "Nov 12 04:30:00" {
		t.Fatalf("unexpected Syslog time: %s", buf.String())
	}
}

func BenchmarkByteBufferAppend(b *testing.B) {
	buf := GetBuffer()
	defer buf.Release()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		buf.AppendString("benchmark_test_string_with_numbers_")
		buf.AppendUint(uint64(i))
	}
}
