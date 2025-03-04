package proxyproto

import (
	"io"
	"net"
)

// Define the zero-copy function type
type zeroCopyFunc func(src, dst net.Conn, buf []byte) (int64, error)

// Global variables for zero-copy implementation
var (
	// zeroCopyImpl is the currently active zero-copy implementation
	zeroCopyImpl zeroCopyFunc

	// zeroCopyAvailable indicates if any optimized zero-copy method is available
	zeroCopyAvailable bool = false
)

// init sets up the default fallback implementation
func init() {
	// Default fallback if no specialized implementation is chosen
	zeroCopyImpl = fallbackCopy
}

// ZeroCopyAvailable returns true if an optimized zero-copy implementation is available
func ZeroCopyAvailable() bool {
	return zeroCopyAvailable
}

// ZeroCopy transfers data from src to dst using the most efficient available method
// with minimized memory copying. It's designed for high-performance proxy scenarios.
// Returns the number of bytes transferred and any error encountered.
func ZeroCopy(src, dst net.Conn) (int64, error) {
	// Use a 64KB buffer for optimal transfers
	buf := make([]byte, 64*1024)
	return zeroCopyImpl(src, dst, buf)
}

// ZeroCopyWithBuffer transfers data from src to dst using the provided buffer
// and the most efficient available method with minimized memory copying.
func ZeroCopyWithBuffer(src, dst net.Conn, buf []byte) (int64, error) {
	return zeroCopyImpl(src, dst, buf)
}

// fallbackCopy is the standard fallback implementation used when optimized
// zero-copy mechanisms aren't available or applicable
func fallbackCopy(src, dst net.Conn, buf []byte) (int64, error) {
	// Use CopyBuffer with the provided buffer to minimize allocations
	return io.CopyBuffer(dst, src, buf)
}

// Update the Conn.WriteTo method to use our zero-copy implementation
func (p *Conn) WriteTo(w io.Writer) (int64, error) {
	dstConn, ok := w.(net.Conn)

	// If we have a direct connection and zero-copy is available, use it
	if ok && zeroCopyAvailable {
		return ZeroCopy(p.conn, dstConn)
	}

	// Fall back to standard io.Copy
	return io.Copy(w, p.conn)
}

// Update the Conn.ReadFrom method to use our zero-copy implementation
func (p *Conn) ReadFrom(r io.Reader) (int64, error) {
	srcConn, ok := r.(net.Conn)

	// If we have a direct connection and zero-copy is available, use it
	if ok && zeroCopyAvailable {
		return ZeroCopy(srcConn, p.conn)
	}

	// Fall back to standard io.Copy
	return io.Copy(p.conn, r)
}
