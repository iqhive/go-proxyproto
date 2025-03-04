//go:build !amd64 && !arm64
// +build !amd64,!arm64

package proxyproto

import (
	"net"
	"runtime"
	"time"
)

// Architecture-specific constants for generic platform
const (
	// Default cache line size for unknown architectures
	archCacheLineSize = 64

	// Conservative buffer sizes that work well on most platforms
	archReadBufferSize  = 64 * 1024 // 64KB read buffer
	archWriteBufferSize = 64 * 1024 // 64KB write buffer

	// Default buffer size for generic implementation
	archDefaultBufferSize = 4096 // 4KB - common page size
)

// initArchSpecific initializes architecture-specific optimizations for generic platforms
func initArchSpecific() {
	// Register architecture-specific functions that may be called from generic code
	archGetOptimalBufferSize = genericGetOptimalBufferSize
	archOptimizeConn = genericOptimizeConn
}

// genericGetOptimalBufferSize returns a reasonable buffer size for unknown architectures
func genericGetOptimalBufferSize() int {
	// Use more conservative buffer sizes for unknown architectures
	switch runtime.GOOS {
	case "linux":
		return 8 * 1024 // 8KB for Linux
	case "darwin":
		return 8 * 1024 // 8KB for macOS
	case "windows":
		return 4 * 1024 // 4KB for Windows
	default:
		return 4 * 1024 // 4KB default
	}
}

// genericOptimizeConn applies basic optimizations to network connections
// for platforms where we don't have specific tuning
func genericOptimizeConn(conn net.Conn) {
	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return
	}

	// Disable Nagle's algorithm for reduced latency on all platforms
	tcpConn.SetNoDelay(true)

	// Apply conservative optimizations based on OS
	switch runtime.GOOS {
	case "linux":
		// Generic Linux optimizations
		tcpConn.SetReadBuffer(archReadBufferSize)
		tcpConn.SetWriteBuffer(archWriteBufferSize)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	case "darwin":
		// Generic macOS optimizations
		tcpConn.SetReadBuffer(32 * 1024)  // 32KB
		tcpConn.SetWriteBuffer(32 * 1024) // 32KB
		tcpConn.SetKeepAlive(true)
	case "windows":
		// Generic Windows optimizations
		tcpConn.SetReadBuffer(32 * 1024)  // 32KB
		tcpConn.SetWriteBuffer(32 * 1024) // 32KB
		tcpConn.SetKeepAlive(true)
	default:
		// For unknown OSes, just apply basic settings
		tcpConn.SetReadBuffer(32 * 1024)  // 32KB
		tcpConn.SetWriteBuffer(32 * 1024) // 32KB
		tcpConn.SetKeepAlive(true)
	}
}
