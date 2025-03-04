//go:build amd64
// +build amd64

package proxyproto

import (
	"net"
	"runtime"
	"syscall"
	"time"
)

// Architecture-specific constants for AMD64
const (
	// CPU cache line size for AMD64 is typically 64 bytes
	archCacheLineSize = 64

	// Optimal buffer sizes tuned for AMD64
	archReadBufferSize  = 256 * 1024 // 256KB read buffer
	archWriteBufferSize = 256 * 1024 // 256KB write buffer

	// Buffer size aligned with common page size and cache line
	archDefaultBufferSize = 4096 // 4KB - common page size on x86_64/amd64
)

// initArchSpecific initializes architecture-specific optimizations for AMD64
func initArchSpecific() {
	// Register architecture-specific functions that may be called from generic code
	archGetOptimalBufferSize = amd64GetOptimalBufferSize
	archOptimizeConn = amd64OptimizeConn
}

// amd64GetOptimalBufferSize returns the optimal buffer size for AMD64 architecture
func amd64GetOptimalBufferSize() int {
	if OSIsLinux {
		return archDefaultBufferSize // 4KB aligns with Linux page size
	}

	// For other OSes, use a buffer size tuned for AMD64
	switch runtime.GOOS {
	case "darwin":
		return 16 * 1024 // 16KB for macOS on AMD64
	case "windows":
		return 8 * 1024 // 8KB for Windows on AMD64
	default:
		return 8 * 1024 // Default for other OSes on AMD64
	}
}

// amd64OptimizeConn applies AMD64-specific optimizations to network connections
func amd64OptimizeConn(conn net.Conn) {
	// Apply specific optimizations for AMD64 architecture
	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return
	}

	// Disable Nagle's algorithm for all platforms
	tcpConn.SetNoDelay(true)

	// Platform-specific optimizations
	if OSIsLinux {
		// Linux-specific optimizations for AMD64

		// Use larger buffers on AMD64 Linux systems
		tcpConn.SetReadBuffer(archReadBufferSize)
		tcpConn.SetWriteBuffer(archWriteBufferSize)

		// Set keepalive settings
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)

		// Try to set TCP_QUICKACK for AMD64 Linux
		if fd, err := getFd(tcpConn); err == nil {
			// TCP_QUICKACK (12) - enable quickack mode
			syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, 12, 1)
		}
	} else if runtime.GOOS == "darwin" {
		// macOS-specific optimizations for AMD64
		tcpConn.SetReadBuffer(128 * 1024)  // 128KB
		tcpConn.SetWriteBuffer(128 * 1024) // 128KB
		tcpConn.SetKeepAlive(true)
	} else if runtime.GOOS == "windows" {
		// Windows-specific optimizations for AMD64
		tcpConn.SetReadBuffer(64 * 1024)  // 64KB
		tcpConn.SetWriteBuffer(64 * 1024) // 64KB
		tcpConn.SetKeepAlive(true)
	}
}

// getFd extracts the file descriptor from a TCP connection
func getFd(tcpConn *net.TCPConn) (int, error) {
	// This is a bit hacky but allows us to set socket options directly
	// Extract the file descriptor from a TCPConn for low-level socket operations
	file, err := tcpConn.File()
	if err != nil {
		return -1, err
	}
	defer file.Close()

	return int(file.Fd()), nil
}
