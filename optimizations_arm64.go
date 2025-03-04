//go:build arm64
// +build arm64

package proxyproto

import (
	"net"
	"runtime"
	"syscall"
	"time"
)

// Architecture-specific constants for ARM64
const (
	// CPU cache line size for ARM64 is typically 64 bytes
	archCacheLineSize = 64

	// Optimal buffer sizes tuned for ARM64
	archReadBufferSize  = 128 * 1024 // 128KB read buffer
	archWriteBufferSize = 128 * 1024 // 128KB write buffer

	// Buffer size aligned with common page size on ARM64
	archDefaultBufferSize = 4096 // 4KB - common page size on ARM64
)

// initArchSpecific initializes architecture-specific optimizations for ARM64
func initArchSpecific() {
	// Register architecture-specific functions that may be called from generic code
	archGetOptimalBufferSize = arm64GetOptimalBufferSize
	archOptimizeConn = arm64OptimizeConn
}

// arm64GetOptimalBufferSize returns the optimal buffer size for ARM64 architecture
func arm64GetOptimalBufferSize() int {
	if OSIsLinux {
		return archDefaultBufferSize // 4KB aligns with Linux page size
	}

	// For other OSes, use a buffer size tuned for ARM64
	switch runtime.GOOS {
	case "darwin":
		return 16 * 1024 // 16KB for macOS on ARM64 (M1/M2)
	case "windows":
		return 8 * 1024 // 8KB for Windows on ARM64
	default:
		return 8 * 1024 // Default for other OSes on ARM64
	}
}

// arm64OptimizeConn applies ARM64-specific optimizations to network connections
func arm64OptimizeConn(conn net.Conn) {
	// Apply specific optimizations for ARM64 architecture
	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		return
	}

	// Disable Nagle's algorithm for all platforms
	tcpConn.SetNoDelay(true)

	// Platform-specific optimizations
	if OSIsLinux {
		// Linux-specific optimizations for ARM64

		// ARM64 often benefits from different buffer sizes compared to AMD64
		// due to different memory access patterns and cache behavior
		tcpConn.SetReadBuffer(archReadBufferSize)
		tcpConn.SetWriteBuffer(archWriteBufferSize)

		// Set keepalive settings
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)

		// For ARM64 Linux, we can apply specific socket options
		if fd, err := getFd(tcpConn); err == nil {
			// TCP_QUICKACK (12) - enable quickack mode
			syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, 12, 1)
		}
	} else if runtime.GOOS == "darwin" {
		// macOS-specific optimizations for ARM64 (Apple Silicon)
		// Apple Silicon has different memory characteristics
		tcpConn.SetReadBuffer(128 * 1024)  // 128KB
		tcpConn.SetWriteBuffer(128 * 1024) // 128KB
		tcpConn.SetKeepAlive(true)
	} else if runtime.GOOS == "windows" {
		// Windows-specific optimizations for ARM64
		tcpConn.SetReadBuffer(64 * 1024)  // 64KB
		tcpConn.SetWriteBuffer(64 * 1024) // 64KB
		tcpConn.SetKeepAlive(true)
	}
}

// getFd extracts the file descriptor from a TCP connection
func getFd(tcpConn *net.TCPConn) (int, error) {
	// Extract the file descriptor from a TCPConn for low-level socket operations
	file, err := tcpConn.File()
	if err != nil {
		return -1, err
	}
	defer file.Close()

	return int(file.Fd()), nil
}
