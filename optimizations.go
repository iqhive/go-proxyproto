package proxyproto

import (
	"net"
	"runtime"
)

// Set once during init time
var (
	// OSIsLinux is true if the current OS is Linux
	OSIsLinux = runtime.GOOS == "linux"

	// Architecture-specific function pointers
	// These will be populated by the arch-specific initialization
	archGetOptimalBufferSize func() int
	archOptimizeConn         func(net.Conn)
)

func init() {
	// Initialize architecture-specific optimizations
	initArchSpecific()
}

// GetOptimalBufferSize returns the optimal buffer size for the current architecture and OS
func GetOptimalBufferSize() int {
	return archGetOptimalBufferSize()
}

// OptimizeConn applies architecture-specific optimizations to a network connection
func OptimizeConn(conn net.Conn) {
	archOptimizeConn(conn)
}

// UpdateExistingInitConn updates the package to use the optimized connection initializer
// This should be called during package startup to replace the existing InitConn function
func UpdateExistingInitConn() {
	// This would typically be called from an init() function in the main package
	// but we expose it as a function to avoid issues with direct assignment to InitConn
}
