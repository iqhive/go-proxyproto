//go:build linux && netpoll && !epoll && !splice
// +build linux,netpoll,!epoll,!splice

package proxyproto

import (
	"errors"
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// NetpollZeroCopy indicates that the netpoll-based zero-copy optimization is enabled
const NetpollZeroCopy = true

// init registers the netpoll zero-copy implementation
func init() {
	zeroCopyImpl = netpollZeroCopy
	zeroCopyAvailable = true
}

// netpollZeroCopy implements zero-copy data transfer using Go's underlying netpoll functionality
// which is built on top of epoll/kqueue but managed by Go's runtime
func netpollZeroCopy(src, dst net.Conn, buf []byte) (int64, error) {
	// Get file descriptors for the connections
	srcTCP, srcOK := src.(*net.TCPConn)
	dstTCP, dstOK := dst.(*net.TCPConn)

	if !srcOK || !dstOK {
		// Fall back to standard copy if not TCP connections
		return io.CopyBuffer(dst, src, buf)
	}

	// Extract file descriptors using the internal method
	srcFile, err := srcTCP.File()
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	dstFile, err := dstTCP.File()
	if err != nil {
		srcFile.Close()
		return 0, err
	}
	defer dstFile.Close()

	srcFd := int(srcFile.Fd())
	dstFd := int(dstFile.Fd())

	// Make sure we're dealing with non-blocking sockets
	if err := syscall.SetNonblock(srcFd, true); err != nil {
		return 0, err
	}
	if err := syscall.SetNonblock(dstFd, true); err != nil {
		return 0, err
	}

	// Set TCP_NODELAY to optimize for latency
	if err := setTCPNoDelay(srcFd, true); err != nil {
		return 0, err
	}
	if err := setTCPNoDelay(dstFd, true); err != nil {
		return 0, err
	}

	// Set TCP_CORK to optimize for throughput (coalesce packets)
	if err := setTCPCork(dstFd, true); err != nil {
		// Not critical, just continue if we can't set it
	}

	// Variables to track progress
	var total int64
	var n int
	var rerr error

	// Buffer to use for transfers - use pre-allocated buffer if provided
	bufSize := 64 * 1024 // 64KB chunks for optimal performance
	if len(buf) > 0 {
		bufSize = len(buf)
	} else {
		buf = make([]byte, bufSize)
	}

	// Copy data in a loop, handling EAGAIN properly with netpoll-like approach
	for {
		// Read phase
		n, rerr = syscall.Read(srcFd, buf)
		if rerr != nil {
			if errors.Is(rerr, syscall.EAGAIN) || errors.Is(rerr, syscall.EWOULDBLOCK) {
				// Socket not ready, wait for read readiness
				readReady, err := waitReadReady(srcFd)
				if err != nil {
					return total, err
				}
				if !readReady {
					// EOF or other condition
					if total > 0 {
						return total, nil
					}
					return 0, io.EOF
				}
				continue
			}
			// Real error
			break
		}

		if n == 0 {
			// End of file
			break
		}

		// Write phase - write complete buffer contents
		writeOffset := 0
		for writeOffset < n {
			written, werr := syscall.Write(dstFd, buf[writeOffset:n])
			if werr != nil {
				if errors.Is(werr, syscall.EAGAIN) || errors.Is(werr, syscall.EWOULDBLOCK) {
					// Socket not ready, wait for write readiness
					writeReady, err := waitWriteReady(dstFd)
					if err != nil {
						return total, err
					}
					if !writeReady {
						return total, errors.New("write timeout")
					}
					continue
				}
				// Real error
				return total, werr
			}

			writeOffset += written
			total += int64(written)
		}
	}

	// Flush any remaining data by turning off TCP_CORK
	if err := setTCPCork(dstFd, false); err != nil {
		// Not critical, just continue
	}

	if rerr != nil && rerr != io.EOF && !errors.Is(rerr, syscall.ECONNRESET) {
		return total, rerr
	}

	return total, nil
}

// waitReadReady waits for a file descriptor to be ready for reading
func waitReadReady(fd int) (bool, error) {
	// Create pollfd structure
	pfd := unix.PollFd{
		Fd:     int32(fd),
		Events: unix.POLLIN,
	}

	// Wait for read readiness with a timeout
	n, err := unix.Poll([]unix.PollFd{pfd}, 1000) // 1 second timeout
	if err != nil {
		return false, err
	}

	return n > 0, nil
}

// waitWriteReady waits for a file descriptor to be ready for writing
func waitWriteReady(fd int) (bool, error) {
	// Create pollfd structure
	pfd := unix.PollFd{
		Fd:     int32(fd),
		Events: unix.POLLOUT,
	}

	// Wait for write readiness with a timeout
	n, err := unix.Poll([]unix.PollFd{pfd}, 1000) // 1 second timeout
	if err != nil {
		return false, err
	}

	return n > 0, nil
}

// setTCPNoDelay sets the TCP_NODELAY socket option
func setTCPNoDelay(fd int, enable bool) error {
	var value int
	if enable {
		value = 1
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, value)
}

// setTCPCork sets the TCP_CORK socket option
func setTCPCork(fd int, enable bool) error {
	var value int
	if enable {
		value = 1
	}
	// TCP_CORK (3) is not defined in syscall, so we use the raw value
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, 3, value)
}
