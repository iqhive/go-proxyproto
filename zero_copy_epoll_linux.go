//go:build linux && epoll && !netpoll && !splice
// +build linux,epoll,!netpoll,!splice

package proxyproto

import (
	"errors"
	"io"
	"net"
	"syscall"
)

// EpollZeroCopy indicates that the epoll-based zero-copy optimization is enabled
const EpollZeroCopy = true

// init registers the epoll zero-copy implementation
func init() {
	zeroCopyImpl = epollZeroCopy
	zeroCopyAvailable = true
}

// epollZeroCopy implements zero-copy data transfer using Linux's epoll syscall directly
// This provides maximum efficiency by directly using the kernel's event notification system
func epollZeroCopy(src, dst net.Conn, buf []byte) (int64, error) {
	// Get file descriptors for the connections
	srcTCP, srcOK := src.(*net.TCPConn)
	dstTCP, dstOK := dst.(*net.TCPConn)

	if !srcOK || !dstOK {
		// Fall back to standard copy if not TCP connections
		return io.CopyBuffer(dst, src, buf)
	}

	// Extract file descriptors
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

	// Make sockets non-blocking
	if err := syscall.SetNonblock(srcFd, true); err != nil {
		return 0, err
	}
	if err := syscall.SetNonblock(dstFd, true); err != nil {
		return 0, err
	}

	// Optimize socket settings
	if err := syscall.SetsockoptInt(srcFd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
		return 0, err
	}
	if err := syscall.SetsockoptInt(dstFd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
		return 0, err
	}

	// Enable TCP_CORK on destination to coalesce packets
	if err := syscall.SetsockoptInt(dstFd, syscall.IPPROTO_TCP, 3 /* TCP_CORK */, 1); err != nil {
		// Not critical if this fails
	}

	// Create epoll instance
	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(epfd)

	// Register source descriptor for read events
	srcEvent := syscall.EpollEvent{
		Events: syscall.EPOLLIN | syscall.EPOLLRDHUP,
		Fd:     int32(srcFd),
	}
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, srcFd, &srcEvent); err != nil {
		return 0, err
	}

	// Register destination descriptor for write events
	dstEvent := syscall.EpollEvent{
		Events: syscall.EPOLLOUT,
		Fd:     int32(dstFd),
	}
	if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, dstFd, &dstEvent); err != nil {
		return 0, err
	}

	// Variables to track progress
	var total int64
	var n int
	var rerr error

	// Buffer for transfers - use pre-allocated buffer if provided
	bufSize := 64 * 1024 // 64KB for optimal throughput
	if len(buf) > 0 {
		bufSize = len(buf)
	} else {
		buf = make([]byte, bufSize)
	}

	// Initialize event array for epoll_wait
	events := make([]syscall.EpollEvent, 2)
	timeout := 1000 // 1 second timeout in milliseconds

	// Main copy loop using epoll for efficient I/O multiplexing
	for {
		// Wait for events (readability of source or writability of destination)
		nevents, err := syscall.EpollWait(epfd, events, timeout)
		if err != nil {
			if err == syscall.EINTR {
				// Interrupted by signal, retry
				continue
			}
			return total, err
		}

		if nevents == 0 {
			// Timeout occurred
			if total > 0 {
				return total, nil
			}
			continue
		}

		// Process events
		readReady := false
		writeReady := false

		for i := 0; i < nevents; i++ {
			if events[i].Fd == int32(srcFd) {
				if events[i].Events&(syscall.EPOLLIN|syscall.EPOLLRDHUP) != 0 {
					readReady = true
				}
				if events[i].Events&(syscall.EPOLLERR|syscall.EPOLLHUP) != 0 {
					// Connection closed or error on source
					if total > 0 {
						return total, nil
					}
					return 0, io.EOF
				}
			} else if events[i].Fd == int32(dstFd) {
				if events[i].Events&syscall.EPOLLOUT != 0 {
					writeReady = true
				}
				if events[i].Events&(syscall.EPOLLERR|syscall.EPOLLHUP) != 0 {
					// Error on destination
					return total, errors.New("destination connection error")
				}
			}
		}

		// If source is readable, read data
		if readReady {
			n, rerr = syscall.Read(srcFd, buf)
			if rerr != nil {
				if errors.Is(rerr, syscall.EAGAIN) || errors.Is(rerr, syscall.EWOULDBLOCK) {
					// False readiness, wait for next epoll event
					continue
				}
				// Real error or EOF
				break
			}

			if n == 0 {
				// End of file
				break
			}

			// Data read successfully, register interest in destination writability
			if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_MOD, dstFd, &dstEvent); err != nil {
				return total, err
			}

			// Try to write immediately if possible
			writeOffset := 0
			for writeOffset < n {
				if writeReady {
					written, werr := syscall.Write(dstFd, buf[writeOffset:n])
					if werr != nil {
						if errors.Is(werr, syscall.EAGAIN) || errors.Is(werr, syscall.EWOULDBLOCK) {
							// Wait for next epoll event
							break
						}
						return total, werr
					}

					writeOffset += written
					total += int64(written)

					if writeOffset >= n {
						// All data written, register interest in source readability again
						if err := syscall.EpollCtl(epfd, syscall.EPOLL_CTL_MOD, srcFd, &srcEvent); err != nil {
							return total, err
						}
						break
					}
				} else {
					// Wait for writability via epoll
					break
				}
			}
		}
	}

	// Flush remaining data by disabling TCP_CORK
	if err := syscall.SetsockoptInt(dstFd, syscall.IPPROTO_TCP, 3 /* TCP_CORK */, 0); err != nil {
		// Not critical if this fails
	}

	if rerr != nil && rerr != io.EOF && !errors.Is(rerr, syscall.ECONNRESET) {
		return total, rerr
	}

	return total, nil
}
