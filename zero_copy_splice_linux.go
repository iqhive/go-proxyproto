//go:build linux && splice && !netpoll && !epoll
// +build linux,splice,!netpoll,!epoll

package proxyproto

import (
	"errors"
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// SpliceZeroCopy indicates that the splice-based zero-copy optimization is enabled
const SpliceZeroCopy = true

// init registers the splice zero-copy implementation
func init() {
	zeroCopyImpl = spliceZeroCopy
	zeroCopyAvailable = true
}

// splice syscall parameters
const (
	// SPLICE_F_MOVE - pipe page is moved instead of copied (kernel might ignore this)
	SPLICE_F_MOVE = 1
	// SPLICE_F_NONBLOCK - non-blocking operation
	SPLICE_F_NONBLOCK = 2
	// SPLICE_F_MORE - more data will be coming in next splices
	SPLICE_F_MORE = 4
)

// spliceZeroCopy implements zero-copy data transfer using Linux's splice syscall
// Splice is a true zero-copy mechanism that moves data between file descriptors
// within the kernel, avoiding copying between kernel and user space
func spliceZeroCopy(src, dst net.Conn, buf []byte) (int64, error) {
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

	// Set optimal socket options for performance
	syscall.SetsockoptInt(srcFd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	syscall.SetsockoptInt(dstFd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
	syscall.SetsockoptInt(dstFd, syscall.IPPROTO_TCP, 3 /* TCP_CORK */, 1)

	// Create pipe for splice operations
	pipeFds := make([]int, 2)
	if err := syscall.Pipe(pipeFds); err != nil {
		return 0, err
	}
	pipeR, pipeW := pipeFds[0], pipeFds[1]
	defer syscall.Close(pipeR)
	defer syscall.Close(pipeW)

	// Variables to track progress
	var total int64
	spliceBufSize := 64 * 1024 // 64KB is generally optimal for most systems

	for {
		// First splice: read from source into the pipe
		n, err := syscallSplice(srcFd, nil, pipeW, nil, spliceBufSize,
			SPLICE_F_MOVE|SPLICE_F_NONBLOCK|SPLICE_F_MORE)

		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				// Socket not ready, wait for readiness
				readReady, err := waitForIO(srcFd, true, 1000)
				if err != nil {
					return total, err
				}
				if !readReady {
					// Socket not ready after timeout
					if total > 0 {
						return total, nil
					}
					continue
				}
				continue
			}

			if errors.Is(err, syscall.EINVAL) {
				// Some network interfaces don't support splice
				// Fall back to standard copy
				return io.CopyBuffer(dst, src, buf)
			}

			// Handle errors
			if err == io.EOF || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
				return total, nil
			}

			return total, err
		}

		if n == 0 {
			// End of data
			break
		}

		// Second splice: write from the pipe to destination
		written := int64(0)
		for written < n {
			w, err := syscallSplice(pipeR, nil, dstFd, nil, int(n-written),
				SPLICE_F_MOVE|SPLICE_F_NONBLOCK)

			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					// Socket not ready, wait for writability
					writeReady, err := waitForIO(dstFd, false, 1000)
					if err != nil {
						return total, err
					}
					if !writeReady {
						// Write timeout or error
						return total, errors.New("write timeout")
					}
					continue
				}

				return total, err
			}

			if w == 0 {
				return total, errors.New("zero bytes written during splice")
			}

			written += w
			total += w
		}
	}

	// Disable TCP_CORK to flush any remaining data
	syscall.SetsockoptInt(dstFd, syscall.IPPROTO_TCP, 3 /* TCP_CORK */, 0)

	return total, nil
}

// syscallSplice makes the actual splice syscall
func syscallSplice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (int64, error) {
	return unix.Splice(rfd, roff, wfd, woff, len, flags)
}

// waitForIO waits for a file descriptor to be ready for I/O operations
func waitForIO(fd int, isRead bool, timeoutMs int) (bool, error) {
	var pfd unix.PollFd
	pfd.Fd = int32(fd)

	if isRead {
		pfd.Events = unix.POLLIN
	} else {
		pfd.Events = unix.POLLOUT
	}

	n, err := unix.Poll([]unix.PollFd{pfd}, timeoutMs)
	if err != nil {
		return false, err
	}

	return n > 0, nil
}
