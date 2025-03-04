package proxyproto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// DefaultReadHeaderTimeout is how long header processing waits for header to
	// be read from the wire, if Listener.ReaderHeaderTimeout is not set.
	// It's kept as a global variable so to make it easier to find and override,
	// e.g. go build -ldflags -X "github.com/pires/go-proxyproto.DefaultReadHeaderTimeout=1s"
	DefaultReadHeaderTimeout = 10 * time.Second

	// ErrInvalidUpstream should be returned when an upstream connection address
	// is not trusted, and therefore is invalid.
	ErrInvalidUpstream = fmt.Errorf("proxyproto: upstream connection address not trusted for PROXY information")

	// bufferPool is a pool of reusable buffers to reduce memory allocations
	bufferPool = sync.Pool{
		New: func() interface{} {
			// Size buffer for most common CPU cache line size (64 bytes on most platforms)
			// and enough for most proxy protocol headers
			size := 128
			b := make([]byte, 0, size)
			return &b
		},
	}

	// readerPool is a pool of bufio.Reader objects to reduce allocations
	readerPool = sync.Pool{
		New: func() interface{} {
			// Size buffer for optimal I/O for most systems
			size := getOptimalBufferSize()
			return bufio.NewReaderSize(nil, size)
		},
	}

	// Platform optimization flags
	isLinux = runtime.GOOS == "linux"
)

// getOptimalBufferSize returns the optimal buffer size for the platform
// On Linux, use 4KB which aligns with the page size for better memory usage
// On other platforms, use 4KB as a reasonable default for network operations
func getOptimalBufferSize() int {
	// Delegate to architecture-specific implementation
	return GetOptimalBufferSize()
}

// getBuffer gets a buffer from the pool
func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// putBuffer returns a buffer to the pool
func putBuffer(b *[]byte) {
	// Reset the buffer before returning it to the pool
	*b = (*b)[:0]
	bufferPool.Put(b)
}

// getReader gets a bufio.Reader from the pool and resets it with the given reader
func getReader(r io.Reader) *bufio.Reader {
	br := readerPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

// putReader returns a bufio.Reader to the pool
func putReader(br *bufio.Reader) {
	br.Reset(nil)
	readerPool.Put(br)
}

// Listener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol.
// If the connection is using the protocol, the RemoteAddr() will return
// the correct client address. ReadHeaderTimeout will be applied to all
// connections in order to prevent blocking operations. If no ReadHeaderTimeout
// is set, a default of 10s will be used. This can be disabled by setting the
// timeout to < 0.
//
// Only one of Policy or ConnPolicy should be provided. If both are provided then
// a panic would occur during accept.
type Listener struct {
	Listener net.Listener
	// Deprecated: use ConnPolicyFunc instead. This will be removed in future release.
	Policy            PolicyFunc
	ConnPolicy        ConnPolicyFunc
	ValidateHeader    Validator
	ReadHeaderTimeout time.Duration
}

// Conn is used to wrap and underlying connection which
// may be speaking the Proxy Protocol. If it is, the RemoteAddr() will
// return the address of the client instead of the proxy address. Each connection
// will have its own readHeaderTimeout and readDeadline set by the Accept() call.
type Conn struct {
	readDeadline      atomic.Value // time.Time
	once              sync.Once
	readErr           error
	conn              net.Conn
	bufReader         *bufio.Reader
	reader            io.Reader
	header            *Header
	ProxyHeaderPolicy Policy
	Validate          Validator
	readHeaderTimeout time.Duration
}

// Validator receives a header and decides whether it is a valid one
// In case the header is not deemed valid it should return an error.
type Validator func(*Header) error

// ValidateHeader adds given validator for proxy headers to a connection when passed as option to NewConn()
func ValidateHeader(v Validator) func(*Conn) {
	return func(c *Conn) {
		if v != nil {
			c.Validate = v
		}
	}
}

// SetReadHeaderTimeout sets the readHeaderTimeout for a connection when passed as option to NewConn()
func SetReadHeaderTimeout(t time.Duration) func(*Conn) {
	return func(c *Conn) {
		if t >= 0 {
			c.readHeaderTimeout = t
		}
	}
}

// Accept waits for and returns the next valid connection to the listener.
func (p *Listener) Accept() (net.Conn, error) {
	for {
		// Get the underlying connection
		conn, err := p.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Apply platform-specific optimizations immediately
		InitConn(conn)

		proxyHeaderPolicy := USE
		if p.Policy != nil && p.ConnPolicy != nil {
			panic("only one of policy or connpolicy must be provided.")
		}

		// Fast path for policy determination
		var policyErr error
		if p.Policy != nil || p.ConnPolicy != nil {
			if p.Policy != nil {
				proxyHeaderPolicy, policyErr = p.Policy(conn.RemoteAddr())
			} else {
				proxyHeaderPolicy, policyErr = p.ConnPolicy(ConnPolicyOptions{
					Upstream:   conn.RemoteAddr(),
					Downstream: conn.LocalAddr(),
				})
			}

			if policyErr != nil {
				// can't decide the policy, we can't accept the connection
				conn.Close()

				if errors.Is(policyErr, ErrInvalidUpstream) {
					// keep listening for other connections
					continue
				}

				return nil, policyErr
			}

			// Handle a connection as a regular one - fast path return
			if proxyHeaderPolicy == SKIP {
				return conn, nil
			}
		}

		// Create a new connection with our optimized reader
		newConn := NewConn(
			conn,
			WithPolicy(proxyHeaderPolicy),
			ValidateHeader(p.ValidateHeader),
		)

		// If the ReadHeaderTimeout for the listener is unset, use the default timeout.
		// This avoids a time.Duration comparison which can be expensive
		readHeaderTimeout := p.ReadHeaderTimeout
		if readHeaderTimeout == 0 {
			readHeaderTimeout = DefaultReadHeaderTimeout
		}

		// Set the readHeaderTimeout of the new conn to the value of the listener
		newConn.readHeaderTimeout = readHeaderTimeout

		return newConn, nil
	}
}

// Close closes the underlying listener.
func (p *Listener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *Listener) Addr() net.Addr {
	return p.Listener.Addr()
}

// InitConn applies performance optimizations to a TCP connection based on platform
// Uses platform-specific settings for maximum performance
func InitConn(conn net.Conn) {
	// Delegate to our architecture-specific optimization function
	OptimizeConn(conn)
}

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewConn(conn net.Conn, opts ...func(*Conn)) *Conn {
	// Apply platform-specific optimizations to the connection
	InitConn(conn)

	// Use reader from pool instead of creating a new one
	br := getReader(conn)

	pConn := &Conn{
		bufReader: br,
		reader:    io.MultiReader(br, conn),
		conn:      conn,
	}

	for _, opt := range opts {
		opt(pConn)
	}

	return pConn
}

// Read checks for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (p *Conn) Read(b []byte) (int, error) {
	p.once.Do(func() {
		p.readErr = p.readHeader()

		// After reading the header, optimize the reader setup for zero-copy
		if p.readErr == nil && p.bufReader != nil {
			// If there's no error and no data left in the buffer reader,
			// we can bypass the MultiReader entirely and read directly from conn
			if p.bufReader.Buffered() == 0 {
				// Replace reader with direct conn for zero-copy reads
				p.reader = p.conn
			}
		}
	})

	if p.readErr != nil {
		return 0, p.readErr
	}

	// Forward to the optimized reader
	return p.reader.Read(b)
}

// Write wraps original conn.Write with optimizations for large writes
func (p *Conn) Write(b []byte) (int, error) {
	// Fast path for small writes
	if len(b) < 4096 {
		return p.conn.Write(b)
	}

	// For larger writes, try to use more efficient methods based on concrete type
	switch c := p.conn.(type) {
	case *net.TCPConn:
		// On Linux/Unix, large writes to TCP are optimized by the OS
		return c.Write(b)
	default:
		// Fall back to standard Write for other connection types
		return p.conn.Write(b)
	}
}

// Close wraps original conn.Close
func (p *Conn) Close() error {
	// Return the bufio.Reader to the pool if it exists
	if p.bufReader != nil {
		putReader(p.bufReader)
		p.bufReader = nil
	}

	// Clear references to help with garbage collection
	p.reader = nil

	// Close the underlying connection
	return p.conn.Close()
}

// ProxyHeader returns the proxy protocol header, if any. If an error occurs
// while reading the proxy header, nil is returned.
func (p *Conn) ProxyHeader() *Header {
	p.once.Do(func() { p.readErr = p.readHeader() })
	return p.header
}

// LocalAddr returns the address of the server if the proxy
// protocol is being used, otherwise just returns the address of
// the socket server. In case an error happens on reading the
// proxy header the original LocalAddr is returned, not the one
// from the proxy header even if the proxy header itself is
// syntactically correct.
func (p *Conn) LocalAddr() net.Addr {
	p.once.Do(func() { p.readErr = p.readHeader() })
	if p.header == nil || p.header.Command.IsLocal() || p.readErr != nil {
		return p.conn.LocalAddr()
	}

	return p.header.DestinationAddr
}

// RemoteAddr returns the address of the client if the proxy
// protocol is being used, otherwise just returns the address of
// the socket peer. In case an error happens on reading the
// proxy header the original RemoteAddr is returned, not the one
// from the proxy header even if the proxy header itself is
// syntactically correct.
func (p *Conn) RemoteAddr() net.Addr {
	p.once.Do(func() { p.readErr = p.readHeader() })
	if p.header == nil || p.header.Command.IsLocal() || p.readErr != nil {
		return p.conn.RemoteAddr()
	}

	return p.header.SourceAddr
}

// Raw returns the underlying connection which can be casted to
// a concrete type, allowing access to specialized functions.
//
// Use this ONLY if you know exactly what you are doing.
func (p *Conn) Raw() net.Conn {
	return p.conn
}

// TCPConn returns the underlying TCP connection,
// allowing access to specialized functions.
//
// Use this ONLY if you know exactly what you are doing.
func (p *Conn) TCPConn() (conn *net.TCPConn, ok bool) {
	conn, ok = p.conn.(*net.TCPConn)
	return
}

// UnixConn returns the underlying Unix socket connection,
// allowing access to specialized functions.
//
// Use this ONLY if you know exactly what you are doing.
func (p *Conn) UnixConn() (conn *net.UnixConn, ok bool) {
	conn, ok = p.conn.(*net.UnixConn)
	return
}

// UDPConn returns the underlying UDP connection,
// allowing access to specialized functions.
//
// Use this ONLY if you know exactly what you are doing.
func (p *Conn) UDPConn() (conn *net.UDPConn, ok bool) {
	conn, ok = p.conn.(*net.UDPConn)
	return
}

// SetDeadline wraps original conn.SetDeadline
func (p *Conn) SetDeadline(t time.Time) error {
	p.readDeadline.Store(t)
	return p.conn.SetDeadline(t)
}

// SetReadDeadline wraps original conn.SetReadDeadline
func (p *Conn) SetReadDeadline(t time.Time) error {
	// Set a local var that tells us the desired deadline. This is
	// needed in order to reset the read deadline to the one that is
	// desired by the user, rather than an empty deadline.
	p.readDeadline.Store(t)
	return p.conn.SetReadDeadline(t)
}

// SetWriteDeadline wraps original conn.SetWriteDeadline
func (p *Conn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

func (p *Conn) readHeader() error {
	// Fast path: if no readHeaderTimeout is set, avoid time.Now() and SetReadDeadline call
	var origDeadline time.Time

	if p.readHeaderTimeout > 0 {
		// Store the original deadline value to restore it later
		storedDeadline := p.readDeadline.Load()
		if storedDeadline != nil {
			origDeadline = storedDeadline.(time.Time)
		}

		// Set temporary deadline for header read
		newDeadline := time.Now().Add(p.readHeaderTimeout)
		if err := p.conn.SetReadDeadline(newDeadline); err != nil {
			return err
		}
	}

	header, err := Read(p.bufReader)

	// Always reset the deadline if we've changed it
	if p.readHeaderTimeout > 0 {
		// Restore original deadline, ignoring errors since we can't do much about them
		p.conn.SetReadDeadline(origDeadline)

		// If we got a timeout error, translate it to ErrNoProxyProtocol for consistent handling
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			err = ErrNoProxyProtocol
		}
	}

	// Handle ErrNoProxyProtocol - act as if there was no error when proxy protocol is not required
	if err == ErrNoProxyProtocol {
		// Unless we're in REQUIRE mode, in which case it's an error
		if p.ProxyHeaderPolicy == REQUIRE {
			return err
		}
		return nil
	}

	// Process a successfully read header
	if err == nil && header != nil {
		switch p.ProxyHeaderPolicy {
		case REJECT:
			return ErrSuperfluousProxyHeader
		case USE, REQUIRE:
			if p.Validate != nil {
				if validateErr := p.Validate(header); validateErr != nil {
					return validateErr
				}
			}
			p.header = header
		}
	}

	return err
}
