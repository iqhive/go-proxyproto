package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"unsafe"
)

var (
	lengthUnspec      = uint16(0)
	lengthV4          = uint16(12)
	lengthV6          = uint16(36)
	lengthUnix        = uint16(216)
	lengthUnspecBytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, lengthUnspec)
		return a
	}()
	lengthV4Bytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, lengthV4)
		return a
	}()
	lengthV6Bytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, lengthV6)
		return a
	}()
	lengthUnixBytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, lengthUnix)
		return a
	}()
	errUint16Overflow = errors.New("proxyproto: uint16 overflow")

	// Pre-allocate port byte buffer to avoid allocations
	portBytesPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 2)
			return &b
		},
	}

	// unixAddrPool is a pool for Unix address formatting
	unixAddrPool = sync.Pool{
		New: func() interface{} {
			// Unix addresses can be up to 108 bytes
			b := make([]byte, 108)
			return &b
		},
	}

	// tlvLenPool is a pool for TLV length buffers
	tlvLenPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 2)
			return &b
		},
	}
)

// getUnixAddrBuffer gets a buffer from the pool for Unix addresses
func getUnixAddrBuffer() *[]byte {
	return unixAddrPool.Get().(*[]byte)
}

// putUnixAddrBuffer returns a buffer to the pool
func putUnixAddrBuffer(b *[]byte) {
	// Clear the buffer for security
	for i := range *b {
		(*b)[i] = 0
	}
	unixAddrPool.Put(b)
}

type _ports struct {
	SrcPort uint16
	DstPort uint16
}

type _addr4 struct {
	Src     [4]byte
	Dst     [4]byte
	SrcPort uint16
	DstPort uint16
}

type _addr6 struct {
	Src [16]byte
	Dst [16]byte
	_ports
}

type _addrUnix struct {
	Src [108]byte
	Dst [108]byte
}

func parseVersion2(reader *bufio.Reader) (header *Header, err error) {
	// Skip first 12 bytes (signature)
	for i := 0; i < 12; i++ {
		if _, err = reader.ReadByte(); err != nil {
			return nil, ErrCantReadProtocolVersionAndCommand
		}
	}

	header = new(Header)
	header.Version = 2

	// Read the 13th byte, protocol version and command
	b13, err := reader.ReadByte()
	if err != nil {
		return nil, ErrCantReadProtocolVersionAndCommand
	}
	header.Command = ProtocolVersionAndCommand(b13)
	if _, ok := supportedCommand[header.Command]; !ok {
		return nil, ErrUnsupportedProtocolVersionAndCommand
	}

	// Read the 14th byte, address family and protocol
	b14, err := reader.ReadByte()
	if err != nil {
		return nil, ErrCantReadAddressFamilyAndProtocol
	}
	header.TransportProtocol = AddressFamilyAndProtocol(b14)
	// UNSPEC is only supported when LOCAL is set.
	if header.TransportProtocol == UNSPEC && header.Command != LOCAL {
		return nil, ErrUnsupportedAddressFamilyAndProtocol
	}

	// Make sure there are bytes available as specified in length
	var length uint16
	// Use a fixed buffer to avoid allocation
	lengthBytes := [2]byte{}
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return nil, ErrCantReadLength
	}
	length = binary.BigEndian.Uint16(lengthBytes[:])

	if !header.validateLength(length) {
		return nil, ErrInvalidLength
	}

	// Return early if the length is zero, which means that
	// there's no address information and TLVs present for UNSPEC.
	if length == 0 {
		return header, nil
	}

	if _, err := reader.Peek(int(length)); err != nil {
		return nil, ErrInvalidLength
	}

	// Length-limited reader for payload section
	payloadReader := io.LimitReader(reader, int64(length)).(*io.LimitedReader)

	// Read addresses and ports for protocols other than UNSPEC.
	// Ignore address information for UNSPEC, and skip straight to read TLVs,
	// since the length is greater than zero.
	if header.TransportProtocol != UNSPEC {
		if header.TransportProtocol.IsIPv4() {
			var addr _addr4
			if err := binary.Read(payloadReader, binary.BigEndian, &addr); err != nil {
				return nil, ErrInvalidAddress
			}
			header.SourceAddr = newIPAddr(header.TransportProtocol, addr.Src[:], addr.SrcPort)
			header.DestinationAddr = newIPAddr(header.TransportProtocol, addr.Dst[:], addr.DstPort)
		} else if header.TransportProtocol.IsIPv6() {
			var addr _addr6
			if err := binary.Read(payloadReader, binary.BigEndian, &addr); err != nil {
				return nil, ErrInvalidAddress
			}
			header.SourceAddr = newIPAddr(header.TransportProtocol, addr.Src[:], addr.SrcPort)
			header.DestinationAddr = newIPAddr(header.TransportProtocol, addr.Dst[:], addr.DstPort)
		} else if header.TransportProtocol.IsUnix() {
			var addr _addrUnix
			if err := binary.Read(payloadReader, binary.BigEndian, &addr); err != nil {
				return nil, ErrInvalidAddress
			}

			network := "unix"
			if header.TransportProtocol.IsDatagram() {
				network = "unixgram"
			}

			header.SourceAddr = &net.UnixAddr{
				Net:  network,
				Name: parseUnixName(addr.Src[:]),
			}
			header.DestinationAddr = &net.UnixAddr{
				Net:  network,
				Name: parseUnixName(addr.Dst[:]),
			}
		}
	}

	// Copy bytes for optional Type-Length-Value vector
	remainingLength := int(payloadReader.N)
	if remainingLength > 0 {
		header.rawTLVs = make([]byte, remainingLength)
		if _, err = io.ReadFull(payloadReader, header.rawTLVs); err != nil && err != io.EOF {
			return nil, err
		}
	}

	return header, nil
}

// formatVersion2 serializes a proxy protocol version 2 header
// This optimized version minimizes copying and reuses buffers
func (header *Header) formatVersion2() ([]byte, error) {
	// Pre-calculate the total buffer size to avoid reallocations
	totalSize := len(SIGV2) + 2 // Signature + command/protocol bytes

	// Add base length for the appropriate protocol
	if header.TransportProtocol.IsIPv4() {
		totalSize += 2 + int(lengthV4) // 2 for length field
	} else if header.TransportProtocol.IsIPv6() {
		totalSize += 2 + int(lengthV6) // 2 for length field
	} else if header.TransportProtocol.IsUnix() {
		totalSize += 2 + int(lengthUnix) // 2 for length field
	} else {
		totalSize += 2 // Just the length field for UNSPEC
	}

	// Add TLV size if present
	totalSize += len(header.rawTLVs)

	// Allocate a single buffer of the right size
	result := make([]byte, 0, totalSize)

	// Append signature (no allocation)
	result = append(result, SIGV2...)
	result = append(result, header.Command.toByte())
	result = append(result, header.TransportProtocol.toByte())

	// Add appropriate length field and address data
	if header.TransportProtocol.IsIPv4() {
		// Use the pre-calculated IPv4 length
		baseLength := lengthV4
		sourceIP, destIP, _ := header.IPs()
		addrSrc := sourceIP.To4()
		addrDst := destIP.To4()

		// Calculate final length including TLVs
		totalLength := baseLength
		if len(header.rawTLVs) > 0 {
			newLength := int(totalLength) + len(header.rawTLVs)
			if newLength > math.MaxUint16 {
				return nil, errUint16Overflow
			}
			totalLength = uint16(newLength)
		}

		// Write length directly into result buffer
		lengthBytes := [2]byte{}
		binary.BigEndian.PutUint16(lengthBytes[:], totalLength)
		result = append(result, lengthBytes[:]...)

		// Validate addresses
		if addrSrc == nil || addrDst == nil {
			return nil, ErrInvalidAddress
		}

		// Append address data (no allocation)
		result = append(result, addrSrc...)
		result = append(result, addrDst...)

		// Add port information if available
		if sourcePort, destPort, ok := header.Ports(); ok {
			// Write ports directly into result buffer
			portBytes := [2]byte{}

			binary.BigEndian.PutUint16(portBytes[:], uint16(sourcePort))
			result = append(result, portBytes[:]...)

			binary.BigEndian.PutUint16(portBytes[:], uint16(destPort))
			result = append(result, portBytes[:]...)
		}
	} else if header.TransportProtocol.IsIPv6() {
		// Use the pre-calculated IPv6 length
		baseLength := lengthV6
		sourceIP, destIP, _ := header.IPs()
		addrSrc := sourceIP.To16()
		addrDst := destIP.To16()

		// Calculate final length including TLVs
		totalLength := baseLength
		if len(header.rawTLVs) > 0 {
			newLength := int(totalLength) + len(header.rawTLVs)
			if newLength > math.MaxUint16 {
				return nil, errUint16Overflow
			}
			totalLength = uint16(newLength)
		}

		// Write length directly into result buffer
		lengthBytes := [2]byte{}
		binary.BigEndian.PutUint16(lengthBytes[:], totalLength)
		result = append(result, lengthBytes[:]...)

		// Validate addresses
		if addrSrc == nil || addrDst == nil {
			return nil, ErrInvalidAddress
		}

		// Append address data (no allocation)
		result = append(result, addrSrc...)
		result = append(result, addrDst...)

		// Add port information if available
		if sourcePort, destPort, ok := header.Ports(); ok {
			// Write ports directly into result buffer
			portBytes := [2]byte{}

			binary.BigEndian.PutUint16(portBytes[:], uint16(sourcePort))
			result = append(result, portBytes[:]...)

			binary.BigEndian.PutUint16(portBytes[:], uint16(destPort))
			result = append(result, portBytes[:]...)
		}
	} else if header.TransportProtocol.IsUnix() {
		// Use the pre-calculated Unix length
		baseLength := lengthUnix
		sourceAddr, destAddr, ok := header.UnixAddrs()
		if !ok {
			return nil, ErrInvalidAddress
		}

		// Use optimized Unix name formatting
		addrSrc := formatUnixNameZeroCopy(sourceAddr.Name)
		addrDst := formatUnixNameZeroCopy(destAddr.Name)

		// These are fully copied values, so we'll need to free them
		defer func() {
			if addrSrc != nil {
				putUnixAddrSlice(addrSrc)
			}
			if addrDst != nil {
				putUnixAddrSlice(addrDst)
			}
		}()

		// Calculate final length including TLVs
		totalLength := baseLength
		if len(header.rawTLVs) > 0 {
			newLength := int(totalLength) + len(header.rawTLVs)
			if newLength > math.MaxUint16 {
				return nil, errUint16Overflow
			}
			totalLength = uint16(newLength)
		}

		// Write length directly into result buffer
		lengthBytes := [2]byte{}
		binary.BigEndian.PutUint16(lengthBytes[:], totalLength)
		result = append(result, lengthBytes[:]...)

		// Validate addresses
		if addrSrc == nil || addrDst == nil {
			return nil, ErrInvalidAddress
		}

		// Append address data (no allocation)
		result = append(result, addrSrc...)
		result = append(result, addrDst...)

		// Add port information if available
		if sourcePort, destPort, ok := header.Ports(); ok {
			// Write ports directly into result buffer
			portBytes := [2]byte{}

			binary.BigEndian.PutUint16(portBytes[:], uint16(sourcePort))
			result = append(result, portBytes[:]...)

			binary.BigEndian.PutUint16(portBytes[:], uint16(destPort))
			result = append(result, portBytes[:]...)
		}
	} else {
		// For UNSPEC, calculate final length with TLVs
		length := uint16(0)
		if len(header.rawTLVs) > 0 {
			length = uint16(len(header.rawTLVs))
			if length > math.MaxUint16 {
				return nil, errUint16Overflow
			}
		}

		// Write length directly into result buffer
		lengthBytes := [2]byte{}
		binary.BigEndian.PutUint16(lengthBytes[:], length)
		result = append(result, lengthBytes[:]...)
	}

	// Append TLVs if present (no allocation)
	if len(header.rawTLVs) > 0 {
		result = append(result, header.rawTLVs...)
	}

	return result, nil
}

// formatUnixNameZeroCopy formats a Unix socket path with minimal copying
// Returns a slice that must be returned to the pool with putUnixAddrSlice
func formatUnixNameZeroCopy(name string) []byte {
	// Create a properly-sized slice
	slice := getUnixAddrSlice()

	// Copy the name into the slice
	nameLen := copy(slice, name)

	// Zero-fill the remainder
	for i := nameLen; i < len(slice); i++ {
		slice[i] = 0
	}

	return slice
}

// getUnixAddrSlice gets a pre-allocated slice for Unix socket addresses
func getUnixAddrSlice() []byte {
	bufPtr := getUnixAddrBuffer()
	slice := (*bufPtr)[:108] // Ensure slice is exactly the right size
	return slice
}

// putUnixAddrSlice returns a Unix address slice to the pool
func putUnixAddrSlice(slice []byte) {
	// Find the buffer pointer by calculating its address
	if cap(slice) >= 108 {
		// Convert slice to pointer to underlying array
		bufPtr := &slice[:cap(slice)][0]
		// Convert to *[]byte (this is a bit hacky but avoids allocating a new buffer)
		sliceHeader := (*[]byte)(unsafe.Pointer(&bufPtr))
		// Put it back in the pool
		putUnixAddrBuffer(sliceHeader)
	}
}

func (header *Header) validateLength(length uint16) bool {
	if header.TransportProtocol.IsIPv4() {
		return length >= lengthV4
	} else if header.TransportProtocol.IsIPv6() {
		return length >= lengthV6
	} else if header.TransportProtocol.IsUnix() {
		return length >= lengthUnix
	} else if header.TransportProtocol.IsUnspec() {
		return length >= lengthUnspec
	}
	return false
}

// addTLVLen adds the length of the TLV to the header length or errors on uint16 overflow.
// This optimized version avoids allocations by using a buffer pool.
func addTLVLen(cur []byte, tlvLen int) ([]byte, error) {
	if tlvLen == 0 {
		return cur, nil
	}

	curLen := binary.BigEndian.Uint16(cur)
	newLen := int(curLen) + tlvLen
	if newLen >= 1<<16 {
		return nil, errUint16Overflow
	}

	// Get buffer from pool
	bufPtr := tlvLenPool.Get().(*[]byte)
	buf := *bufPtr

	binary.BigEndian.PutUint16(buf, uint16(newLen))

	// Create a new slice to return - we can't return the pooled buffer directly
	result := make([]byte, 2)
	copy(result, buf)

	// Return buffer to pool
	tlvLenPool.Put(bufPtr)

	return result, nil
}

func newIPAddr(transport AddressFamilyAndProtocol, ip net.IP, port uint16) net.Addr {
	if transport.IsStream() {
		return &net.TCPAddr{IP: ip, Port: int(port)}
	} else if transport.IsDatagram() {
		return &net.UDPAddr{IP: ip, Port: int(port)}
	} else {
		return nil
	}
}

// parseUnixName extracts the null-terminated Unix socket path
func parseUnixName(b []byte) string {
	// Find null terminator
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b)
	}
	return string(b[:i])
}
