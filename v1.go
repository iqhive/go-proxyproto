package proxyproto

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	crlf      = "\r\n"
	separator = " "
)

func initVersion1() *Header {
	header := new(Header)
	header.Version = 1
	// Command doesn't exist in v1
	header.Command = PROXY
	return header
}

func parseVersion1(reader *bufio.Reader) (*Header, error) {
	//The header cannot be more than 107 bytes long. Per spec:
	//
	//   (...)
	//   - worst case (optional fields set to 0xff) :
	//     "PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
	//     => 5 + 1 + 7 + 1 + 39 + 1 + 39 + 1 + 5 + 1 + 5 + 2 = 107 chars
	//
	//   So a 108-byte buffer is always enough to store all the line and a
	//   trailing zero for string processing.
	//
	//   It must also be CRLF terminated, as above. The header does not otherwise
	//   contain a CR or LF byte.

	// Get a buffer from the pool
	bufPtr := getBuffer()
	buf := *bufPtr

	defer putBuffer(bufPtr) // Return the buffer to the pool when done

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, fmt.Errorf(ErrCantReadVersion1Header.Error()+": %v", err)
		}
		buf = append(buf, b)
		if b == '\n' {
			// End of header found
			break
		}
		if len(buf) == 107 {
			// No delimiter in first 107 bytes
			return nil, ErrVersion1HeaderTooLong
		}
		if reader.Buffered() == 0 {
			// Header was not buffered in a single read. Since we can't
			// differentiate between genuine slow writers and DoS agents,
			// we abort. On healthy networks, this should never happen.
			return nil, ErrCantReadVersion1Header
		}
	}

	// Update the buffer in the pool pointer
	*bufPtr = buf

	// Check for CR before LF.
	if len(buf) < 2 || buf[len(buf)-2] != '\r' {
		return nil, ErrLineMustEndWithCrlf
	}

	// Note: Using string() here allocates, but seems unavoidable due to Split
	// We could manually parse the string to avoid Split if needed for more performance
	tokens := strings.Split(string(buf[:len(buf)-2]), separator)

	// Expect at least 2 tokens: "PROXY" and the transport protocol.
	if len(tokens) < 2 {
		return nil, ErrCantReadAddressFamilyAndProtocol
	}

	// Read address family and protocol
	var transportProtocol AddressFamilyAndProtocol
	switch tokens[1] {
	case "TCP4":
		transportProtocol = TCPv4
	case "TCP6":
		transportProtocol = TCPv6
	case "UNKNOWN":
		transportProtocol = UNSPEC // doesn't exist in v1 but fits UNKNOWN
	default:
		return nil, ErrCantReadAddressFamilyAndProtocol
	}

	// Expect 6 tokens only when UNKNOWN is not present.
	if transportProtocol != UNSPEC && len(tokens) < 6 {
		return nil, ErrCantReadAddressFamilyAndProtocol
	}

	// When a signature is found, allocate a v1 header with Command set to PROXY.
	// Command doesn't exist in v1 but set it for other parts of this library
	// to rely on it for determining connection details.
	header := initVersion1()

	// Transport protocol has been processed already.
	header.TransportProtocol = transportProtocol

	// When UNKNOWN, set the command to LOCAL and return early
	if header.TransportProtocol == UNSPEC {
		header.Command = LOCAL
		return header, nil
	}

	// Otherwise, continue to read addresses and ports
	sourceIP, err := parseV1IPAddress(header.TransportProtocol, tokens[2])
	if err != nil {
		return nil, err
	}
	destIP, err := parseV1IPAddress(header.TransportProtocol, tokens[3])
	if err != nil {
		return nil, err
	}
	sourcePort, err := parseV1PortNumber(tokens[4])
	if err != nil {
		return nil, err
	}
	destPort, err := parseV1PortNumber(tokens[5])
	if err != nil {
		return nil, err
	}
	header.SourceAddr = &net.TCPAddr{
		IP:   sourceIP,
		Port: sourcePort,
	}
	header.DestinationAddr = &net.TCPAddr{
		IP:   destIP,
		Port: destPort,
	}

	return header, nil
}

func (header *Header) formatVersion1() ([]byte, error) {
	// For unknown connections (short form), just return a static byte slice
	if header.TransportProtocol != TCPv4 && header.TransportProtocol != TCPv6 {
		// Use pre-allocated static slice
		result := make([]byte, 15) // "PROXY UNKNOWN\r\n"
		copy(result, "PROXY UNKNOWN\r\n")
		return result, nil
	}

	// Validate addresses
	sourceAddr, sourceOK := header.SourceAddr.(*net.TCPAddr)
	destAddr, destOK := header.DestinationAddr.(*net.TCPAddr)
	if !sourceOK || !destOK {
		return nil, ErrInvalidAddress
	}

	// Get IPs in the right format
	sourceIP, destIP := sourceAddr.IP, destAddr.IP
	switch header.TransportProtocol {
	case TCPv4:
		sourceIP = sourceIP.To4()
		destIP = destIP.To4()
	case TCPv6:
		sourceIP = sourceIP.To16()
		destIP = destIP.To16()
	}

	if sourceIP == nil || destIP == nil {
		return nil, ErrInvalidAddress
	}

	// Pre-calculate the exact buffer size we need
	// "PROXY TCP4 " or "PROXY TCP6 " = 11 bytes
	// source IP + " " = len(sourceIP.String()) + 1
	// dest IP + " " = len(destIP.String()) + 1
	// source port + " " = len(strconv.Itoa(sourceAddr.Port)) + 1
	// dest port + "\r\n" = len(strconv.Itoa(destAddr.Port)) + 2
	sourceIPStr := sourceIP.String()
	destIPStr := destIP.String()
	sourcePortStr := strconv.Itoa(sourceAddr.Port)
	destPortStr := strconv.Itoa(destAddr.Port)

	totalLen := 11 + len(sourceIPStr) + 1 + len(destIPStr) + 1 +
		len(sourcePortStr) + 1 + len(destPortStr) + 2

	// Allocate the exact buffer size we need
	buf := make([]byte, 0, totalLen)

	// Build the header directly using append to avoid temporary allocations
	buf = append(buf, SIGV1...)
	buf = append(buf, separator...)

	if header.TransportProtocol == TCPv4 {
		buf = append(buf, "TCP4"...)
	} else {
		buf = append(buf, "TCP6"...)
	}

	buf = append(buf, separator...)
	buf = append(buf, sourceIPStr...)
	buf = append(buf, separator...)
	buf = append(buf, destIPStr...)
	buf = append(buf, separator...)
	buf = append(buf, sourcePortStr...)
	buf = append(buf, separator...)
	buf = append(buf, destPortStr...)
	buf = append(buf, crlf...)

	return buf, nil
}

func parseV1PortNumber(portStr string) (int, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return 0, ErrInvalidPortNumber
	}
	return port, nil
}

func parseV1IPAddress(protocol AddressFamilyAndProtocol, addrStr string) (net.IP, error) {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return nil, ErrInvalidAddress
	}

	switch protocol {
	case TCPv4:
		if addr.Is4() {
			return net.IP(addr.AsSlice()), nil
		}
	case TCPv6:
		if addr.Is6() || addr.Is4In6() {
			return net.IP(addr.AsSlice()), nil
		}
	}

	return nil, ErrInvalidAddress
}
