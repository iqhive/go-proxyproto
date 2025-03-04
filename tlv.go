// Type-Length-Value splitting and parsing for proxy protocol V2
// See spec https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt sections 2.2 to 2.7 and

package proxyproto

import (
	"errors"
	"fmt"
	"math"
)

const (
	// Section 2.2
	PP2_TYPE_ALPN           PP2Type = 0x01
	PP2_TYPE_AUTHORITY      PP2Type = 0x02
	PP2_TYPE_CRC32C         PP2Type = 0x03
	PP2_TYPE_NOOP           PP2Type = 0x04
	PP2_TYPE_UNIQUE_ID      PP2Type = 0x05
	PP2_TYPE_SSL            PP2Type = 0x20
	PP2_SUBTYPE_SSL_VERSION PP2Type = 0x21
	PP2_SUBTYPE_SSL_CN      PP2Type = 0x22
	PP2_SUBTYPE_SSL_CIPHER  PP2Type = 0x23
	PP2_SUBTYPE_SSL_SIG_ALG PP2Type = 0x24
	PP2_SUBTYPE_SSL_KEY_ALG PP2Type = 0x25
	PP2_TYPE_NETNS          PP2Type = 0x30

	// Section 2.2.7, reserved types
	PP2_TYPE_MIN_CUSTOM     PP2Type = 0xE0
	PP2_TYPE_MAX_CUSTOM     PP2Type = 0xEF
	PP2_TYPE_MIN_EXPERIMENT PP2Type = 0xF0
	PP2_TYPE_MAX_EXPERIMENT PP2Type = 0xF7
	PP2_TYPE_MIN_FUTURE     PP2Type = 0xF8
	PP2_TYPE_MAX_FUTURE     PP2Type = 0xFF
)

var (
	ErrTruncatedTLV    = errors.New("proxyproto: truncated TLV")
	ErrMalformedTLV    = errors.New("proxyproto: malformed TLV Value")
	ErrIncompatibleTLV = errors.New("proxyproto: incompatible TLV type")
)

// PP2Type is the proxy protocol v2 type
type PP2Type byte

// TLV is a uninterpreted Type-Length-Value for V2 protocol, see section 2.2
type TLV struct {
	Type  PP2Type
	Value []byte
}

// SplitTLVs splits the Type-Length-Value vector with minimal copying.
func SplitTLVs(raw []byte) ([]TLV, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	// Pre-allocate with a reasonable size to avoid reallocations
	tlvs := make([]TLV, 0, 4)

	// Process the byte slice directly without intermediate allocations
	for i := 0; i < len(raw); {
		// Ensure we have at least 3 bytes (type + 2-byte length)
		if len(raw)-i < 3 {
			return nil, ErrTruncatedTLV
		}

		// Read type byte directly
		tlvType := PP2Type(raw[i])
		i++

		// Read length directly (big endian)
		tlvLen := (int(raw[i]) << 8) | int(raw[i+1])
		i += 2

		// Check if we have enough bytes for the value
		if i+tlvLen > len(raw) {
			return nil, ErrTruncatedTLV
		}

		// Process the value
		if tlvType != PP2_TYPE_NOOP {
			var tlvValue []byte

			// For small values, make a copy to avoid referencing the larger raw buffer
			if tlvLen <= 16 {
				tlvValue = make([]byte, tlvLen)
				copy(tlvValue, raw[i:i+tlvLen])
			} else {
				// For larger values, use a slice of the original to avoid copying
				// This is safe as long as the original raw slice stays in scope
				tlvValue = raw[i : i+tlvLen]
			}

			tlvs = append(tlvs, TLV{
				Type:  tlvType,
				Value: tlvValue,
			})
		}

		// Move to the next TLV
		i += tlvLen
	}

	return tlvs, nil
}

// JoinTLVs joins multiple Type-Length-Value records with minimal copying.
func JoinTLVs(tlvs []TLV) ([]byte, error) {
	if len(tlvs) == 0 {
		return nil, nil
	}

	// Pre-calculate total size to avoid reallocations
	totalSize := 0
	for _, tlv := range tlvs {
		if len(tlv.Value) > math.MaxUint16 {
			return nil, fmt.Errorf("proxyproto: cannot format TLV %v with length %d", tlv.Type, len(tlv.Value))
		}
		totalSize += 3 + len(tlv.Value) // 1 byte for type, 2 bytes for length, n bytes for value
	}

	// Early return for empty result
	if totalSize == 0 {
		return nil, nil
	}

	// Allocate exactly the size needed in one go
	raw := make([]byte, totalSize)

	// Fill the buffer directly without intermediate allocations
	offset := 0
	for _, tlv := range tlvs {
		valueLen := len(tlv.Value)

		// Write type byte
		raw[offset] = byte(tlv.Type)
		offset++

		// Write length (big endian)
		raw[offset] = byte(valueLen >> 8) // high byte
		raw[offset+1] = byte(valueLen)    // low byte
		offset += 2

		// Copy value directly into destination buffer
		if valueLen > 0 {
			copy(raw[offset:offset+valueLen], tlv.Value)
			offset += valueLen
		}
	}

	return raw, nil
}

// Registered is true if the type is registered in the spec, see section 2.2
func (p PP2Type) Registered() bool {
	switch p {
	case PP2_TYPE_ALPN,
		PP2_TYPE_AUTHORITY,
		PP2_TYPE_CRC32C,
		PP2_TYPE_NOOP,
		PP2_TYPE_UNIQUE_ID,
		PP2_TYPE_SSL,
		PP2_SUBTYPE_SSL_VERSION,
		PP2_SUBTYPE_SSL_CN,
		PP2_SUBTYPE_SSL_CIPHER,
		PP2_SUBTYPE_SSL_SIG_ALG,
		PP2_SUBTYPE_SSL_KEY_ALG,
		PP2_TYPE_NETNS:
		return true
	}
	return false
}

// App is true if the type is reserved for application specific data, see section 2.2.7
func (p PP2Type) App() bool {
	return p >= PP2_TYPE_MIN_CUSTOM && p <= PP2_TYPE_MAX_CUSTOM
}

// Experiment is true if the type is reserved for temporary experimental use by application developers, see section 2.2.7
func (p PP2Type) Experiment() bool {
	return p >= PP2_TYPE_MIN_EXPERIMENT && p <= PP2_TYPE_MAX_EXPERIMENT
}

// Future is true is the type is reserved for future use, see section 2.2.7
func (p PP2Type) Future() bool {
	return p >= PP2_TYPE_MIN_FUTURE
}

// Spec is true if the type is covered by the spec, see section 2.2 and 2.2.7
func (p PP2Type) Spec() bool {
	return p.Registered() || p.App() || p.Experiment() || p.Future()
}
