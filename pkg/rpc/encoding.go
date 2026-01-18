package rpc

import (
	"encoding/base64"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
	"github.com/mr-tron/base58"
)

// Encoding types supported by Solana RPC
const (
	EncodingBase58      = "base58"
	EncodingBase64      = "base64"
	EncodingBase64Zstd  = "base64+zstd"
	EncodingJSONParsed  = "jsonParsed"
)

// EncodeBase58 encodes bytes to base58 string.
func EncodeBase58(data []byte) string {
	return base58.Encode(data)
}

// DecodeBase58 decodes a base58 string to bytes.
func DecodeBase58(s string) ([]byte, error) {
	return base58.Decode(s)
}

// EncodeBase64 encodes bytes to base64 string.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes a base64 string to bytes.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// EncodePubkey encodes a pubkey to base58 string.
func EncodePubkey(pk types.Pubkey) string {
	return pk.String()
}

// DecodePubkey decodes a base58 string to pubkey.
func DecodePubkey(s string) (types.Pubkey, error) {
	return types.PubkeyFromBase58(s)
}

// EncodeSignature encodes a signature to base58 string.
func EncodeSignature(sig types.Signature) string {
	return sig.String()
}

// DecodeSignature decodes a base58 string to signature.
func DecodeSignature(s string) (types.Signature, error) {
	return types.SignatureFromBase58(s)
}

// EncodeHash encodes a hash to base58 string.
func EncodeHash(h types.Hash) string {
	return h.String()
}

// DecodeHash decodes a base58 string to hash.
func DecodeHash(s string) (types.Hash, error) {
	return types.HashFromBase58(s)
}

// EncodeAccountData encodes account data in the specified encoding.
// Returns a tuple of [data, encoding] for Solana compatibility.
func EncodeAccountData(data []byte, encoding string) ([]interface{}, error) {
	switch encoding {
	case EncodingBase58:
		// Base58 is only valid for small amounts of data
		if len(data) > 128 {
			return nil, fmt.Errorf("data too large for base58 encoding, use base64")
		}
		return []interface{}{EncodeBase58(data), EncodingBase58}, nil

	case EncodingBase64, "":
		// Base64 is the default
		return []interface{}{EncodeBase64(data), EncodingBase64}, nil

	case EncodingBase64Zstd:
		// TODO: Implement zstd compression
		// For now, fall back to base64
		return []interface{}{EncodeBase64(data), EncodingBase64}, nil

	case EncodingJSONParsed:
		// jsonParsed returns raw data if parsing is not supported
		return []interface{}{EncodeBase64(data), EncodingBase64}, nil

	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// DecodeAccountData decodes account data from the specified encoding.
func DecodeAccountData(encoded string, encoding string) ([]byte, error) {
	switch encoding {
	case EncodingBase58:
		return DecodeBase58(encoded)

	case EncodingBase64, "":
		return DecodeBase64(encoded)

	case EncodingBase64Zstd:
		// TODO: Implement zstd decompression
		return nil, fmt.Errorf("base64+zstd decoding not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// ValidateEncoding validates that an encoding string is supported.
func ValidateEncoding(encoding string) error {
	switch encoding {
	case EncodingBase58, EncodingBase64, EncodingBase64Zstd, EncodingJSONParsed, "":
		return nil
	default:
		return fmt.Errorf("unsupported encoding: %s", encoding)
	}
}

// SliceData returns a slice of data based on offset and length.
// Returns the full data if slice is nil.
func SliceData(data []byte, slice *DataSlice) []byte {
	if slice == nil {
		return data
	}

	dataLen := uint64(len(data))

	// Handle offset beyond data length
	if slice.Offset >= dataLen {
		return []byte{}
	}

	// Calculate end position
	end := slice.Offset + slice.Length
	if end > dataLen {
		end = dataLen
	}

	return data[slice.Offset:end]
}

// FormatLamports formats lamports as a string with proper precision.
func FormatLamports(lamports types.Lamports) string {
	return fmt.Sprintf("%d", lamports)
}

// ParseLamports parses a lamports amount from a string or number.
func ParseLamports(v interface{}) (types.Lamports, error) {
	switch val := v.(type) {
	case float64:
		return types.Lamports(val), nil
	case int64:
		return types.Lamports(val), nil
	case uint64:
		return types.Lamports(val), nil
	case string:
		var l uint64
		_, err := fmt.Sscanf(val, "%d", &l)
		if err != nil {
			return 0, fmt.Errorf("invalid lamports value: %s", val)
		}
		return types.Lamports(l), nil
	default:
		return 0, fmt.Errorf("invalid lamports type: %T", v)
	}
}
