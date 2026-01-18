package crypto

import (
	"crypto/sha256"
	"hash"
)

// Hash computes the SHA256 hash of the input data.
// Returns a fixed-size 32-byte array.
func Hash(data []byte) [HashSize]byte {
	return sha256.Sum256(data)
}

// HashMulti computes the SHA256 hash of multiple byte slices concatenated together.
// This is more efficient than concatenating the slices first, as it avoids
// an additional memory allocation.
//
// Example:
//
//	hash := HashMulti(header, body, footer)
func HashMulti(data ...[]byte) [HashSize]byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	var result [HashSize]byte
	copy(result[:], h.Sum(nil))
	return result
}

// Hashv computes the SHA256 hash of a slice of byte slices.
// This is equivalent to Solana's hashv function and is used for
// computing hashes over multiple pieces of data in a deterministic way.
//
// This function is functionally equivalent to HashMulti but takes
// a slice of slices instead of variadic arguments, making it easier
// to use when the data is already in a slice.
//
// Example:
//
//	slices := [][]byte{header, body, footer}
//	hash := Hashv(slices)
func Hashv(slices [][]byte) [HashSize]byte {
	h := sha256.New()
	for _, s := range slices {
		h.Write(s)
	}
	var result [HashSize]byte
	copy(result[:], h.Sum(nil))
	return result
}

// HashToBytes computes the SHA256 hash of the input data and returns
// it as a byte slice. This is a convenience function for cases where
// a slice is needed instead of an array.
func HashToBytes(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HashReader computes the SHA256 hash incrementally.
// This is useful for hashing large amounts of data without loading
// everything into memory at once.
type HashReader struct {
	h hash.Hash
}

// NewHashReader creates a new incremental hash reader.
func NewHashReader() *HashReader {
	return &HashReader{
		h: sha256.New(),
	}
}

// Write adds data to the hash computation.
func (hr *HashReader) Write(data []byte) (int, error) {
	return hr.h.Write(data)
}

// Sum returns the current hash value without resetting.
func (hr *HashReader) Sum() [HashSize]byte {
	var result [HashSize]byte
	copy(result[:], hr.h.Sum(nil))
	return result
}

// Reset resets the hash reader for reuse.
func (hr *HashReader) Reset() {
	hr.h.Reset()
}
