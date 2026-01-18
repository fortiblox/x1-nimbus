// Package poh provides Proof of History verification for X1-Nimbus.
package poh

import "errors"

// Error types for PoH verification.
var (
	// ErrHashMismatch indicates that an entry hash doesn't match the expected computed hash.
	ErrHashMismatch = errors.New("poh: entry hash does not match expected hash")

	// ErrInvalidNumHashes indicates that the number of hashes in an entry is invalid.
	ErrInvalidNumHashes = errors.New("poh: invalid number of hashes (must be > 0)")

	// ErrInvalidEntry indicates that an entry is malformed or invalid.
	ErrInvalidEntry = errors.New("poh: malformed or invalid entry")
)
