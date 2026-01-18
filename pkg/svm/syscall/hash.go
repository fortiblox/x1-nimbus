package syscall

import (
	"crypto/sha256"

	"github.com/fortiblox/x1-nimbus/pkg/svm/sbpf"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

// SolSHA256 implements the sol_sha256 syscall.
// Computes SHA256 hash of input data slices.
// Arguments:
//   r1: pointer to result (32 bytes output)
//   r2: pointer to array of data slice descriptors
//   r3: number of data slices
//
// Each slice descriptor is 16 bytes:
//   - 8 bytes: pointer to data
//   - 8 bytes: length of data
func SolSHA256(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	resultAddr := r1
	slicesAddr := r2
	numSlices := r3

	// Compute cost
	cost := CUSHA256Base
	if err := vm.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	hasher := sha256.New()
	mem := vm.Memory()

	for i := uint64(0); i < numSlices; i++ {
		// Each slice descriptor is 16 bytes (ptr + len)
		descriptorAddr := slicesAddr + i*16

		// Read pointer (8 bytes)
		dataPtr, err := mem.ReadUint64(descriptorAddr)
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Read length (8 bytes)
		dataLen, err := mem.ReadUint64(descriptorAddr + 8)
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Charge per-byte cost
		if err := vm.ConsumeComputeUnits(dataLen * CUSHA256PerByte); err != nil {
			return SyscallErrorComputeExceeded, err
		}

		// Read actual data
		data, err := vm.ReadMemory(dataPtr, int(dataLen))
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		hasher.Write(data)
	}

	// Write result
	result := hasher.Sum(nil)
	if err := vm.WriteMemory(resultAddr, result); err != nil {
		return SyscallErrorInvalidMemory, err
	}

	return SyscallSuccess, nil
}

// SolKeccak256 implements the sol_keccak256 syscall.
// Computes Keccak256 hash of input data slices.
// Arguments:
//   r1: pointer to result (32 bytes output)
//   r2: pointer to array of data slice descriptors
//   r3: number of data slices
//
// Each slice descriptor is 16 bytes:
//   - 8 bytes: pointer to data
//   - 8 bytes: length of data
func SolKeccak256(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	resultAddr := r1
	slicesAddr := r2
	numSlices := r3

	// Compute cost
	cost := CUKeccak256Base
	if err := vm.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	hasher := sha3.NewLegacyKeccak256()
	mem := vm.Memory()

	for i := uint64(0); i < numSlices; i++ {
		// Each slice descriptor is 16 bytes (ptr + len)
		descriptorAddr := slicesAddr + i*16

		// Read pointer (8 bytes)
		dataPtr, err := mem.ReadUint64(descriptorAddr)
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Read length (8 bytes)
		dataLen, err := mem.ReadUint64(descriptorAddr + 8)
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Charge per-byte cost
		if err := vm.ConsumeComputeUnits(dataLen * CUKeccak256PerByte); err != nil {
			return SyscallErrorComputeExceeded, err
		}

		// Read actual data
		data, err := vm.ReadMemory(dataPtr, int(dataLen))
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		hasher.Write(data)
	}

	// Write result
	result := hasher.Sum(nil)
	if err := vm.WriteMemory(resultAddr, result); err != nil {
		return SyscallErrorInvalidMemory, err
	}

	return SyscallSuccess, nil
}

// SolBlake3 implements the sol_blake3 syscall.
// Computes BLAKE3 hash of input data slices.
// Arguments:
//   r1: pointer to result (32 bytes output)
//   r2: pointer to array of data slice descriptors
//   r3: number of data slices
//
// Each slice descriptor is 16 bytes:
//   - 8 bytes: pointer to data
//   - 8 bytes: length of data
//
// Note: We use BLAKE2b-256 as a stand-in since Go doesn't have a standard BLAKE3.
// In production, use a proper BLAKE3 implementation like github.com/zeebo/blake3.
func SolBlake3(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	resultAddr := r1
	slicesAddr := r2
	numSlices := r3

	// Compute cost
	cost := CUBlake3Base
	if err := vm.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	// Use BLAKE2b-256 as approximation (replace with BLAKE3 in production)
	hasher, err := blake2b.New256(nil)
	if err != nil {
		return SyscallErrorPanic, err
	}

	mem := vm.Memory()

	for i := uint64(0); i < numSlices; i++ {
		// Each slice descriptor is 16 bytes (ptr + len)
		descriptorAddr := slicesAddr + i*16

		// Read pointer (8 bytes)
		dataPtr, err := mem.ReadUint64(descriptorAddr)
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Read length (8 bytes)
		dataLen, err := mem.ReadUint64(descriptorAddr + 8)
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		// Charge per-byte cost
		if err := vm.ConsumeComputeUnits(dataLen * CUBlake3PerByte); err != nil {
			return SyscallErrorComputeExceeded, err
		}

		// Read actual data
		data, err := vm.ReadMemory(dataPtr, int(dataLen))
		if err != nil {
			return SyscallErrorInvalidMemory, err
		}

		hasher.Write(data)
	}

	// Write result
	result := hasher.Sum(nil)
	if err := vm.WriteMemory(resultAddr, result); err != nil {
		return SyscallErrorInvalidMemory, err
	}

	return SyscallSuccess, nil
}

// HashSHA256 is a helper function to compute SHA256 of multiple byte slices.
func HashSHA256(data ...[]byte) [32]byte {
	hasher := sha256.New()
	for _, d := range data {
		hasher.Write(d)
	}
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

// HashKeccak256 is a helper function to compute Keccak256 of multiple byte slices.
func HashKeccak256(data ...[]byte) [32]byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, d := range data {
		hasher.Write(d)
	}
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

// HashBlake2b256 is a helper function to compute BLAKE2b-256 of multiple byte slices.
func HashBlake2b256(data ...[]byte) [32]byte {
	hasher, _ := blake2b.New256(nil)
	for _, d := range data {
		hasher.Write(d)
	}
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}
