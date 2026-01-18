package syscall

import (
	"github.com/fortiblox/x1-nimbus/pkg/svm/sbpf"
)

// SolMemcpy implements the sol_memcpy_ syscall.
// Copies non-overlapping memory regions.
// Arguments:
//   r1: destination address
//   r2: source address
//   r3: number of bytes to copy
//
// Returns 0 on success, error code on failure.
func SolMemcpy(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	dst := r1
	src := r2
	n := r3

	if n == 0 {
		return SyscallSuccess, nil
	}

	// Consume compute units
	cost := CUMemoryOp + n*CUMemoryPerByte
	if err := vm.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	// Check for overlap - memcpy requires non-overlapping regions
	if (dst < src && dst+n > src) || (src < dst && src+n > dst) {
		return SyscallErrorInvalidArgument, nil
	}

	// Read source
	srcData, err := vm.ReadMemory(src, int(n))
	if err != nil {
		return SyscallErrorInvalidMemory, err
	}

	// Write to destination
	if err := vm.WriteMemory(dst, srcData); err != nil {
		return SyscallErrorInvalidMemory, err
	}

	return SyscallSuccess, nil
}

// SolMemmove implements the sol_memmove_ syscall.
// Moves memory regions that may overlap.
// Arguments:
//   r1: destination address
//   r2: source address
//   r3: number of bytes to move
//
// Returns 0 on success, error code on failure.
func SolMemmove(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	dst := r1
	src := r2
	n := r3

	if n == 0 {
		return SyscallSuccess, nil
	}

	// Consume compute units
	cost := CUMemoryOp + n*CUMemoryPerByte
	if err := vm.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	// Read source into temporary buffer
	srcData, err := vm.ReadMemory(src, int(n))
	if err != nil {
		return SyscallErrorInvalidMemory, err
	}

	// Copy data (handles overlap by using intermediate buffer)
	dataCopy := make([]byte, n)
	copy(dataCopy, srcData)

	// Write to destination
	if err := vm.WriteMemory(dst, dataCopy); err != nil {
		return SyscallErrorInvalidMemory, err
	}

	return SyscallSuccess, nil
}

// SolMemset implements the sol_memset_ syscall.
// Fills memory with a specific byte value.
// Arguments:
//   r1: destination address
//   r2: byte value to fill with
//   r3: number of bytes to fill
//
// Returns 0 on success, error code on failure.
func SolMemset(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	dst := r1
	val := byte(r2)
	n := r3

	if n == 0 {
		return SyscallSuccess, nil
	}

	// Consume compute units
	cost := CUMemoryOp + n*CUMemoryPerByte
	if err := vm.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	// Create fill buffer
	fillData := make([]byte, n)
	for i := range fillData {
		fillData[i] = val
	}

	// Write to destination
	if err := vm.WriteMemory(dst, fillData); err != nil {
		return SyscallErrorInvalidMemory, err
	}

	return SyscallSuccess, nil
}

// SolMemcmp implements the sol_memcmp_ syscall.
// Compares two memory regions.
// Arguments:
//   r1: first memory region address
//   r2: second memory region address
//   r3: number of bytes to compare
//   r4: address to write result (int32)
//
// Result is:
//   - 0 if equal
//   - < 0 if first region is less than second
//   - > 0 if first region is greater than second
//
// Returns 0 on success, error code on failure.
func SolMemcmp(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	addr1 := r1
	addr2 := r2
	n := r3
	resultAddr := r4

	// Consume compute units
	cost := CUMemoryOp + n*CUMemoryPerByte
	if err := vm.ConsumeComputeUnits(cost); err != nil {
		return SyscallErrorComputeExceeded, err
	}

	mem := vm.Memory()

	if n == 0 {
		// Equal if both zero length
		if err := mem.WriteUint32(resultAddr, 0); err != nil {
			return SyscallErrorInvalidMemory, err
		}
		return SyscallSuccess, nil
	}

	// Read both regions
	data1, err := vm.ReadMemory(addr1, int(n))
	if err != nil {
		return SyscallErrorInvalidMemory, err
	}
	data2, err := vm.ReadMemory(addr2, int(n))
	if err != nil {
		return SyscallErrorInvalidMemory, err
	}

	// Compare byte by byte
	var result int32 = 0
	for i := uint64(0); i < n; i++ {
		if data1[i] < data2[i] {
			result = -1
			break
		} else if data1[i] > data2[i] {
			result = 1
			break
		}
	}

	// Write result
	if err := mem.WriteUint32(resultAddr, uint32(result)); err != nil {
		return SyscallErrorInvalidMemory, err
	}

	return SyscallSuccess, nil
}

// SolAllocFree implements the sol_alloc_free_ syscall.
// Bump allocator for heap memory.
// Arguments:
//   r1: size to allocate (0 for free, which is a no-op)
//   r2: pointer to free (unused, bump allocator doesn't free)
//
// Returns: address of allocated memory, or 0 on failure
func SolAllocFree(vm *sbpf.VM, r1, r2, r3, r4, r5 uint64) (uint64, error) {
	size := r1

	// Consume compute units
	cost := CUMemoryOp
	if err := vm.ConsumeComputeUnits(cost); err != nil {
		return 0, err
	}

	// Free is a no-op in bump allocator
	if size == 0 {
		return 0, nil
	}

	// Allocate with 8-byte alignment
	addr, err := vm.Alloc(size, 8)
	if err != nil {
		// Return 0 on allocation failure (not an error, just no memory)
		return 0, nil
	}

	return addr, nil
}

// MemoryCopy is a helper function for copying memory within the VM.
func MemoryCopy(vm *sbpf.VM, dst, src, n uint64) error {
	if n == 0 {
		return nil
	}

	srcData, err := vm.ReadMemory(src, int(n))
	if err != nil {
		return err
	}

	dataCopy := make([]byte, n)
	copy(dataCopy, srcData)

	return vm.WriteMemory(dst, dataCopy)
}

// MemoryZero is a helper function for zeroing memory in the VM.
func MemoryZero(vm *sbpf.VM, addr, n uint64) error {
	if n == 0 {
		return nil
	}

	zeroData := make([]byte, n)
	return vm.WriteMemory(addr, zeroData)
}

// ReadSlice reads a Rust slice (ptr, len) from memory.
func ReadSlice(vm *sbpf.VM, addr uint64) (uint64, uint64, error) {
	mem := vm.Memory()
	ptr, err := mem.ReadUint64(addr)
	if err != nil {
		return 0, 0, err
	}
	length, err := mem.ReadUint64(addr + 8)
	if err != nil {
		return 0, 0, err
	}
	return ptr, length, nil
}

// ReadSliceData reads the data referenced by a Rust slice.
func ReadSliceData(vm *sbpf.VM, sliceAddr uint64) ([]byte, error) {
	ptr, length, err := ReadSlice(vm, sliceAddr)
	if err != nil {
		return nil, err
	}
	return vm.ReadMemory(ptr, int(length))
}
