package sbpf

import (
	"encoding/binary"
)

// Memory region base addresses (following Solana's sBPF memory model)
const (
	// ProgramStart is the base address for the read-only program code.
	ProgramStart = 0x100000000

	// StackStart is the base address for the stack region.
	StackStart = 0x200000000

	// HeapStart is the base address for the heap region.
	HeapStart = 0x300000000

	// InputStart is the base address for the input data region.
	InputStart = 0x400000000
)

// Memory region sizes
const (
	// MaxProgramSize is the maximum program size (10MB).
	MaxProgramSize = 10 * 1024 * 1024

	// StackSize is the size of each stack frame (4KB).
	StackFrameSize = 4 * 1024

	// MaxStackFrames is the maximum number of stack frames.
	MaxStackFrames = 64

	// StackSize is the total stack size.
	StackSize = StackFrameSize * MaxStackFrames

	// HeapSize is the heap size (32KB default, can be extended).
	HeapSize = 32 * 1024

	// MaxInputSize is the maximum input data size (10MB).
	MaxInputSize = 10 * 1024 * 1024
)

// Region permission flags
const (
	PermRead  = 1 << 0
	PermWrite = 1 << 1
	PermExec  = 1 << 2
)

// MemoryRegion represents a contiguous memory region.
type MemoryRegion struct {
	Base   uint64 // Virtual base address
	Data   []byte // Backing storage
	Perm   uint8  // Permission flags
	Name   string // Region name for debugging
}

// Contains checks if an address is within this region.
func (r *MemoryRegion) Contains(addr uint64) bool {
	return addr >= r.Base && addr < r.Base+uint64(len(r.Data))
}

// Translate converts a virtual address to an offset in the backing storage.
func (r *MemoryRegion) Translate(addr uint64) (int, bool) {
	if !r.Contains(addr) {
		return 0, false
	}
	return int(addr - r.Base), true
}

// CanRead returns true if the region is readable.
func (r *MemoryRegion) CanRead() bool {
	return (r.Perm & PermRead) != 0
}

// CanWrite returns true if the region is writable.
func (r *MemoryRegion) CanWrite() bool {
	return (r.Perm & PermWrite) != 0
}

// MemoryMap manages the VM's virtual memory space.
type MemoryMap struct {
	Program *MemoryRegion
	Stack   *MemoryRegion
	Heap    *MemoryRegion
	Input   *MemoryRegion

	// Heap allocator state
	heapPos uint64
}

// NewMemoryMap creates a new memory map with the specified regions.
func NewMemoryMap(program, input []byte) *MemoryMap {
	mm := &MemoryMap{
		Program: &MemoryRegion{
			Base: ProgramStart,
			Data: program,
			Perm: PermRead | PermExec,
			Name: "program",
		},
		Stack: &MemoryRegion{
			Base: StackStart,
			Data: make([]byte, StackSize),
			Perm: PermRead | PermWrite,
			Name: "stack",
		},
		Heap: &MemoryRegion{
			Base: HeapStart,
			Data: make([]byte, HeapSize),
			Perm: PermRead | PermWrite,
			Name: "heap",
		},
		Input: &MemoryRegion{
			Base: InputStart,
			Data: input,
			Perm: PermRead | PermWrite, // Input can be modified
			Name: "input",
		},
		heapPos: HeapStart,
	}
	return mm
}

// findRegion finds the memory region containing the given address.
func (mm *MemoryMap) findRegion(addr uint64) *MemoryRegion {
	// Check each region (ordered by likelihood of access)
	if mm.Stack.Contains(addr) {
		return mm.Stack
	}
	if mm.Heap.Contains(addr) {
		return mm.Heap
	}
	if mm.Input.Contains(addr) {
		return mm.Input
	}
	if mm.Program.Contains(addr) {
		return mm.Program
	}
	return nil
}

// Read reads bytes from virtual memory.
func (mm *MemoryMap) Read(addr uint64, size int) ([]byte, error) {
	region := mm.findRegion(addr)
	if region == nil {
		return nil, ErrAccessViolation
	}

	if !region.CanRead() {
		return nil, ErrAccessViolation
	}

	offset, ok := region.Translate(addr)
	if !ok {
		return nil, ErrAccessViolation
	}

	end := offset + size
	if end > len(region.Data) {
		return nil, ErrAccessViolation
	}

	return region.Data[offset:end], nil
}

// Write writes bytes to virtual memory.
func (mm *MemoryMap) Write(addr uint64, data []byte) error {
	region := mm.findRegion(addr)
	if region == nil {
		return ErrAccessViolation
	}

	if !region.CanWrite() {
		return ErrAccessViolation
	}

	offset, ok := region.Translate(addr)
	if !ok {
		return ErrAccessViolation
	}

	end := offset + len(data)
	if end > len(region.Data) {
		return ErrAccessViolation
	}

	copy(region.Data[offset:end], data)
	return nil
}

// ReadByte reads a single byte from virtual memory.
func (mm *MemoryMap) ReadByte(addr uint64) (byte, error) {
	data, err := mm.Read(addr, 1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

// ReadUint16 reads a 16-bit value from virtual memory (little-endian).
func (mm *MemoryMap) ReadUint16(addr uint64) (uint16, error) {
	data, err := mm.Read(addr, 2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(data), nil
}

// ReadUint32 reads a 32-bit value from virtual memory (little-endian).
func (mm *MemoryMap) ReadUint32(addr uint64) (uint32, error) {
	data, err := mm.Read(addr, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

// ReadUint64 reads a 64-bit value from virtual memory (little-endian).
func (mm *MemoryMap) ReadUint64(addr uint64) (uint64, error) {
	data, err := mm.Read(addr, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

// WriteByte writes a single byte to virtual memory.
func (mm *MemoryMap) WriteByte(addr uint64, val byte) error {
	return mm.Write(addr, []byte{val})
}

// WriteUint16 writes a 16-bit value to virtual memory (little-endian).
func (mm *MemoryMap) WriteUint16(addr uint64, val uint16) error {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, val)
	return mm.Write(addr, data)
}

// WriteUint32 writes a 32-bit value to virtual memory (little-endian).
func (mm *MemoryMap) WriteUint32(addr uint64, val uint32) error {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, val)
	return mm.Write(addr, data)
}

// WriteUint64 writes a 64-bit value to virtual memory (little-endian).
func (mm *MemoryMap) WriteUint64(addr uint64, val uint64) error {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, val)
	return mm.Write(addr, data)
}

// Alloc allocates memory from the heap using bump allocation.
// Returns the virtual address of the allocated memory.
func (mm *MemoryMap) Alloc(size uint64, align uint64) (uint64, error) {
	// Align the current position
	if align > 0 {
		remainder := mm.heapPos % align
		if remainder != 0 {
			mm.heapPos += align - remainder
		}
	}

	// Check if allocation fits
	heapEnd := HeapStart + uint64(len(mm.Heap.Data))
	if mm.heapPos+size > heapEnd {
		return 0, ErrAccessViolation
	}

	addr := mm.heapPos
	mm.heapPos += size

	return addr, nil
}

// Free is a no-op for bump allocation (memory is freed when VM is destroyed).
func (mm *MemoryMap) Free(addr uint64) error {
	// Bump allocator doesn't support freeing
	return nil
}

// HeapPosition returns the current heap allocation position.
func (mm *MemoryMap) HeapPosition() uint64 {
	return mm.heapPos
}

// GetStackFrame returns the virtual address of a stack frame.
func (mm *MemoryMap) GetStackFrame(depth int) uint64 {
	// Stack grows downward from the top
	// Frame 0 is at the top of the stack
	return StackStart + uint64(StackSize) - uint64((depth+1)*StackFrameSize)
}

// GetFramePointer returns the initial frame pointer for a given call depth.
func (mm *MemoryMap) GetFramePointer(depth int) uint64 {
	// Frame pointer points to the top of the current frame
	return StackStart + uint64(StackSize) - uint64(depth*StackFrameSize)
}

// ValidateAccess checks if an access is valid without performing it.
func (mm *MemoryMap) ValidateAccess(addr uint64, size int, write bool) error {
	region := mm.findRegion(addr)
	if region == nil {
		return ErrAccessViolation
	}

	if write && !region.CanWrite() {
		return ErrAccessViolation
	}

	if !write && !region.CanRead() {
		return ErrAccessViolation
	}

	offset, ok := region.Translate(addr)
	if !ok {
		return ErrAccessViolation
	}

	if offset+size > len(region.Data) {
		return ErrAccessViolation
	}

	return nil
}

// RegionName returns the name of the region containing the address.
func (mm *MemoryMap) RegionName(addr uint64) string {
	region := mm.findRegion(addr)
	if region == nil {
		return "invalid"
	}
	return region.Name
}
