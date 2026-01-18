// Package sbpf implements the Solana BPF (sBPF) virtual machine for X1-Nimbus.
//
// The sBPF VM is a specialized virtual machine for executing Solana smart contracts.
// It implements a variant of the eBPF instruction set with Solana-specific extensions
// for syscalls and memory management.
//
// Memory Model:
//   - Program region (0x100000000): Read-only program code
//   - Stack region (0x200000000): Stack frames for function calls
//   - Heap region (0x300000000): Bump-allocated dynamic memory
//   - Input region (0x400000000): Serialized transaction input data
//
// Registers:
//   - R0: Return value and scratch register
//   - R1-R5: Function arguments
//   - R6-R9: Callee-saved registers
//   - R10: Frame pointer (read-only)
package sbpf

// NumRegisters is the number of registers in the sBPF VM.
const NumRegisters = 11

// SyscallHandler is the interface for handling syscalls from the VM.
type SyscallHandler interface {
	// HandleSyscall handles a syscall invocation.
	// The syscall number is in inst.Imm, arguments are in R1-R5.
	// Returns the result to be placed in R0, or an error.
	HandleSyscall(vm *VM, syscallNum uint32) (uint64, error)
}

// CallFrame stores the state for a function call.
type CallFrame struct {
	ReturnPC uint64 // Program counter to return to
	FramePtr uint64 // Previous frame pointer
}

// VM is the sBPF virtual machine.
type VM struct {
	// Registers R0-R10
	reg [NumRegisters]uint64

	// Program counter (instruction index, not byte offset)
	pc uint64

	// Decoded instructions
	instructions []Instruction

	// Memory map
	memory *MemoryMap

	// Call stack
	callStack []CallFrame
	callDepth int

	// Compute budget
	computeUnits uint64
	initialCU    uint64

	// Syscall handler
	syscallHandler SyscallHandler

	// Execution state
	exited bool
}

// NewVM creates a new sBPF virtual machine.
//
// The program parameter should contain the raw sBPF bytecode.
// computeUnits specifies the maximum number of compute units (instructions)
// that can be executed before the VM halts with ErrComputeExhausted.
func NewVM(program []byte, computeUnits uint64) (*VM, error) {
	if len(program) > MaxProgramSize {
		return nil, ErrProgramTooLarge
	}

	if len(program)%InstructionSize != 0 {
		return nil, ErrInvalidProgramData
	}

	// Decode all instructions upfront
	numInstructions := len(program) / InstructionSize
	instructions := make([]Instruction, numInstructions)
	for i := 0; i < numInstructions; i++ {
		offset := i * InstructionSize
		instructions[i] = DecodeInstruction(program[offset : offset+InstructionSize])
	}

	vm := &VM{
		instructions: instructions,
		callStack:    make([]CallFrame, MaxStackFrames),
		computeUnits: computeUnits,
		initialCU:    computeUnits,
	}

	return vm, nil
}

// Run executes the program with the given input data.
//
// The input data is typically the serialized account data and instruction
// parameters. It returns the value in R0 upon successful completion,
// or an error if execution fails.
func (vm *VM) Run(input []byte) (uint64, error) {
	// Initialize memory map
	programBytes := make([]byte, len(vm.instructions)*InstructionSize)
	for i, inst := range vm.instructions {
		offset := i * InstructionSize
		programBytes[offset] = inst.Opcode
		programBytes[offset+1] = (inst.Src << 4) | inst.Dst
		programBytes[offset+2] = byte(inst.Offset)
		programBytes[offset+3] = byte(inst.Offset >> 8)
		programBytes[offset+4] = byte(inst.Imm)
		programBytes[offset+5] = byte(inst.Imm >> 8)
		programBytes[offset+6] = byte(inst.Imm >> 16)
		programBytes[offset+7] = byte(inst.Imm >> 24)
	}
	vm.memory = NewMemoryMap(programBytes, input)

	// Initialize registers
	vm.reg = [NumRegisters]uint64{}
	vm.pc = 0
	vm.callDepth = 0
	vm.exited = false

	// R1 points to input data
	vm.reg[R1] = InputStart

	// R10 is the frame pointer (top of stack)
	vm.reg[R10] = vm.memory.GetFramePointer(0)

	// Execute
	err := vm.execute()
	if err != nil {
		return 0, err
	}

	return vm.reg[R0], nil
}

// SetSyscallHandler sets the handler for syscall instructions.
func (vm *VM) SetSyscallHandler(handler SyscallHandler) {
	vm.syscallHandler = handler
}

// GetRegister returns the value of a register.
func (vm *VM) GetRegister(reg int) uint64 {
	if reg < 0 || reg >= NumRegisters {
		return 0
	}
	return vm.reg[reg]
}

// SetRegister sets the value of a register (except R10 which is read-only for programs).
func (vm *VM) SetRegister(reg int, value uint64) {
	if reg < 0 || reg >= NumRegisters {
		return
	}
	vm.reg[reg] = value
}

// GetPC returns the current program counter.
func (vm *VM) GetPC() uint64 {
	return vm.pc
}

// GetComputeUnitsRemaining returns the remaining compute units.
func (vm *VM) GetComputeUnitsRemaining() uint64 {
	return vm.computeUnits
}

// GetComputeUnitsUsed returns the number of compute units used.
func (vm *VM) GetComputeUnitsUsed() uint64 {
	return vm.initialCU - vm.computeUnits
}

// ConsumeComputeUnits consumes compute units (for syscalls).
// Returns an error if there are insufficient compute units.
func (vm *VM) ConsumeComputeUnits(units uint64) error {
	if vm.computeUnits < units {
		vm.computeUnits = 0
		return ErrComputeExhausted
	}
	vm.computeUnits -= units
	return nil
}

// Memory returns the memory map for direct access (used by syscalls).
func (vm *VM) Memory() *MemoryMap {
	return vm.memory
}

// GetCallDepth returns the current call depth.
func (vm *VM) GetCallDepth() int {
	return vm.callDepth
}

// ReadMemory reads bytes from VM memory.
func (vm *VM) ReadMemory(addr uint64, size int) ([]byte, error) {
	return vm.memory.Read(addr, size)
}

// WriteMemory writes bytes to VM memory.
func (vm *VM) WriteMemory(addr uint64, data []byte) error {
	return vm.memory.Write(addr, data)
}

// Alloc allocates memory from the heap.
func (vm *VM) Alloc(size uint64, align uint64) (uint64, error) {
	return vm.memory.Alloc(size, align)
}
