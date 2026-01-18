package sbpf

import (
	"errors"
	"testing"
)

// Helper function to encode an instruction into bytes.
func encodeInstruction(opcode uint8, dst, src uint8, offset int16, imm int32) []byte {
	data := make([]byte, InstructionSize)
	data[0] = opcode
	data[1] = (src << 4) | dst
	data[2] = byte(offset)
	data[3] = byte(offset >> 8)
	data[4] = byte(imm)
	data[5] = byte(imm >> 8)
	data[6] = byte(imm >> 16)
	data[7] = byte(imm >> 24)
	return data
}

// Helper function to create a program from instructions.
func makeProgram(instructions ...[]byte) []byte {
	var program []byte
	for _, inst := range instructions {
		program = append(program, inst...)
	}
	return program
}

func TestNewVM(t *testing.T) {
	// Simple program: mov r0, 42; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 42),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	if vm == nil {
		t.Fatal("NewVM returned nil")
	}

	if vm.GetComputeUnitsRemaining() != 1000 {
		t.Errorf("expected 1000 compute units, got %d", vm.GetComputeUnitsRemaining())
	}
}

func TestNewVMInvalidProgram(t *testing.T) {
	// Program with invalid size (not multiple of 8)
	program := []byte{0x01, 0x02, 0x03}
	_, err := NewVM(program, 1000)
	if err == nil {
		t.Fatal("expected error for invalid program size")
	}
	if !errors.Is(err, ErrInvalidProgramData) {
		t.Errorf("expected ErrInvalidProgramData, got %v", err)
	}
}

func TestSimpleReturn(t *testing.T) {
	// mov r0, 42; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 42),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}

	// Should have used 2 compute units (mov + exit)
	if vm.GetComputeUnitsUsed() != 2 {
		t.Errorf("expected 2 compute units used, got %d", vm.GetComputeUnitsUsed())
	}
}

func TestALU64Add(t *testing.T) {
	// mov r0, 10; add r0, 32; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 10),
		encodeInstruction(ADD64_IMM, R0, 0, 0, 32),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}
}

func TestALU64Sub(t *testing.T) {
	// mov r0, 100; sub r0, 58; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 100),
		encodeInstruction(SUB64_IMM, R0, 0, 0, 58),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}
}

func TestALU64Mul(t *testing.T) {
	// mov r0, 6; mul r0, 7; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 6),
		encodeInstruction(MUL64_IMM, R0, 0, 0, 7),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}
}

func TestALU64Div(t *testing.T) {
	// mov r0, 84; div r0, 2; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 84),
		encodeInstruction(DIV64_IMM, R0, 0, 0, 2),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}
}

func TestALU64DivByZero(t *testing.T) {
	// mov r0, 84; div r0, 0; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 84),
		encodeInstruction(DIV64_IMM, R0, 0, 0, 0),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	_, err = vm.Run(nil)
	if err == nil {
		t.Fatal("expected division by zero error")
	}
	if !errors.Is(err, ErrDivisionByZero) {
		t.Errorf("expected ErrDivisionByZero, got %v", err)
	}
}

func TestALU64Mod(t *testing.T) {
	// mov r0, 47; mod r0, 5; exit (47 % 5 = 2)
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 47),
		encodeInstruction(MOD64_IMM, R0, 0, 0, 5),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 2 {
		t.Errorf("expected result 2, got %d", result)
	}
}

func TestALU64BitwiseOps(t *testing.T) {
	tests := []struct {
		name     string
		opcode   uint8
		initial  int32
		operand  int32
		expected uint64
	}{
		{"OR", OR64_IMM, 0x0F, 0xF0, 0xFF},
		{"AND", AND64_IMM, 0xFF, 0x0F, 0x0F},
		{"XOR", XOR64_IMM, 0xFF, 0xF0, 0x0F},
		{"LSH", LSH64_IMM, 1, 4, 16},
		{"RSH", RSH64_IMM, 16, 4, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			program := makeProgram(
				encodeInstruction(MOV64_IMM, R0, 0, 0, tc.initial),
				encodeInstruction(tc.opcode, R0, 0, 0, tc.operand),
				encodeInstruction(EXIT, 0, 0, 0, 0),
			)

			vm, err := NewVM(program, 1000)
			if err != nil {
				t.Fatalf("NewVM failed: %v", err)
			}

			result, err := vm.Run(nil)
			if err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected result %d, got %d", tc.expected, result)
			}
		})
	}
}

func TestALU64Neg(t *testing.T) {
	// mov r0, 42; neg r0; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 42),
		encodeInstruction(NEG64, R0, 0, 0, 0),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// -42 in two's complement
	expected := ^uint64(41) // Same as -42 in two's complement
	if result != expected {
		t.Errorf("expected result %d, got %d", expected, result)
	}
}

func TestALU64RegisterOps(t *testing.T) {
	// mov r1, 10; mov r0, 32; add r0, r1; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R1, 0, 0, 10),
		encodeInstruction(MOV64_IMM, R0, 0, 0, 32),
		encodeInstruction(ADD64_REG, R0, R1, 0, 0),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}
}

func TestALU32(t *testing.T) {
	// mov32 r0, 0xFFFFFFFF (should truncate to 32 bits)
	// add32 r0, 1 (should wrap around)
	program := makeProgram(
		encodeInstruction(MOV32_IMM, R0, 0, 0, -1), // 0xFFFFFFFF
		encodeInstruction(ADD32_IMM, R0, 0, 0, 1),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Should wrap to 0
	if result != 0 {
		t.Errorf("expected result 0, got %d", result)
	}
}

func TestJumpAlways(t *testing.T) {
	// ja +1; mov r0, 1; mov r0, 42; exit
	program := makeProgram(
		encodeInstruction(JA, 0, 0, 1, 0),       // Jump over next instruction
		encodeInstruction(MOV64_IMM, R0, 0, 0, 1), // Skipped
		encodeInstruction(MOV64_IMM, R0, 0, 0, 42),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}
}

func TestJumpConditionalImm(t *testing.T) {
	tests := []struct {
		name     string
		opcode   uint8
		r0Value  int32
		imm      int32
		expected uint64
	}{
		{"JEQ_IMM true", JEQ_IMM, 42, 42, 1},
		{"JEQ_IMM false", JEQ_IMM, 42, 43, 0},
		{"JNE_IMM true", JNE_IMM, 42, 43, 1},
		{"JNE_IMM false", JNE_IMM, 42, 42, 0},
		{"JGT_IMM true", JGT_IMM, 43, 42, 1},
		{"JGT_IMM false", JGT_IMM, 42, 42, 0},
		{"JGE_IMM true", JGE_IMM, 42, 42, 1},
		{"JGE_IMM false", JGE_IMM, 41, 42, 0},
		{"JLT_IMM true", JLT_IMM, 41, 42, 1},
		{"JLT_IMM false", JLT_IMM, 42, 42, 0},
		{"JLE_IMM true", JLE_IMM, 42, 42, 1},
		{"JLE_IMM false", JLE_IMM, 43, 42, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// mov r0, value; jxx +2, imm; mov r0, 0; ja +1; mov r0, 1; exit
			// If condition is true: jump to mov r0, 1
			// If condition is false: fall through to mov r0, 0, then jump to exit
			program := makeProgram(
				encodeInstruction(MOV64_IMM, R0, 0, 0, tc.r0Value),
				encodeInstruction(tc.opcode, R0, 0, 2, tc.imm),  // Jump over next 2 instructions
				encodeInstruction(MOV64_IMM, R0, 0, 0, 0),       // Not taken path
				encodeInstruction(JA, 0, 0, 1, 0),               // Skip mov r0, 1
				encodeInstruction(MOV64_IMM, R0, 0, 0, 1),       // Taken path
				encodeInstruction(EXIT, 0, 0, 0, 0),
			)

			vm, err := NewVM(program, 1000)
			if err != nil {
				t.Fatalf("NewVM failed: %v", err)
			}

			result, err := vm.Run(nil)
			if err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected result %d, got %d", tc.expected, result)
			}
		})
	}
}

func TestJumpSignedImm(t *testing.T) {
	// Test signed comparison with negative numbers
	// mov r0, -1; jsgt r0, -2, +2; mov r0, 0; ja +1; mov r0, 1; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, -1),
		encodeInstruction(JSGT_IMM, R0, 0, 2, -2), // -1 > -2 is true, jump +2
		encodeInstruction(MOV64_IMM, R0, 0, 0, 0), // Not taken
		encodeInstruction(JA, 0, 0, 1, 0),         // Skip next
		encodeInstruction(MOV64_IMM, R0, 0, 0, 1),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 1 {
		t.Errorf("expected result 1 (jump taken), got %d", result)
	}
}

func TestComputeExhausted(t *testing.T) {
	// Program that loops forever
	// loop: ja -1
	program := makeProgram(
		encodeInstruction(JA, 0, 0, -1, 0), // Jump back to itself
	)

	vm, err := NewVM(program, 10) // Only 10 compute units
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	_, err = vm.Run(nil)
	if err == nil {
		t.Fatal("expected compute exhausted error")
	}
	if !errors.Is(err, ErrComputeExhausted) {
		t.Errorf("expected ErrComputeExhausted, got %v", err)
	}
}

func TestMemoryLoad(t *testing.T) {
	// Create input data
	input := make([]byte, 16)
	input[0] = 0x12
	input[1] = 0x34
	input[2] = 0x56
	input[3] = 0x78
	input[4] = 0x9A
	input[5] = 0xBC
	input[6] = 0xDE
	input[7] = 0xF0

	// ldxdw r0, [r1+0]; exit
	// R1 points to input data by default
	program := makeProgram(
		encodeInstruction(LDXDW, R0, R1, 0, 0),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(input)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	expected := uint64(0xF0DEBC9A78563412)
	if result != expected {
		t.Errorf("expected result 0x%X, got 0x%X", expected, result)
	}
}

func TestMemoryLoadSizes(t *testing.T) {
	// Create input data
	input := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}

	tests := []struct {
		name     string
		opcode   uint8
		expected uint64
	}{
		{"LDXB", LDXB, 0x12},
		{"LDXH", LDXH, 0x3412},
		{"LDXW", LDXW, 0x78563412},
		{"LDXDW", LDXDW, 0xF0DEBC9A78563412},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			program := makeProgram(
				encodeInstruction(tc.opcode, R0, R1, 0, 0),
				encodeInstruction(EXIT, 0, 0, 0, 0),
			)

			vm, err := NewVM(program, 1000)
			if err != nil {
				t.Fatalf("NewVM failed: %v", err)
			}

			result, err := vm.Run(input)
			if err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			if result != tc.expected {
				t.Errorf("expected result 0x%X, got 0x%X", tc.expected, result)
			}
		})
	}
}

func TestMemoryStore(t *testing.T) {
	// Create input buffer for writing
	input := make([]byte, 16)

	// Store 42 to input[0] and read it back
	// mov r2, 42; stxdw [r1+0], r2; ldxdw r0, [r1+0]; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R2, 0, 0, 42),
		encodeInstruction(STXDW, R1, R2, 0, 0),
		encodeInstruction(LDXDW, R0, R1, 0, 0),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(input)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}
}

func TestMemoryAccessViolation(t *testing.T) {
	// Try to read from invalid address
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R1, 0, 0, 0), // Invalid address 0
		encodeInstruction(LDXDW, R0, R1, 0, 0),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	_, err = vm.Run(nil)
	if err == nil {
		t.Fatal("expected access violation error")
	}
	if !errors.Is(err, ErrAccessViolation) {
		t.Errorf("expected ErrAccessViolation, got %v", err)
	}
}

func TestLDDW(t *testing.T) {
	// lddw r0, 0x123456789ABCDEF0
	// This uses two instruction slots
	lowImm := int32(-1698898192)  // 0x9ABCDEF0 as signed int32
	highImm := int32(0x12345678)

	program := makeProgram(
		encodeInstruction(LDDW, R0, 0, 0, lowImm),
		encodeInstruction(0, 0, 0, 0, highImm), // Second slot
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	expected := uint64(0x123456789ABCDEF0)
	if result != expected {
		t.Errorf("expected result 0x%X, got 0x%X", expected, result)
	}
}

// MockSyscallHandler implements SyscallHandler for testing.
type MockSyscallHandler struct {
	calls []uint32
}

func (h *MockSyscallHandler) HandleSyscall(vm *VM, syscallNum uint32) (uint64, error) {
	h.calls = append(h.calls, syscallNum)
	// Return sum of R1-R5 as result
	return vm.GetRegister(R1) + vm.GetRegister(R2) + vm.GetRegister(R3) +
		vm.GetRegister(R4) + vm.GetRegister(R5), nil
}

func TestSyscall(t *testing.T) {
	// mov r1, 10; mov r2, 20; mov r3, 12; call 0; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R1, 0, 0, 10),
		encodeInstruction(MOV64_IMM, R2, 0, 0, 20),
		encodeInstruction(MOV64_IMM, R3, 0, 0, 12),
		encodeInstruction(CALL, 0, 0, 0, 0), // Syscall 0
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	vm, err := NewVM(program, 1000)
	if err != nil {
		t.Fatalf("NewVM failed: %v", err)
	}

	handler := &MockSyscallHandler{}
	vm.SetSyscallHandler(handler)

	result, err := vm.Run(nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Result should be R1+R2+R3 = 10+20+12 = 42
	if result != 42 {
		t.Errorf("expected result 42, got %d", result)
	}

	// Syscall should have been called once
	if len(handler.calls) != 1 {
		t.Errorf("expected 1 syscall, got %d", len(handler.calls))
	}
}

func TestInstructionDecode(t *testing.T) {
	data := []byte{0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00}
	inst := DecodeInstruction(data)

	if inst.Opcode != ADD64_IMM {
		t.Errorf("expected opcode 0x07, got 0x%02x", inst.Opcode)
	}
	if inst.Dst != 1 {
		t.Errorf("expected dst 1, got %d", inst.Dst)
	}
	if inst.Src != 0 {
		t.Errorf("expected src 0, got %d", inst.Src)
	}
	if inst.Offset != 0 {
		t.Errorf("expected offset 0, got %d", inst.Offset)
	}
	if inst.Imm != 42 {
		t.Errorf("expected imm 42, got %d", inst.Imm)
	}
}

func TestOpcodeString(t *testing.T) {
	tests := []struct {
		opcode   uint8
		expected string
	}{
		{ADD64_IMM, "ADD64_IMM"},
		{MOV64_REG, "MOV64_REG"},
		{LDXDW, "LDXDW"},
		{EXIT, "EXIT"},
		{0xFF, "UNKNOWN"},
	}

	for _, tc := range tests {
		name := OpcodeString(tc.opcode)
		if name != tc.expected {
			t.Errorf("OpcodeString(0x%02x): expected %s, got %s", tc.opcode, tc.expected, name)
		}
	}
}

func TestMemoryMapRegions(t *testing.T) {
	program := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	input := []byte{1, 2, 3, 4}

	mm := NewMemoryMap(program, input)

	// Test program region
	if mm.RegionName(ProgramStart) != "program" {
		t.Errorf("expected program region")
	}

	// Test stack region
	if mm.RegionName(StackStart) != "stack" {
		t.Errorf("expected stack region")
	}

	// Test heap region
	if mm.RegionName(HeapStart) != "heap" {
		t.Errorf("expected heap region")
	}

	// Test input region
	if mm.RegionName(InputStart) != "input" {
		t.Errorf("expected input region")
	}

	// Test invalid address
	if mm.RegionName(0) != "invalid" {
		t.Errorf("expected invalid region for address 0")
	}
}

func TestHeapAllocation(t *testing.T) {
	program := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	mm := NewMemoryMap(program, nil)

	// Allocate 100 bytes
	addr1, err := mm.Alloc(100, 8)
	if err != nil {
		t.Fatalf("Alloc failed: %v", err)
	}
	if addr1 != HeapStart {
		t.Errorf("expected allocation at HeapStart, got 0x%x", addr1)
	}

	// Allocate another 100 bytes
	addr2, err := mm.Alloc(100, 8)
	if err != nil {
		t.Fatalf("Alloc failed: %v", err)
	}
	if addr2 <= addr1 {
		t.Errorf("expected addr2 > addr1, got addr2=0x%x, addr1=0x%x", addr2, addr1)
	}
}

func TestVMError(t *testing.T) {
	err := NewVMError(ErrDivisionByZero, 42, DIV64_IMM, 0)

	if !errors.Is(err, ErrDivisionByZero) {
		t.Error("VMError.Is failed")
	}

	unwrapped := errors.Unwrap(err)
	if unwrapped != ErrDivisionByZero {
		t.Error("VMError.Unwrap failed")
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("VMError.Error returned empty string")
	}
}

func BenchmarkSimpleProgram(b *testing.B) {
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 42),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	for i := 0; i < b.N; i++ {
		vm, _ := NewVM(program, 1000)
		vm.Run(nil)
	}
}

func BenchmarkLoop(b *testing.B) {
	// Loop 100 times: mov r0, 0; mov r1, 100; loop: add r0, 1; sub r1, 1; jne r1, 0, loop; exit
	program := makeProgram(
		encodeInstruction(MOV64_IMM, R0, 0, 0, 0),
		encodeInstruction(MOV64_IMM, R1, 0, 0, 100),
		encodeInstruction(ADD64_IMM, R0, 0, 0, 1),
		encodeInstruction(SUB64_IMM, R1, 0, 0, 1),
		encodeInstruction(JNE_IMM, R1, 0, -3, 0),
		encodeInstruction(EXIT, 0, 0, 0, 0),
	)

	for i := 0; i < b.N; i++ {
		vm, _ := NewVM(program, 10000)
		vm.Run(nil)
	}
}
