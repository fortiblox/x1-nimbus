package sbpf

// sBPF instruction format:
// +------------------------+----------------+------+------+--------+
// |         imm (32)       |   offset (16)  | src  | dst  | opcode |
// +------------------------+----------------+------+------+--------+
// MSB                                                           LSB

// Instruction classes (lower 3 bits of opcode)
const (
	ClassLD   = 0x00 // Load (immediate)
	ClassLDX  = 0x01 // Load (from memory)
	ClassST   = 0x02 // Store (immediate)
	ClassSTX  = 0x03 // Store (from register)
	ClassALU  = 0x04 // ALU 32-bit
	ClassJMP  = 0x05 // Jump
	ClassJMP32 = 0x06 // Jump 32-bit
	ClassALU64 = 0x07 // ALU 64-bit
)

// ALU operations (upper 4 bits of opcode)
const (
	AluAdd  = 0x00
	AluSub  = 0x10
	AluMul  = 0x20
	AluDiv  = 0x30
	AluOr   = 0x40
	AluAnd  = 0x50
	AluLsh  = 0x60
	AluRsh  = 0x70
	AluNeg  = 0x80
	AluMod  = 0x90
	AluXor  = 0xa0
	AluMov  = 0xb0
	AluArsh = 0xc0
	AluEnd  = 0xd0 // Endianness conversion
)

// Source modifiers
const (
	SrcImm = 0x00 // Use immediate value
	SrcReg = 0x08 // Use source register
)

// Memory sizes
const (
	SizeW  = 0x00 // Word (4 bytes)
	SizeH  = 0x08 // Half-word (2 bytes)
	SizeB  = 0x10 // Byte
	SizeDW = 0x18 // Double-word (8 bytes)
)

// Jump operations (upper 4 bits of opcode)
const (
	JmpJA   = 0x00 // Jump always
	JmpJEQ  = 0x10 // Jump if equal
	JmpJGT  = 0x20 // Jump if greater than (unsigned)
	JmpJGE  = 0x30 // Jump if greater or equal (unsigned)
	JmpJSET = 0x40 // Jump if set (bitwise AND)
	JmpJNE  = 0x50 // Jump if not equal
	JmpJSGT = 0x60 // Jump if signed greater than
	JmpJSGE = 0x70 // Jump if signed greater or equal
	JmpCALL = 0x80 // Call
	JmpEXIT = 0x90 // Exit
	JmpJLT  = 0xa0 // Jump if less than (unsigned)
	JmpJLE  = 0xb0 // Jump if less or equal (unsigned)
	JmpJSLT = 0xc0 // Jump if signed less than
	JmpJSLE = 0xd0 // Jump if signed less or equal
)

// Full opcodes (class + operation + source/size)
const (
	// ALU64 operations with immediate
	ADD64_IMM  = ClassALU64 | AluAdd | SrcImm  // 0x07
	SUB64_IMM  = ClassALU64 | AluSub | SrcImm  // 0x17
	MUL64_IMM  = ClassALU64 | AluMul | SrcImm  // 0x27
	DIV64_IMM  = ClassALU64 | AluDiv | SrcImm  // 0x37
	OR64_IMM   = ClassALU64 | AluOr | SrcImm   // 0x47
	AND64_IMM  = ClassALU64 | AluAnd | SrcImm  // 0x57
	LSH64_IMM  = ClassALU64 | AluLsh | SrcImm  // 0x67
	RSH64_IMM  = ClassALU64 | AluRsh | SrcImm  // 0x77
	NEG64      = ClassALU64 | AluNeg | SrcImm  // 0x87
	MOD64_IMM  = ClassALU64 | AluMod | SrcImm  // 0x97
	XOR64_IMM  = ClassALU64 | AluXor | SrcImm  // 0xa7
	MOV64_IMM  = ClassALU64 | AluMov | SrcImm  // 0xb7
	ARSH64_IMM = ClassALU64 | AluArsh | SrcImm // 0xc7

	// ALU64 operations with register
	ADD64_REG  = ClassALU64 | AluAdd | SrcReg  // 0x0f
	SUB64_REG  = ClassALU64 | AluSub | SrcReg  // 0x1f
	MUL64_REG  = ClassALU64 | AluMul | SrcReg  // 0x2f
	DIV64_REG  = ClassALU64 | AluDiv | SrcReg  // 0x3f
	OR64_REG   = ClassALU64 | AluOr | SrcReg   // 0x4f
	AND64_REG  = ClassALU64 | AluAnd | SrcReg  // 0x5f
	LSH64_REG  = ClassALU64 | AluLsh | SrcReg  // 0x6f
	RSH64_REG  = ClassALU64 | AluRsh | SrcReg  // 0x7f
	MOD64_REG  = ClassALU64 | AluMod | SrcReg  // 0x9f
	XOR64_REG  = ClassALU64 | AluXor | SrcReg  // 0xaf
	MOV64_REG  = ClassALU64 | AluMov | SrcReg  // 0xbf
	ARSH64_REG = ClassALU64 | AluArsh | SrcReg // 0xcf

	// ALU32 operations with immediate
	ADD32_IMM  = ClassALU | AluAdd | SrcImm  // 0x04
	SUB32_IMM  = ClassALU | AluSub | SrcImm  // 0x14
	MUL32_IMM  = ClassALU | AluMul | SrcImm  // 0x24
	DIV32_IMM  = ClassALU | AluDiv | SrcImm  // 0x34
	OR32_IMM   = ClassALU | AluOr | SrcImm   // 0x44
	AND32_IMM  = ClassALU | AluAnd | SrcImm  // 0x54
	LSH32_IMM  = ClassALU | AluLsh | SrcImm  // 0x64
	RSH32_IMM  = ClassALU | AluRsh | SrcImm  // 0x74
	NEG32      = ClassALU | AluNeg | SrcImm  // 0x84
	MOD32_IMM  = ClassALU | AluMod | SrcImm  // 0x94
	XOR32_IMM  = ClassALU | AluXor | SrcImm  // 0xa4
	MOV32_IMM  = ClassALU | AluMov | SrcImm  // 0xb4
	ARSH32_IMM = ClassALU | AluArsh | SrcImm // 0xc4

	// ALU32 operations with register
	ADD32_REG  = ClassALU | AluAdd | SrcReg  // 0x0c
	SUB32_REG  = ClassALU | AluSub | SrcReg  // 0x1c
	MUL32_REG  = ClassALU | AluMul | SrcReg  // 0x2c
	DIV32_REG  = ClassALU | AluDiv | SrcReg  // 0x3c
	OR32_REG   = ClassALU | AluOr | SrcReg   // 0x4c
	AND32_REG  = ClassALU | AluAnd | SrcReg  // 0x5c
	LSH32_REG  = ClassALU | AluLsh | SrcReg  // 0x6c
	RSH32_REG  = ClassALU | AluRsh | SrcReg  // 0x7c
	MOD32_REG  = ClassALU | AluMod | SrcReg  // 0x9c
	XOR32_REG  = ClassALU | AluXor | SrcReg  // 0xac
	MOV32_REG  = ClassALU | AluMov | SrcReg  // 0xbc
	ARSH32_REG = ClassALU | AluArsh | SrcReg // 0xcc

	// Endianness conversions
	LE = ClassALU | AluEnd | SrcImm  // 0xd4 - Little endian
	BE = ClassALU | AluEnd | SrcReg  // 0xdc - Big endian

	// Memory load operations (LDX)
	LDXB  = ClassLDX | SizeB  // 0x71 - Load byte
	LDXH  = ClassLDX | SizeH  // 0x69 - Load half-word
	LDXW  = ClassLDX | SizeW  // 0x61 - Load word
	LDXDW = ClassLDX | SizeDW // 0x79 - Load double-word

	// Memory store operations with immediate (ST)
	STB  = ClassST | SizeB  // 0x72 - Store byte
	STH  = ClassST | SizeH  // 0x6a - Store half-word
	STW  = ClassST | SizeW  // 0x62 - Store word
	STDW = ClassST | SizeDW // 0x7a - Store double-word

	// Memory store operations with register (STX)
	STXB  = ClassSTX | SizeB  // 0x73 - Store byte
	STXH  = ClassSTX | SizeH  // 0x6b - Store half-word
	STXW  = ClassSTX | SizeW  // 0x63 - Store word
	STXDW = ClassSTX | SizeDW // 0x7b - Store double-word

	// Load double-word immediate (uses two instructions)
	LDDW = ClassLD | SizeDW // 0x18 - Load 64-bit immediate

	// Jump operations with immediate
	JA       = ClassJMP | JmpJA              // 0x05 - Jump always
	JEQ_IMM  = ClassJMP | JmpJEQ | SrcImm    // 0x15 - Jump if equal
	JGT_IMM  = ClassJMP | JmpJGT | SrcImm    // 0x25 - Jump if greater (unsigned)
	JGE_IMM  = ClassJMP | JmpJGE | SrcImm    // 0x35 - Jump if greater or equal (unsigned)
	JSET_IMM = ClassJMP | JmpJSET | SrcImm   // 0x45 - Jump if set
	JNE_IMM  = ClassJMP | JmpJNE | SrcImm    // 0x55 - Jump if not equal
	JSGT_IMM = ClassJMP | JmpJSGT | SrcImm   // 0x65 - Jump if signed greater
	JSGE_IMM = ClassJMP | JmpJSGE | SrcImm   // 0x75 - Jump if signed greater or equal
	JLT_IMM  = ClassJMP | JmpJLT | SrcImm    // 0xa5 - Jump if less (unsigned)
	JLE_IMM  = ClassJMP | JmpJLE | SrcImm    // 0xb5 - Jump if less or equal (unsigned)
	JSLT_IMM = ClassJMP | JmpJSLT | SrcImm   // 0xc5 - Jump if signed less
	JSLE_IMM = ClassJMP | JmpJSLE | SrcImm   // 0xd5 - Jump if signed less or equal

	// Jump operations with register
	JEQ_REG  = ClassJMP | JmpJEQ | SrcReg    // 0x1d - Jump if equal
	JGT_REG  = ClassJMP | JmpJGT | SrcReg    // 0x2d - Jump if greater (unsigned)
	JGE_REG  = ClassJMP | JmpJGE | SrcReg    // 0x3d - Jump if greater or equal (unsigned)
	JSET_REG = ClassJMP | JmpJSET | SrcReg   // 0x4d - Jump if set
	JNE_REG  = ClassJMP | JmpJNE | SrcReg    // 0x5d - Jump if not equal
	JSGT_REG = ClassJMP | JmpJSGT | SrcReg   // 0x6d - Jump if signed greater
	JSGE_REG = ClassJMP | JmpJSGE | SrcReg   // 0x7d - Jump if signed greater or equal
	JLT_REG  = ClassJMP | JmpJLT | SrcReg    // 0xad - Jump if less (unsigned)
	JLE_REG  = ClassJMP | JmpJLE | SrcReg    // 0xbd - Jump if less or equal (unsigned)
	JSLT_REG = ClassJMP | JmpJSLT | SrcReg   // 0xcd - Jump if signed less
	JSLE_REG = ClassJMP | JmpJSLE | SrcReg   // 0xdd - Jump if signed less or equal

	// Call and exit
	CALL = ClassJMP | JmpCALL // 0x85 - Call function/syscall
	EXIT = ClassJMP | JmpEXIT // 0x95 - Exit program
)

// Register indices
const (
	R0  = 0  // Return value / scratch
	R1  = 1  // Argument 1
	R2  = 2  // Argument 2
	R3  = 3  // Argument 3
	R4  = 4  // Argument 4
	R5  = 5  // Argument 5
	R6  = 6  // Callee-saved
	R7  = 7  // Callee-saved
	R8  = 8  // Callee-saved
	R9  = 9  // Callee-saved
	R10 = 10 // Frame pointer (read-only)
)

// Instruction represents a decoded sBPF instruction.
type Instruction struct {
	Opcode uint8  // Operation code
	Dst    uint8  // Destination register (0-10)
	Src    uint8  // Source register (0-10)
	Offset int16  // Signed offset (for memory/jumps)
	Imm    int32  // Signed immediate value
}

// InstructionSize is the size of a single instruction in bytes.
const InstructionSize = 8

// DecodeInstruction decodes an 8-byte instruction.
func DecodeInstruction(data []byte) Instruction {
	if len(data) < InstructionSize {
		return Instruction{}
	}

	return Instruction{
		Opcode: data[0],
		Dst:    data[1] & 0x0f,
		Src:    (data[1] >> 4) & 0x0f,
		Offset: int16(uint16(data[2]) | uint16(data[3])<<8),
		Imm:    int32(uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24),
	}
}

// Class returns the instruction class.
func (i Instruction) Class() uint8 {
	return i.Opcode & 0x07
}

// IsALU returns true if this is an ALU instruction.
func (i Instruction) IsALU() bool {
	class := i.Class()
	return class == ClassALU || class == ClassALU64
}

// IsALU64 returns true if this is a 64-bit ALU instruction.
func (i Instruction) IsALU64() bool {
	return i.Class() == ClassALU64
}

// IsJump returns true if this is a jump instruction.
func (i Instruction) IsJump() bool {
	class := i.Class()
	return class == ClassJMP || class == ClassJMP32
}

// IsMemory returns true if this is a memory instruction.
func (i Instruction) IsMemory() bool {
	class := i.Class()
	return class == ClassLD || class == ClassLDX || class == ClassST || class == ClassSTX
}

// IsLoad returns true if this is a load instruction.
func (i Instruction) IsLoad() bool {
	class := i.Class()
	return class == ClassLD || class == ClassLDX
}

// IsStore returns true if this is a store instruction.
func (i Instruction) IsStore() bool {
	class := i.Class()
	return class == ClassST || class == ClassSTX
}

// UsesImmediate returns true if the instruction uses an immediate value.
func (i Instruction) UsesImmediate() bool {
	return (i.Opcode & SrcReg) == 0
}

// MemorySize returns the size of the memory access in bytes.
func (i Instruction) MemorySize() int {
	size := i.Opcode & 0x18
	switch size {
	case SizeB:
		return 1
	case SizeH:
		return 2
	case SizeW:
		return 4
	case SizeDW:
		return 8
	default:
		return 0
	}
}

// OpcodeString returns a human-readable name for the opcode.
func OpcodeString(opcode uint8) string {
	switch opcode {
	// ALU64 immediate
	case ADD64_IMM:
		return "ADD64_IMM"
	case SUB64_IMM:
		return "SUB64_IMM"
	case MUL64_IMM:
		return "MUL64_IMM"
	case DIV64_IMM:
		return "DIV64_IMM"
	case OR64_IMM:
		return "OR64_IMM"
	case AND64_IMM:
		return "AND64_IMM"
	case LSH64_IMM:
		return "LSH64_IMM"
	case RSH64_IMM:
		return "RSH64_IMM"
	case NEG64:
		return "NEG64"
	case MOD64_IMM:
		return "MOD64_IMM"
	case XOR64_IMM:
		return "XOR64_IMM"
	case MOV64_IMM:
		return "MOV64_IMM"
	case ARSH64_IMM:
		return "ARSH64_IMM"

	// ALU64 register
	case ADD64_REG:
		return "ADD64_REG"
	case SUB64_REG:
		return "SUB64_REG"
	case MUL64_REG:
		return "MUL64_REG"
	case DIV64_REG:
		return "DIV64_REG"
	case OR64_REG:
		return "OR64_REG"
	case AND64_REG:
		return "AND64_REG"
	case LSH64_REG:
		return "LSH64_REG"
	case RSH64_REG:
		return "RSH64_REG"
	case MOD64_REG:
		return "MOD64_REG"
	case XOR64_REG:
		return "XOR64_REG"
	case MOV64_REG:
		return "MOV64_REG"
	case ARSH64_REG:
		return "ARSH64_REG"

	// ALU32 immediate
	case ADD32_IMM:
		return "ADD32_IMM"
	case SUB32_IMM:
		return "SUB32_IMM"
	case MUL32_IMM:
		return "MUL32_IMM"
	case DIV32_IMM:
		return "DIV32_IMM"
	case OR32_IMM:
		return "OR32_IMM"
	case AND32_IMM:
		return "AND32_IMM"
	case LSH32_IMM:
		return "LSH32_IMM"
	case RSH32_IMM:
		return "RSH32_IMM"
	case NEG32:
		return "NEG32"
	case MOD32_IMM:
		return "MOD32_IMM"
	case XOR32_IMM:
		return "XOR32_IMM"
	case MOV32_IMM:
		return "MOV32_IMM"
	case ARSH32_IMM:
		return "ARSH32_IMM"

	// ALU32 register
	case ADD32_REG:
		return "ADD32_REG"
	case SUB32_REG:
		return "SUB32_REG"
	case MUL32_REG:
		return "MUL32_REG"
	case DIV32_REG:
		return "DIV32_REG"
	case OR32_REG:
		return "OR32_REG"
	case AND32_REG:
		return "AND32_REG"
	case LSH32_REG:
		return "LSH32_REG"
	case RSH32_REG:
		return "RSH32_REG"
	case MOD32_REG:
		return "MOD32_REG"
	case XOR32_REG:
		return "XOR32_REG"
	case MOV32_REG:
		return "MOV32_REG"
	case ARSH32_REG:
		return "ARSH32_REG"

	// Memory load
	case LDXB:
		return "LDXB"
	case LDXH:
		return "LDXH"
	case LDXW:
		return "LDXW"
	case LDXDW:
		return "LDXDW"
	case LDDW:
		return "LDDW"

	// Memory store immediate
	case STB:
		return "STB"
	case STH:
		return "STH"
	case STW:
		return "STW"
	case STDW:
		return "STDW"

	// Memory store register
	case STXB:
		return "STXB"
	case STXH:
		return "STXH"
	case STXW:
		return "STXW"
	case STXDW:
		return "STXDW"

	// Jump immediate
	case JA:
		return "JA"
	case JEQ_IMM:
		return "JEQ_IMM"
	case JGT_IMM:
		return "JGT_IMM"
	case JGE_IMM:
		return "JGE_IMM"
	case JSET_IMM:
		return "JSET_IMM"
	case JNE_IMM:
		return "JNE_IMM"
	case JSGT_IMM:
		return "JSGT_IMM"
	case JSGE_IMM:
		return "JSGE_IMM"
	case JLT_IMM:
		return "JLT_IMM"
	case JLE_IMM:
		return "JLE_IMM"
	case JSLT_IMM:
		return "JSLT_IMM"
	case JSLE_IMM:
		return "JSLE_IMM"

	// Jump register
	case JEQ_REG:
		return "JEQ_REG"
	case JGT_REG:
		return "JGT_REG"
	case JGE_REG:
		return "JGE_REG"
	case JSET_REG:
		return "JSET_REG"
	case JNE_REG:
		return "JNE_REG"
	case JSGT_REG:
		return "JSGT_REG"
	case JSGE_REG:
		return "JSGE_REG"
	case JLT_REG:
		return "JLT_REG"
	case JLE_REG:
		return "JLE_REG"
	case JSLT_REG:
		return "JSLT_REG"
	case JSLE_REG:
		return "JSLE_REG"

	// Call and exit
	case CALL:
		return "CALL"
	case EXIT:
		return "EXIT"

	// Endianness
	case LE:
		return "LE"
	case BE:
		return "BE"

	default:
		return "UNKNOWN"
	}
}
