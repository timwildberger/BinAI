# Tokenizer notes


python3 -m tokenizer.low_level 

Operand types: (in theory)
0: Register         mov eax, ebx          ; reg (eax), reg (ebx)        => operands are registers (type 0)
1: Immediate        add eax, 5            ; reg (eax), imm (5)           => one register, one immediate (type 1)
2: Memory           mov eax, [ebx + 4]    ; reg (eax), mem ([ebx+4])    => register and memory operand (type 2)
3: FloatingPoint    fld qword ptr [esp]   ; floating point load from mem => mem (type 2) with floating point semantics (type 3)

Operand types (inferred from code due to terrible documentation from angr)
1: Register
2: Immediate
3: Memory

Classifies:
- ValueConstants: 0x00 to 0xFF
- ValueConstantLiterals: larger static values (up to 128-bit)
- OpaqueConstants: memory references using base registers or unresolved values
- OpaqueConstantLiterals: overflow beyond the first 16 unique opaque constants


Opaque Const Metadaten:
0: {type: Local function, name: fibonacci}
1: {type: String, value: "Hello World I love u"}
2: {type: Library function, name: read_file, library: libc}
3: {type: Library function, name: close_file, library: libc}