import warnings

from tokenizer.constant_handler import ConstantHandler
from typing import List

from tokenizer.tokens import Tokens, MemoryOperandSymbol
from tokenizer.token_manager import VocabularyManager


def _register_registry_token(reg_id: int, insn, vocab_manager) -> Tokens:
    """Helper method to register a register token if it doesn't exist."""
    if reg_id != 0:
        reg_name = insn.reg_name(reg_id)
        if reg_name not in symbol_tokens:
            symbol_tokens[reg_name] = vocab_manager.PlatformToken(reg_name)


size_map = {
    1: "byte_ptr",
    2: "word_ptr",
    4: "dword_ptr",
    8: "qword_ptr",
   10: "xword_ptr",        # x87 extended precision (80-bit)
   14: "fpu_env_ptr",      # x87 environment (16-bit mode)
   16: "xmmword_ptr",
   28: "fpu_env_ptr",      # x87 environment (32-bit mode) - ADD THIS
   32: "ymmword_ptr",
   64: "zmmword_ptr",
   94: "fpu_state_ptr",    # x87 state (16-bit mode)
   108: "fpu_state_ptr",   # x87 state (32-bit mode)
}

segment_prefixes = {
    0x26: "es:",
    0x2E: "cs:",
    0x36: "ss:",
    0x3E: "ds:",
    0x64: "fs:",
    0x65: "gs:"
}

def tokenize_operand_memory(insn, lookup, op, text_end, text_start,
                           func_max_addr, func_min_addr, vocab_manager: VocabularyManager,
                           constant_handler: ConstantHandler) -> List[Tokens]:
    """
    Tokenize memory operand and return list of tokens.

    Returns:
        List of TokensRepl objects for this memory operand
    """
    tokens = []

    disp = op.mem.disp



    scale = op.mem.scale
    base = op.mem.base
    index = op.mem.index

    has_reg = op.mem.base != 0
    has_index = op.mem.index != 0
    has_disp = op.mem.disp != 0

    if op.size in size_map:
        tokens.append(vocab_manager.PlatformToken(size_map[op.size]))
    else:
        # Find the next bigger size in size_map or take the largest available
        next_size = min((s for s in size_map if s > op.size), default=max(size_map))
        tokens.append(vocab_manager.PlatformToken(size_map[next_size]))
        warnings.warn(f"unexpected memory operand size: {op.size}, using next bigger '{size_map[next_size]}' at {next_size}bytes for instruction {insn}")


    if op.mem.segment > 0:
        tokens.append(vocab_manager.PlatformToken(f"{insn.reg_name(op.mem.segment)}:"))

    tokens.append(vocab_manager.MemoryOperand(MemoryOperandSymbol.OPEN_BRACKET))

    # Register the base and index registers
    if has_reg:
        tokens.append(vocab_manager.get_registry_token(insn, base))

    if has_index:
        if has_reg:
            tokens.append(vocab_manager.MemoryOperand(MemoryOperandSymbol.PLUS))

        tokens.append(vocab_manager.get_registry_token(insn, index))

    # Process scale as a constant if in expected range
    if scale != 1:
        assert scale > 0
        if has_index:
            tokens.append(vocab_manager.MemoryOperand(MemoryOperandSymbol.MULTIPLY))
            tokens.append(vocab_manager.Valued_Const(abs(scale)))
        else:
            warnings.warn(f"Scale {scale} used without index register in instruction {insn}")


    if disp < 0:
        tokens.append(vocab_manager.MemoryOperand(MemoryOperandSymbol.MINUS))
    elif has_disp and (has_reg or has_index):
        tokens.append(vocab_manager.MemoryOperand(MemoryOperandSymbol.PLUS))


    # Process displacement
    if not has_disp:
        1 # noop ignore
    elif disp <= 0xFF: # if we are in range 00 to 0xFF we always use constant, same if we are negative as its defo not an addr
        tokens.append(vocab_manager.Valued_Const(abs(disp)))

    else:
        # For larger displacements, check if pointing to known constant or code or opaque
        meta, kind = lookup.lookup(disp)
        if meta is not None:
            # Check if displacement is in text section or outside function bounds
            if (text_start <= disp < text_end) or (disp < func_min_addr or disp > func_max_addr):
                disp_token = constant_handler.process_constant(
                    hex(disp),
                    is_arithmetic=False,
                    meta=meta,
                    library_type=meta.get("library", "unknown")
                )
                tokens.append(disp_token)
            else:
                # Local constant - treat as valued constant literal
                disp_token = constant_handler.process_constant(hex(disp), is_arithmetic=True)
                tokens.append(disp_token)
        else:
            # No metadata found - treat as valued constant literal
            disp_token = constant_handler.process_constant(hex(disp), is_arithmetic=True)
            tokens.append(disp_token)


    tokens.append(vocab_manager.MemoryOperand(MemoryOperandSymbol.CLOSE_BRACKET))

    return tokens


def tokenize_operand_immediate(addressing_control_flow_instructions, arithmetic_instructions,
                              insn, lookup, op, func_max_addr, func_min_addr,
                              constant_handler: ConstantHandler) -> List[Tokens]:
    """
    Tokenize immediate operand and return list of tokens.

    Returns:
        List of TokensRepl objects for this immediate operand
    """
    tokens = []

    imm_val = abs(op.imm)
    imm_val_hex = hex(imm_val)

    if len(imm_val_hex[2:]) <= 2:  # Small immediate (0x00 to 0xFF)
        imm_token = constant_handler.process_constant(imm_val_hex)
        tokens.append(imm_token)
    elif len(imm_val_hex[2:]) <= (128 / 4):  # Larger immediate (up to 128-bit)
        if insn.mnemonic in arithmetic_instructions:
            # Arithmetic instruction - treat as valued constant literal
            imm_token = constant_handler.process_constant(imm_val_hex, is_arithmetic=True)
            tokens.append(imm_token)
        elif insn.mnemonic in addressing_control_flow_instructions:
            # Addressing/control flow instruction - check for metadata
            meta, kind = lookup.lookup(imm_val)
            if meta is not None:
                if kind == "range":
                    if func_min_addr <= imm_val < func_max_addr:  # Local
                        imm_token = constant_handler.process_constant(imm_val_hex, is_arithmetic=True)
                        tokens.append(imm_token)
                    else:  # External
                        imm_token = constant_handler.process_constant(
                            imm_val_hex,
                            is_arithmetic=False,
                            meta=meta,
                            library_type="function"
                        )
                        tokens.append(imm_token)
                else:
                    imm_token = constant_handler.process_constant(
                        imm_val_hex,
                        is_arithmetic=False,
                        meta=meta,
                        library_type="unknown"
                    )
                    tokens.append(imm_token)
            else:
                # No metadata - treat as valued constant literal
                imm_token = constant_handler.process_constant(imm_val_hex, is_arithmetic=True)
                tokens.append(imm_token)
        else:  # Fallback - create opaque constant
            meta, kind = lookup.lookup(imm_val)
            if meta is None:
                # Default/fallback meta if lookup fails
                meta = {
                    "start_addr": imm_val,
                    "end_addr": imm_val,
                    "name": "unknown",
                    "type": "unknown",
                    "library": "unknown",
                }
            imm_token = constant_handler.process_constant(
                imm_val_hex,
                is_arithmetic=False,
                meta=meta,
                library_type="unknown"
            )
            tokens.append(imm_token)

    return tokens
