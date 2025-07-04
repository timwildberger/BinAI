import re

from tokenizer.tokens import Tokens


def parse_instruction_to_tokens(
        ins_dict,
        renamed_value_constants,
        value_constant_literals,
        opaque_constants,
        opaque_constant_literals,
        mnemonics,
        inv_prefix_tokens,
        symbol_tokens,
        func_addr_range: list,
) -> list[Tokens]:
    """
    Tokenizes a single instruction dictionary into TokensRepl objects.

    Args:
        ins_dict: Instruction dictionary with mnemonic, operands, and prefixes
        renamed_value_constants: dict mapping addresses to token objects
        value_constant_literals: dict mapping addresses to token objects
        opaque_constants: dict mapping addresses to token names
        opaque_constant_literals: dict mapping addresses to token names
        mnemonics: dict of mnemonic -> token objects
        symbol_tokens: dict of symbol -> token objects
        func_addr_range: list of function address ranges

    Returns:
        list[Tokens]: List of token objects for this instruction
    """
    SIZE_SPECIFIERS = {
        "byte": "x86_BYTE_PTR",
        "word": "x86_WORD_PTR",
        "dword": "x86_DWORD_PTR",
        "qword": "x86_QWORD_PTR",
        "xmmword": "x86_YMMWORD_PTR",
        "ymmword": "x86_YMMWORD_PTR",
        "zmmword": "x86_ZMMWORD_PTR",
        "tmmword": "x86_ZMMWORD_PTR",
    }

    mnemonic = ins_dict[0]
    op_str = ins_dict[1]
    prefixes = ins_dict[2]

    tokens = []

    # Add mnemonic token
    if mnemonic in mnemonics:
        tokens.append(mnemonics[mnemonic])
    else:
        raise ValueError(f"Mnemonic {mnemonic} has not been registered.")

    # Handle operands
    if op_str:
        operand = op_str.split(", ")

        for i in range(len(operand)):
            current_operand = operand[i]

            # Handle ljmp-style segment:offset operands
            if ":" in current_operand and all(part.startswith("0x") for part in current_operand.split(":")):
                segment, offset = current_operand.split(":")

                try:
                    seg_token = resolve_constant_to_token(
                        segment,
                        renamed_value_constants,
                        value_constant_literals,
                        opaque_constants,
                        opaque_constant_literals,
                        func_addr_range,
                    )
                    off_token = resolve_constant_to_token(
                        offset,
                        renamed_value_constants,
                        value_constant_literals,
                        opaque_constants,
                        opaque_constant_literals,
                        func_addr_range,
                    )
                except:
                    print(f"{mnemonic}, {op_str}")
                    raise ValueError

                tokens.append(seg_token)
                # Add colon - for now skip or handle as needed
                tokens.append(off_token)
                continue

            symbols = re.split(r"([0-9A-Za-z_:]+)", operand[i])
            symbols = [s.strip() for s in symbols if s]

            for s in symbols:
                if s.lower() == "ptr" or s.lower() in inv_prefix_tokens.values():
                    continue  # skip ptr entirely

                if s.startswith("0x"):  # hex constants
                    try:
                        const_token = resolve_constant_to_token(
                            s,
                            renamed_value_constants,
                            value_constant_literals,
                            opaque_constants,
                            opaque_constant_literals,
                            func_addr_range,
                        )
                        tokens.append(const_token)
                    except:
                        print(f"{mnemonic}, {op_str}")
                        raise ValueError

                elif s.isdigit():  # byte constants
                    try:
                        const_token = resolve_constant_to_token(
                            hex(int(s)),
                            renamed_value_constants,
                            value_constant_literals,
                            opaque_constants,
                            opaque_constant_literals,
                            func_addr_range,
                        )
                        tokens.append(const_token)
                    except:
                        print(f"{mnemonic}, {op_str}")
                        raise ValueError

                elif s in SIZE_SPECIFIERS.keys():
                    # Register size specifier as token (assuming it's registered)
                    # For now, skip or handle as needed
                    pass

                elif s in symbol_tokens:
                    tokens.append(symbol_tokens[s])
                else:
                    # Handle unknown symbols - for now skip or add as needed
                    pass

    return tokens


def resolve_constant_to_token(
        s,
        renamed_value_constants,
        value_constant_literals,
        opaque_constants,
        opaque_constant_literals,
        func_addr_range: list,
) -> Tokens:
    """
    Returns a TokensRepl object for a constant value.

    Returns:
        Tokens: Token object for the constant
    """
    # Check function address ranges first
    for element in func_addr_range:
        for block_token, bounds in element.items():
            try:
                if int(bounds[0], 16) <= int(s, 16) < int(bounds[1], 16):
                    return block_token
            except:
                continue

    # Check value constants
    if s in renamed_value_constants:
        token_obj, _ = renamed_value_constants[s]
        return token_obj

    # Check value constant literals
    if s in value_constant_literals:
        token_obj, _ = value_constant_literals[s]
        return token_obj

    # Check opaque constants
    if s in opaque_constants:
        token_obj, _ = opaque_constants[s]
        return token_obj

    # Check opaque constant literals
    if s in opaque_constant_literals:
        token_obj, _ = opaque_constant_literals[s]
        return token_obj

    # Fallback - unknown constant
    raise ValueError(f"Unknown constant: {s}")
