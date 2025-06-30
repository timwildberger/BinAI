import angr
import re
import csv, json
from pathlib import Path
from address_meta_data_lookup import AddressMetaDataLookup
from compact_base64_utils import ndarray_to_base64
from utils import register_name_range, register_value_in_dict, mnemonic_to_token
from typing import Union, Optional
import numpy as np

"""
Blöcke 0 bis 16:
Block0, Block1, ..., BlockF

Ab 16:
BlockLitStart
BlockLit1
BlockLit0
BlockLitEnd

e.g. Block 257
BlockLitStart
BlockLit1
BlockLit0
BlockLit1
BlockLitEnd

Konstanten:
1. ValueConstants (00 to FF representing a constant of exactly that value)
2. ValueConstantLiterals (for up to 128 Bit values)
3. OpaqueConstants (16 uniqe - they represent an opaque value basically: e.g. the representation of the string "HelloWorld")
4. OpaqueConstantLiterals (if a function needs more than 16 Opaque Literals)
"""


def extract_ldis_blocks_from_file(file_path):
    """
    Reads a structured CSV-like file and extracts disassembly blocks from <LDIS> tags.
    Returns a dict: function_name -> list of disassembled blocks.
    """
    file_path = Path(file_path)
    result = {}

    with file_path.open(encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 4:
                continue

            funcname = row[0]
            ldis_field = row[3]

            # Extract content between <LDIS> and </LDIS>
            match = re.search(r"<LDIS>(.*?)</LDIS>", ldis_field, flags=re.DOTALL)
            if match:
                ldis_text = match.group(1).strip()
                # Optional: split blocks if separated by "|"
                blocks = [b.strip() for b in ldis_text.split("|")]
                result[funcname] = blocks
    return result


def fill_constant_candidates(
    func_name: str,
    func_addr: int,
    func: angr.knowledge_plugins.functions.function.Function,
    arithmetic_instructions: set[str],
    addressing_control_flow_instructions: set[str],
    inv_prefix_tokens: dict[str, str],
    constant_dict: dict[str, list[str]],
    opaque_const_meta: dict[str, list[str]],
    opaque_const_meta_list,
    lookup: AddressMetaDataLookup,
    text_start: int,
    text_end: int,
) -> Optional[
    tuple[
        dict[str, int],
        dict[str, int],
        dict[str, int],
        list[dict[str, list[list[Union[str, list[str]]]]]],
        list[dict],
        dict[str, str],
        dict[str, str],
        dict[str, str],
    ]
]:
    """
    Assigns all operands for a given function to datastructures that are used to determine the token type.

    Args:
        func_name (str): Name of the function
        func_addr (int): Integer value of the function's start address
        func (angr.knowledge_plugins.functions.function.Function): angr function object to be analyzed
        arithmetic_instructions (set): Set of all arithmetic instruction. Used to indicate non-opaque constants.
        addressing_control_flow_instructions (set): Set of all instruction that indicate memory operations or controlflow. Used to indicate opaque constants.
        inv_prefix_tokens (dict[str, str]): Maps the hex value of all possible decorators to their intended meaning.
        constant_dict (dict[str, list[str]]): Stores all constants from .rodata
        opaque_const_meta (dict[str, list[str]]): Stores all available metadata for any opaque value.
        lookup (AddressMetaDataLookup): lookupObject to quickly parse function libraries to populate opaque_const_meta
        text_start (int): Start address of the .text section
        text_end (int): End address of the .text section"""

    func_min_addr: int = int(func_addr)
    func_max_addr: int = 0

    if func_name in ["UnresolvableCallTarget", "UnresolvableJumpTarget"]:
        return None

    disassembly_list: list[list[Union[str, list[str]]]] = []
    blocks: set = set()

    value_constants: dict[str, int] = {}
    value_constant_literals_candidates: dict[str, int] = {}
    opaque_candidates: dict[str, int] = {}

    temp_bbs: list[dict[str, list[list[Union[str, list[str]]]]]] = []
    block_list: list[dict[str, tuple[str, str]]] = []

    mnemonics: dict[str, str] = {}
    symbol_tokens: dict[str, str] = {}

    block_dict: dict[str, str] = {}  # hex value of Block address: block_name

    block_counter: int = 0
    for block in func.blocks:
        func_max_addr = max(func_min_addr, block.addr + block.size)

        # ------------------Register name of current Block---------------------
        if block_counter < 16:
            block_name =  f"Block_{str(hex(block_counter)[2:]).upper()}"
        else:
            block_name = register_name_range(block_counter, basename="Block")
        block_list.append(
            {
                block_name: (
                    hex(func_min_addr),
                    hex(func_max_addr),
                )
            }
        )
        blocks.add(hex(block.addr))

        if block.capstone.insns is None:
            print("KAPUTT")
        block_addr = hex(block.addr)
        block_dict[block_addr] = block_name

        disassembly_list = []

        # Single loop over instructions to get both disassembly and immediates
        for insn in block.capstone.insns:
            # Extract non-zero prefixes (up to 4 bytes)
            prefix_bytes = [f"0x{b:02X}" for b in insn.prefix if b != 0]
            # print(f"prefix bytes: {prefix_bytes}")

            # Register prefix tokens
            for byte in prefix_bytes:
                if byte in inv_prefix_tokens:
                    prefix_name: str = inv_prefix_tokens[byte]
                    if prefix_name not in mnemonics:
                        mnemonics[prefix_name] = mnemonic_to_token(prefix_name)
                    symbol_tokens[prefix_name] = mnemonics[prefix_name]

            insn_list = []

            if hasattr(insn, "operands"):
                # print("\n")
                # go through all operands
                for op in insn.operands:
                    insn_list.append(op.type)
                    if op.type == 0 or op.type > 3:
                        raise Exception
                    if op.type == 1:  # REGISTER
                        symbol_tokens[insn.reg_name(op.reg)] = mnemonic_to_token(
                            insn.reg_name(op.reg)
                        )
                    elif op.type == 2:  # IMMEDIATE
                        imm_val = abs(op.imm)
                        if 0x00 <= imm_val <= 0xFF:
                            if hex(imm_val) in value_constants:
                                value_constants[hex(imm_val)] += 1
                            else:
                                value_constants[hex(imm_val)] = 1
                        elif (
                            0x100 <= imm_val <= (2**128 - 1)
                            or (-(2**127)) <= imm_val <= -0x100
                        ):
                            if hex(imm_val) in constant_dict.keys():  # is it a constant
                                value_constant_literals_candidates = (
                                    register_value_in_dict(
                                        value_constant_literals_candidates,
                                        hex(imm_val),
                                    )
                                )
                            else:  # Not a known constant
                                if insn.mnemonic in arithmetic_instructions:
                                    value_constant_literals_candidates = (
                                        register_value_in_dict(
                                            value_constant_literals_candidates,
                                            hex(imm_val),
                                        )
                                    )
                                elif (
                                    insn.mnemonic
                                    in addressing_control_flow_instructions
                                ):
                                    meta, kind = lookup.lookup(imm_val)
                                    if meta is not None:
                                        if kind == "range":
                                            if (
                                                func_min_addr <= imm_val < func_max_addr
                                            ):  # Local
                                                value_constant_literals_candidates = register_value_in_dict(
                                                    value_constant_literals_candidates,
                                                    hex(imm_val),
                                                )
                                            else:
                                                if (
                                                    hex(imm_val)
                                                    not in opaque_const_meta
                                                ):
                                                    opaque_const_meta_list[hex(imm_val)] = (hex(meta["start_addr"]), hex(meta["end_addr"]), meta["name"], meta["type"], "function")
                                                    opaque_const_meta[hex(meta["start_addr"])] = [
                                                        meta["name"],
                                                        hex(meta["end_addr"]),
                                                        meta["type"],
                                                        meta.get("library", "unknown"),
                                                    ]
                                                opaque_candidates = (
                                                    register_value_in_dict(
                                                        opaque_candidates,
                                                        hex(imm_val),
                                                    )
                                                )
                                        else:
                                            if hex(imm_val) not in opaque_const_meta:
                                                opaque_const_meta_list[hex(imm_val)] = (hex(meta["start_addr"]), hex(meta["end_addr"]), meta["name"], meta["type"], "unknown")
                                                opaque_const_meta[hex(meta["start_addr"])] = [
                                                    meta["name"],
                                                    hex(meta["end_addr"]),
                                                    meta["type"],
                                                ]
                                            opaque_candidates = register_value_in_dict(
                                                opaque_candidates, hex(imm_val)
                                            )
                                    else:
                                        value_constant_literals_candidates = (
                                            register_value_in_dict(
                                                value_constant_literals_candidates,
                                                hex(imm_val),
                                            )
                                        )
                                else:  # Fallback
                                    if hex(imm_val) not in opaque_const_meta:
                                        opaque_const_meta_list[hex(imm_val)] = hex(imm_val), hex(meta["end_addr"]), (meta["name"], meta["type"], meta.get("library", "unknown"))
                                        opaque_const_meta[hex(meta["start_addr"])] = [
                                                    meta["name"],
                                                    hex(meta["end_addr"]),
                                                    meta["type"],
                                                ]
                                    opaque_candidates = register_value_in_dict(
                                        opaque_candidates, hex(imm_val)
                                    )

                    elif op.type == 3:  # MEMORY
                        disp = abs(op.mem.disp)
                        scale = op.mem.scale
                        base = op.mem.base
                        index = op.mem.index
                        # Register the base register
                        if base != 0:
                            base_reg_name = insn.reg_name(base)
                            symbol_tokens[base_reg_name] = mnemonic_to_token(base_reg_name)
                        
                        # Register the index register
                        if index != 0:
                            index_reg_name = insn.reg_name(index)
                            symbol_tokens[index_reg_name] = mnemonic_to_token(index_reg_name)


                        # Register the scale as a constant if in expected range
                        if 0x00 <= scale <= 0xFF:
                            if hex(scale) in value_constants:
                                value_constants[hex(scale)] += 1
                            else:
                                value_constants[hex(scale)] = 1

                        if 0x00 <= disp <= 0xFF:
                            if hex(disp) in value_constants:
                                value_constants[hex(disp)] += 1
                            else:
                                value_constants[hex(disp)] = 1
                        else:
                            # For larger displacements, check if pointing to known constant or code or opaque
                            if hex(disp) in constant_dict:
                                value_constant_literals_candidates = (
                                    register_value_in_dict(
                                        value_constant_literals_candidates,
                                        hex(disp),
                                    )
                                )
                            else:
                                meta, kind = lookup.lookup(disp)
                                if meta is not None:
                                    if text_start <= disp < text_end:
                                        if hex(disp) not in opaque_const_meta:
                                            opaque_const_meta_list[hex(disp)] = (hex(meta["start_addr"]), hex(meta["end_addr"]), meta["name"], meta["type"], meta.get("library", "unknown"))
                                            opaque_const_meta[hex(meta["start_addr"])] = [
                                                meta["name"],
                                                hex(meta["end_addr"]),
                                                meta["type"],
                                            ]
                                        opaque_candidates = register_value_in_dict(
                                            opaque_candidates, hex(disp)
                                        )
                                    elif disp < func_min_addr or disp > func_max_addr:
                                        if hex(disp) not in opaque_const_meta:
                                            opaque_const_meta_list[hex(disp)] = (hex(meta["start_addr"]), hex(meta["end_addr"]), meta["name"], meta["type"], meta.get("library", "unknown"))
                                            opaque_const_meta[hex(meta["start_addr"])] = [
                                                meta["name"],
                                                hex(meta["end_addr"]),
                                                meta["type"],
                                            ]
                                        opaque_candidates = register_value_in_dict(
                                            opaque_candidates, hex(disp)
                                        )
                                    else:
                                        value_constant_literals_candidates = (
                                            register_value_in_dict(
                                                value_constant_literals_candidates,
                                                hex(disp),
                                            )
                                        )
                                else:
                                    value_constant_literals_candidates = (
                                        register_value_in_dict(
                                            value_constant_literals_candidates,
                                            hex(disp),
                                        )
                                    )

            else:
                print(f"INSTRUCTION WITHOUT OPERANDS: {insn}")
                raise TypeError
            # print((insn.mnemonic, insn.op_str))
            disasssembly_stream: list[str] = [
                inv_prefix_tokens[f"0x{b:02X}"]
                for b in insn.prefix
                if b != 0 and f"0x{b:02X}" in inv_prefix_tokens
            ]
            disassembly_list.append([insn.mnemonic, insn.op_str, disasssembly_stream])

            # Use only the mnemonic itself, without prefixes
            mnemonic = insn.mnemonic.strip()

            # Register the base mnemonic token if not already done
            if mnemonic not in mnemonics:
                mnemonics[mnemonic] = mnemonic_to_token(mnemonic)

        temp_bbs.append({block_addr: disassembly_list})
        block_counter += 1
    return (
        value_constants,
        value_constant_literals_candidates,
        opaque_candidates,
        temp_bbs,
        block_list,
        mnemonics,
        symbol_tokens,
        block_dict,
        opaque_const_meta,
        opaque_const_meta_list
    )


def lowlevel_disas(path, cfg, constant_list) -> tuple[
    dict[str, list[dict[str, list[list[str | list[str]]]]]],
    dict[str, list[dict[str, list[str]]]],
    dict[str, list[str]],
    dict[str, list[int]],
]:
    """
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
    """

    vocab: dict[str, int] = {}
    opaque_const_meta: dict[str, list[str]] = {}

    func_addr_range: dict[int, list[dict[str, tuple[str, str]]]] = (
        {}
    )  # func_addr: [{block_name: (block_min_addr, block_max_addr)}, ... , {block_nr: (block_min_addr, block_max_addr)}]
    func_disas: dict[str, list[dict[str, list[list[Union[str, list[str]]]]]]] = {}
    func_tokens: dict[str, list[int]] = {}

    data = {}
    with open("tokenizer/data_store.json") as f:
        data = json.load(f)
    arithmetic_instructions: set = set(data["arithmetic_instructions"])
    addressing_control_flow_instructions: set = set(
        data["addressing_control_flow_instructions"]
    )
    inv_prefix_tokens: dict[str, str] = data["inv_prefix_tokens"]

    # Get .text section size
    project = angr.Project(path, auto_load_libs=False)
    obj = project.loader.main_object
    text_start: int = 0
    text_end: int = 0

    for section in obj.sections:
        if section.name == ".text":
            text_start = section.vaddr  # virtuelle Startadresse
            text_size = section.memsize  # Größe in Bytes
            text_end = text_start + text_size

    # SECTION PARSER FOR FUNCTION LOOKUP
    lookup = AddressMetaDataLookup(path)

    func_disas_token: dict[str, list[dict[str, list[str]]]] = {}


    for func_addr, func in cfg.functions.items():
        func_name = cfg.functions[func_addr].name
        opaque_const_meta_list = {}

        function_analysis = fill_constant_candidates(
            func_name=func_name,
            func_addr=func_addr,
            func=func,
            arithmetic_instructions=arithmetic_instructions,
            addressing_control_flow_instructions=addressing_control_flow_instructions,
            inv_prefix_tokens=inv_prefix_tokens,
            constant_dict=constant_list,
            opaque_const_meta=opaque_const_meta,
            opaque_const_meta_list=opaque_const_meta_list,
            lookup=lookup,
            text_start=text_start,
            text_end=text_end,
        )

        

        if function_analysis is None:
            continue

        assert function_analysis[0] is not None
        value_constants: dict[str, int] = function_analysis[0]
        assert function_analysis[1] is not None
        value_constant_literals_candidates: dict[str, int] = function_analysis[1]
        assert function_analysis[2] is not None
        opaque_candidates: dict[str, int] = function_analysis[2]
        assert function_analysis[3] is not None
        temp_bbs: list[dict[str, list[list[Union[str, list[str]]]]]] = (
            function_analysis[3]
        )
        assert function_analysis[4] is not None
        block_list: list[dict[str, tuple[str, str]]] = function_analysis[4]
        assert function_analysis[5] is not None
        mnemonics: dict[str, str] = function_analysis[5]
        assert function_analysis[6] is not None
        symbol_tokens: dict[str, str] = function_analysis[6]
        assert function_analysis[7] is not None
        block_dict: dict[str, str] = function_analysis[7]
        assert function_analysis[8] is not None
        opaque_const_meta = function_analysis[8]
        assert function_analysis[9] is not None
        opaque_const_meta_list = function_analysis[9]


        func_addr_range[func_addr] = sorted(
            block_list, key=lambda d: list(d.values())[0][0]
        )

        # handle the constants dict
        # VALUE CONSTANTS 0x00 bis 0xFF
        renamed_value_constants: dict[str, tuple[str, int]] = name_value_constants(
            value_constants
        )

        # Take all candidates for value constant literals and check which of those are known constants
        # First, sort the items once

        # Then, iterate once and split into matching and non-matching
        # Only use classification we already did earlier during parsing
        sorted_opaque_candidates = dict(
            sorted(opaque_candidates.items(), key=lambda item: item[1], reverse=True)
        )

        # Name the constants
        value_constant_literals = name_value_constant_literals(
            value_constant_literals_candidates, "VALUED_CONST"
        )

        opaque_constants, opaque_constant_literals = name_opaque_constants(
            sorted_opaque_candidates, "OPAQUE_CONST"
        )
        
        if len(opaque_constant_literals) != 0:
            print("\n")
            for k, v in opaque_const_meta.items():
                print(f"{k}: {v}")

            print("\nOPAQUE_CONST_META_LIST: \n")
            for k, v in opaque_const_meta_list.items():
                print(f"{k}: {v}")
            print("\n")
            for k, v in opaque_constants.items():
                print(f"{k}: {v}")
            print("\n")
            for k, v in opaque_constant_literals.items():
                print(f"{k}: {v}")  

            meta_result = resolve_metadata(opaque_constants, opaque_constant_literals, opaque_const_meta_list, placeholder=("UNKNOWN", -1))
            for k in  meta_result:
                print(f"{k}")
            raise ValueError
    
        
        
        function_addr_range: list[dict[str, tuple[str, str]]] = func_addr_range[
            func_addr
        ]

        temp_tk = create_tokenstream(
            temp_bbs=temp_bbs,
            renamed_value_constants=renamed_value_constants,
            value_constant_literals=value_constant_literals,
            opaque_constants=opaque_constants,
            opaque_constant_literals=opaque_constant_literals,
            mnemonics=mnemonics,
            inv_prefix_tokens=inv_prefix_tokens,
            symbol_tokens=symbol_tokens,
            function_addr_range=function_addr_range,
            block_dict=block_dict,
        )
        vocab, tokenized_instructions, block_run_lengths, insn_run_lengths = (
            build_vocab_tokenize_and_index(temp_tk, vocab)
        )
        # print(f"Token stream: {temp_tk}")
        # print(f"Tokenized instructions: {tokenized_instructions}")
        # print(len(tokenized_instructions))
        # print(block_run_lengths)
        # print(insn_run_lengths)

        func_disas[func_name] = temp_bbs
        func_disas_token[func_name] = temp_tk
        func_tokens[func_name] = tokenized_instructions
        
    vocab = dict(sorted(vocab.items(), key=lambda item: item[1]))
    for key, value in vocab.items():
        print(f"{key}: {value}")

    return (func_disas, func_disas_token, opaque_const_meta, func_tokens)


def resolve_metadata(dict1, dict2, metadata_dict, placeholder=('UNKNOWN', -1), key_index=2):
    """
    Matches addresses from dict1 and dict2 with metadata_dict using exact and range matching.

    :param dict1: dict mapping address to token name
    :param dict2: same as dict1
    :param metadata_dict: dict mapping address to metadata tuple (token_name, range_end, ...)
    :param placeholder: tuple to use when no match is found
    :param key_index: index in metadata tuple that holds the end address
    :return: list of metadata tuples (either matched or placeholder)
    """
    result = []
    addresses = set(dict1.keys()) | set(dict2.keys())

    for addr in addresses:
        if addr in metadata_dict:
            result.append(metadata_dict[addr])
        else:
            # Try range match
            match_found = False
            for base_addr, meta in metadata_dict.items():
                try:
                    range_end = int(meta[key_index], 16) if isinstance(meta[key_index], str) else meta[key_index]
                    if int(base_addr, 16) <= int(addr, 16) <= range_end:
                        result.append(meta)
                        match_found = True
                        break
                except (IndexError, ValueError, TypeError):
                    continue
            if not match_found:
                result.append(placeholder)
    return result

def find_function_by_address(address: str, func_map: dict[str, list[str]]) -> str | None:
    """
    Find a function name for a given address.
    
    Args:
        address (str): The address to look up (e.g., "0x8049f91").
        func_map (dict[str, list[str]]): A mapping from function names to their metadata:
            [start_address, end_address, kind, binary_name].

    Returns:
        str | None: The name of the function if the address is found directly or in its range, otherwise None.
    """
    # Normalize address to int for comparison
    addr_int = int(address, 16)

    # First pass: direct match
    for func_name, (start_addr, *_rest) in func_map.items():
        if address == start_addr:
            return func_name

    # Second pass: range check
    for func_name, (start_addr, end_addr, *_rest) in func_map.items():
        start = int(start_addr, 16)
        end = int(end_addr, 16)
        if start <= addr_int <= end:
            return func_name

    return None


def create_tokenstream(
    temp_bbs,
    renamed_value_constants,
    value_constant_literals,
    opaque_constants,
    opaque_constant_literals,
    mnemonics,
    inv_prefix_tokens,
    symbol_tokens,
    function_addr_range,
    block_dict,
) -> list[dict[str, list[str]]]:
    temp_tk: list[dict[str, list[str]]] = []

    for block_code in temp_bbs:
        token_list: list[str] = []
        block_code_addr: str = ""
        block_instrs: str | list[str] = []
        # There is only one item --> traversal like this is fine
        for addr, op_str in block_code.items():  # dict[str, list[str]]
            block_code_addr = addr
            block_instrs = op_str

        for code_snippet in block_instrs:
            # Save tokenized instruction with prefixes passed in
            block_token_stream: str = parse_instruction(
                code_snippet,
                renamed_value_constants,
                value_constant_literals,
                opaque_constants,
                opaque_constant_literals,
                mnemonics,
                inv_prefix_tokens,
                symbol_tokens,
                function_addr_range,
            )
            token_list.append(block_token_stream)
        temp_tk.append({block_dict[block_code_addr]: token_list})
    return temp_tk


def build_vocab_tokenize_and_index(
    blocks: list[dict[str, list[str]]], vocab: dict[str, int]
) -> tuple[dict[str, int], list[int], list[int], list[int]]:
    
    current_id = max(vocab.values(), default=-1) + 1

    tokenized_instructions: list[int] = []

    block_break_indices: list[int] = []
    insn_break_indices: list[int] = []

    token_count = 0  # Zähler für Token insgesamt
    block_idx = 0  # Index des aktuellen Blocks
    insn_idx = 0  # Index der aktuellen Instruktion innerhalb des Blocks

    for block in blocks:
        for block_name, instructions in block.items():
            if len(block_name) > 7:
                block_names = block_name.split(" ")
                for block_name in block_names:
                    if block_name not in vocab:
                        vocab[block_name] = current_id
                        current_id += 1
            # Blocknamen zum Vokabular hinzufügen
            if block_name not in vocab:
                vocab[block_name] = current_id
                current_id += 1

            # Alle Instruktionen im Block durchgehen
            for instruction in instructions:
                tokens = instruction.split()
                for token in tokens:
                    if token not in vocab:
                        vocab[token] = current_id
                        current_id += 1
                    tokenized_instructions.append(vocab[token])
                    token_count += 1

                # Letzter Token dieser Instruktion → Instruktionsindex speichern
                insn_break_indices.append(token_count)
                insn_idx += 1

            # Letzter Token dieses Blocks → Blockindex speichern
            block_break_indices.append(token_count)
            block_idx += 1

    # Run-Length-Encoding: Differenzen der Break-Indices (inkl. 0 vorne)
    block_run_lengths = np.diff(np.concatenate(([0], block_break_indices))).tolist()
    insn_run_lengths = np.diff(np.concatenate(([0], insn_break_indices))).tolist()

    return vocab, tokenized_instructions, block_run_lengths, insn_run_lengths


def parse_instruction(
    ins_dict,
    renamed_value_constants,
    value_constant_literals,
    opaque_constants,
    opaque_constant_literals,
    mnemonics,
    inv_prefix_tokens,
    symbol_tokens,
    func_addr_range: list,
) -> str:
    """
    Tokenizes a single instruction dictionary into prefix, mnemonic, and operand tokens.

    Args:
        ins_dict (dict): {
            'mnemonic': str,
            'op_str': str,
            'prefixes': list[str]  # e.g., ['x86_lock']
        }
        renamed_value_constants (dict[str, int]): Mapping from address to Tokenname
        value_constant_literals: dict
        opaque_constants: dict
        opaque_constant_literals: dict
        mnemonics: dict of mnemonic -> token
        symbol_tokens: dict of symbol (register, prefix, etc.) -> token

    Returns:
        str: space-separated tokenized instruction
    """
    SIZE_SPECIFIERS = {
        "byte": "x86_BYTE_PTR",
        "word": "x86_WORD_PTR",
        "dword": "x86_DWORD_PTR",
        "qword": "x86_QWORD_PTR",
        "xmmword": "x86_XMMWORD_PTR",
        "ymmword": "x86_YMMWORD_PTR",
        "zmmword": "x86_ZMMWORD_PTR",
        "tmmword": "x86_ZMMWORD_PTR",
    }

    mnemonic = ins_dict[0]
    op_str = ins_dict[1]
    prefixes = ins_dict[2]
        
    token_lst = []

    # Add mnemonic token
    if mnemonic in mnemonics:
        token_lst.append(mnemonics[mnemonic])
    else:
        raise ValueError(f"Mnemonic {mnemonic} has not been registered.")

    # Handle operands
    if op_str:
        operand = op_str.split(", ")

        for i in range(len(operand)):
            symbols = re.split(r"([0-9A-Za-z_:]+)", operand[i])
            symbols = [s.strip() for s in symbols if s]
            processed = []
            for s in symbols:
                if (
                    s.lower() == "ptr" or s.lower() in inv_prefix_tokens.values()
                ):  # skip token solely reserved to make code more human-readable
                    continue  # skip ptr entirely
                if s.startswith("0x"):  # hex constants
                    processed.append(
                        resolve_constant(
                            s,
                            renamed_value_constants,
                            value_constant_literals,
                            opaque_constants,
                            opaque_constant_literals,
                            func_addr_range,
                        )
                    )
                elif s.isdigit():  # byte constants
                    processed.append(
                        resolve_constant(
                            hex(int(s)),
                            renamed_value_constants,
                            value_constant_literals,
                            opaque_constants,
                            opaque_constant_literals,
                            func_addr_range,
                        )
                    )
                elif s in SIZE_SPECIFIERS.keys():
                    processed.append(SIZE_SPECIFIERS[s])
                elif s in symbol_tokens:
                    processed.append(symbol_tokens[s])
                else:
                    processed.append(s)

            token_lst.extend(processed)
    return " ".join(token_lst)


def resolve_constant(
    s,
    renamed_value_constants,
    value_constant_literals,
    opaque_constants,
    opaque_constant_literals,
    func_addr_range: list[dict[int, tuple[str, str]]],
):
    """
    Returns the tokenrepresentation depending on the data type.

    Args:
        s (str): The element of the disassembly stream that is to be converted to a token
        renamed_value_constants (dict[str, tuple[str, int]]): dict with all positive value constant tokens
        value_constant_literals (dict[str, int]): dict with all valued constant literals tokens
        opaque_constants (dict[str, int]): dict with all opaque constants tokens
        opaque_constant_literals (dict[str, int]): dict with all opaque constant literals tokens

    Returns:
        token (str)
    """
    for element in func_addr_range:
        for block_nr, bounds in element.items():
            if int(bounds[0], 16) <= int(s, 16) < int(bounds[1], 16):
                return block_nr
    return (
        renamed_value_constants.get(s, [None])[0]
        or value_constant_literals.get(s, [None])[0]
        or opaque_constants.get(s, [None])[0]
        or opaque_constant_literals.get(s, [None])[0]
        or f"UNBEKNOWNST: {s}"
    )


def name_opaque_constants(
    occ: dict, base_name: str
) -> tuple[dict[str, tuple[str, int]], dict[str, tuple[str, int]]]:
    """
    Takes a dict of all addresses that do not point to a known constant. Assigns the first 16 to OPAQUE_CONSTANTS, the rest to OPAQUE_CONSTANT_LITERALS

    Args:
        occ (dict[address, occurence])

    Returns:
        tuple(dict[const_name: tuple(address, occurence)], dict[const_name: tuple(address, occurence)])
    """
    counter = 0
    opaque_constants = {}
    opaque_constant_literals = {}
    for addr, freq in occ.items():
        if counter < 16:
            new_name = f"OPAQUE_CONST_{hex(counter)[2:].upper()}"
            opaque_constants[addr] = (new_name, freq)
        else:
            new_name = register_name_range(counter, base_name)
            opaque_constant_literals[addr] = (new_name, freq)
        counter += 1
    return opaque_constants, opaque_constant_literals


def name_value_constant_literals(
    vcl: dict, base_name: str
) -> dict[str, tuple[str, int]]:
    """
    Takes a sorted dict of value constant literals and gives them a descriptive token name: e.g. 0x7c --> x86_VALCONST_124

    Args:
        vc (dict): Previously sorted dict of hex value constant literals and their number of occurences within a function.

    Returns:
        renamed_dict (dict): Mapping from new constant name to tuple of value constant literal: occurences.
    """
    renamed_dict = {}
    for addr, freq in vcl.items():
        new_name = register_name_range(int(addr[2:], 16), base_name)
        renamed_dict[addr] = (new_name, freq)
    return renamed_dict


def name_value_constants(vc: dict) -> dict[str, tuple[str, int]]:
    """
    Takes a sorted dict of value constants and gives them a descriptive token name: e.g. 0x7c --> x86_VALCONST_124

    Args:
        vc (dict): Previously sorted dict of hex value constants and their number of occurences within a function.

    Returns:
        renamed_dict (dict): Mapping from new constant name to tuple of value constant : occurences.
    """
    renamed_dict = {}
    for addr, freq in vc.items():
        # print(f"INTEGER: {int(addr, 16)}, HEX: {addr[2:]}")
        new_name = f"VALUED_CONST_{addr[2:].upper()}"
        renamed_dict[addr] = (new_name, freq)
    return renamed_dict


def parse_and_save_data_sections(
    proj, sections_to_parse: list[str] = [".rodata"], output_txt="parsed_constants.txt"
) -> dict[str, list[str]]:
    """
    Parses the .rodata (read-only data) section to retrieve a dict with all constants.

    Args:
        proj: angr Project
        sections_to_parse (list[str]): Contains per default only '.rodata'
        output_txt (str): Name of the file for persistence

    Returns:
        dict with all constants of structure: start_addr: [end_addr, section_name, value]
    """
    all_entries = []
    addr_dict: dict[str, list[str]] = {}

    def parse_rodata(data, base_addr):
        entries = []
        for match in re.finditer(b"[\x20-\x7e]{4,}\x00", data):
            s = match.group().rstrip(b"\x00").decode("utf-8", errors="ignore")
            start = base_addr + match.start()
            entries.append(
                {
                    "section": ".rodata",
                    "start": hex(start),
                    "end": hex(start + len(s) + 1),
                    "value": f'"{s}"',
                }
            )
        return entries

    # Only process .rodata or other truly constant sections
    for sec in proj.loader.main_object.sections:
        if sec.name not in sections_to_parse:
            continue
        if sec.name == ".rodata" and sec.is_readable and sec.memsize > 0:
            data = proj.loader.memory.load(sec.vaddr, sec.memsize)
            entries = parse_rodata(data, sec.vaddr)
            all_entries.extend(entries)
            for e in entries:
                addr_dict[e["start"]] = [e["end"], e["section"], e["value"]]

    # Output only exact-address constants
    with open(output_txt, "w") as f:
        for e in all_entries:
            f.write(f'{e["start"]} - {e["end"]}: {e["section"]}: {e["value"]}\n')

    print(
        f"Parsed {len(all_entries)} .rodata constants with exact addresses into {output_txt}"
    )
    return addr_dict


def parse_init_sections(
    proj, output_txt="parsed_init_sections.txt", sections_to_parse=None
):
    """
    Parse ELF .init/.fini/.init_array/.fini_array sections and write to file.

    Args:
        proj (angr.Project): Loaded angr project.
        output_txt (str): Output file to write parsed content.
        sections_to_parse (list[str], optional): Section names to parse. Defaults to init/fini types.

    Returns:
        list[dict]: list of parsed section entries.
    """
    if sections_to_parse is None:
        sections_to_parse = [".init", ".fini", ".init_array", ".fini_array"]

    entries = []

    with open(output_txt, "w") as f:
        f.write("# Parsed init/fini related sections\n")

        for section in proj.loader.main_object.sections:
            if section.name not in sections_to_parse:
                continue

            try:
                data = proj.loader.memory.load(section.vaddr, section.memsize)
            except Exception as e:
                print(f"Warning: could not read section {section.name}: {e}")
                continue

            if section.name.endswith("_array"):
                word_size = proj.arch.bytes
                for i in range(0, len(data), word_size):
                    chunk = data[i : i + word_size]
                    if len(chunk) != word_size:
                        continue
                    val = int.from_bytes(chunk, byteorder="little")
                    entry = {
                        "section": section.name,
                        "start": hex(section.vaddr + i),
                        "end": hex(section.vaddr + i + word_size),
                        "value": hex(val),
                        "type": "pointer",
                    }
                    entries.append(entry)
                    f.write(
                        f"{entry['section']}, {entry['start']} - {entry['end']}: {entry['value']} (ptr)\n"
                    )
            else:
                hex_preview = data[:32].hex()
                entry = {
                    "section": section.name,
                    "start": hex(section.vaddr),
                    "end": hex(section.vaddr + section.memsize),
                    "value": f"hex({hex_preview}...)",
                    "type": "code",
                }
                entries.append(entry)
                f.write(
                    f"{entry['section']}, {entry['start']} - {entry['end']}: {entry['value']} (code)\n"
                )

    print(f"Parsed {len(entries)} entries from init-related sections into {output_txt}")
    return entries


def main():
    file_path = "src/curl/x86-clang-3.5-O0_curl"
    # print(extract_ldis_blocks_from_file("out\\clamav\\x86-gcc-4.8-Os_clambc\\x86-gcc-4.8-Os_clambc_functions.csv"))

    project = angr.Project(file_path, auto_load_libs=False)
    constants: dict[str, list[str]] = parse_and_save_data_sections(project)

    cfg = project.analyses.CFGFast(normalize=True)
    disassembly: dict[str, list[dict[str, list[list[str | list[str]]]]]] = {}
    disassembly_tokenized: dict[str, list[dict[str, list[str]]]] = {}
    opaque_constants_meta: dict[str, list[str]] = {}
    disassembly, disassembly_tokenized, opaque_constants_meta, func_tokens = (
        lowlevel_disas(file_path, cfg, constants)
    )

    with open("opaque_const_meta.txt", encoding="utf-8", mode="w") as f:
        for k, v in opaque_constants_meta.items():
            f.write(f"{k}: {v}\n")

    with open("tokenized_disassembly.txt", encoding="utf-8", mode="w") as f:
        for k, v in disassembly_tokenized.items():
            f.write(f"{k}: {v}\n")

    with open(f"test.txt", encoding="utf-8", mode="w") as f:
        f.write("Function name, assembly\n")
        for (k1, v1), (k2, v2) in zip(
            disassembly.items(), disassembly_tokenized.items()
        ):
            f.write(f"{k1}: {v1}\n")
            f.write(f"{k2}: {v2}\n")

    with open("tokens.txt", encoding="utf-8", mode="w") as f:
        for key, value in func_tokens.items():
            f.write(f"{key}: {value}")

    return


if __name__ == "__main__":
    main()

    # TODO nach csv bauen: Reversecheck ob das auch alles wieder korrekt aufgelöst wird
