import angr
import re
import pickle
import csv, json
from pathlib import Path
from dataclasses import dataclass
from address_meta_data_lookup import AddressMetaDataLookup
from compact_base64_utils import ndarray_to_base64
from tokenizer.csv_files import parse_and_save_data_sections, token_to_insn, compare_csv_files, csv_to_dict
from tokenizer.make_name import name_opaque_constants, name_value_constant_literals, name_value_constants
from tokenizer.op_imm_mem import tokenize_operand_memory, tokenize_operand_immediate
from tokenizer.pickles import load_all_pickles, save_pickles
from tokenizer.tokens import VocabularyManager, TokenResolver, Tokens
from tokenizer.constant_handler import ConstantHandler
from typing import Union, Optional
from tqdm import tqdm
import numpy as np
import numpy.typing as npt


@dataclass
class FunctionData:
    """Consolidated data structure for function analysis results"""
    tokens_base64: str
    block_runlength_base64: str
    instruction_runlength_base64: str
    opaque_metadata: str

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


def fill_constant_candidates(
        func_addr: int,
        func: angr.knowledge_plugins.functions.function.Function,
        arithmetic_instructions: set[str],
        addressing_control_flow_instructions: set[str],
        inv_prefix_tokens: dict[str, str],
        constant_dict: dict[str, list[str]],
        lookup: AddressMetaDataLookup,
        text_start: int,
        text_end: int,
        resolver: TokenResolver,
        vocab_manager: VocabularyManager,
) -> Optional[
    tuple[
        list[dict[str, list[list[Union[str, list[str]]]]]],
        list[dict],
        dict[str, Tokens],
        dict[str, Tokens],
        dict[str, Tokens],
        ConstantHandler,
    ]
]:
    """
    Assigns all operands for a given function to datastructures that are used to determine the token type.

    Args:
        func_addr (int): Integer value of the function's start address
        func (angr.knowledge_plugins.functions.function.Function): angr function object to be analyzed
        arithmetic_instructions (set): Set of all arithmetic instruction. Used to indicate non-opaque constants.
        addressing_control_flow_instructions (set): Set of all instruction that indicate memory operations or controlflow. Used to indicate opaque constants.
        inv_prefix_tokens (dict[str, str]): Maps the hex value of all possible decorators to their intended meaning.
        constant_dict (dict[str, list[str]]): Stores all constants from .rodata
        lookup (AddressMetaDataLookup): lookupObject to quickly parse function libraries to populate opaque_const_meta
        text_start (int): Start address of the .text section
        text_end (int): End address of the .text section
        resolver (TokenResolver): Token resolver for early ID resolution
        vocab_manager (VocabularyManager): Vocabulary manager for token creation"""

    func_min_addr: int = int(func_addr)
    blocks: set = set()

    # Create constant handler for this function
    constant_handler = ConstantHandler(vocab_manager, resolver, constant_dict)
    temp_bbs: list[dict[str, list[list[Union[str, list[str]]]]]] = []
    block_list: list[dict[Tokens, tuple[str, str]]] = []
    block_dict: dict[str, Tokens] = {}  # hex value of Block address: block_token

    if sum(1 for _ in func.blocks) == 1 and next(func.blocks).capstone.insns is None:
        return None

    for block in func.blocks:

        func_max_addr = max(func_min_addr, block.addr + block.size)

        # ------------------Register name of current Block---------------------
        block_addr = hex(block.addr)
        block_id = resolver.get_block_id(block_addr)
        block_token = vocab_manager.Block(block_id)
        block_list.append(
            {
                block_token: (
                    hex(func_min_addr),
                    hex(func_max_addr),
                )
            }
        )
        blocks.add(block_addr)

        if block.capstone.insns is None:
            print("KAPUTT")

        block_dict[block_addr] = block_token

        disassembly_list = [[vocab_manager.Block_Def(), block_token]]

        # Single loop over instructions to get both disassembly and immediates
        for insn in block.capstone.insns:
            # Extract non-zero prefixes (up to 4 bytes)
            prefix_bytes = [f"0x{b:02X}" for b in insn.prefix if b != 0]
            # print(f"prefix bytes: {prefix_bytes}")
            
            insn_tokens = []

            # Register prefix tokens
            # looking at capstone source: https://github.com/qemu/capstone/blob/9e27c51c2485dd37dd3917919ae781c6153f3688/include/capstone/x86.h#L247C1-L262C14
            for byte in prefix_bytes:
                if byte in inv_prefix_tokens:
                    prefix_name: str = inv_prefix_tokens[byte]
                    insn_tokens.append(vocab_manager.PlatformToken(prefix_name))


            insn_tokens.append(vocab_manager.PlatformToken(insn.insn.insn_name()))
            #interesting stuff: insn.group_name(insn.groups[0])
            insn_list = []

            if hasattr(insn, "operands"):
                # print("\n")
                # go through all operands
                for op in insn.operands:
                    insn_list.append(op.type)
                    if op.type == 0 or op.type > 3:
                        raise Exception
                    if op.type == 1:  # REGISTER
                        insn_tokens.append(vocab_manager.get_registry_token(insn, op.reg))
                        # reg_name = insn.reg_name(op.reg)
                        # if reg_name not in symbol_tokens:
                        #     symbol_tokens[reg_name] = vocab_manager.PlatformToken(reg_name)
                    elif op.type == 2:  # IMMEDIATE
                        immediate_tokens = tokenize_operand_immediate(
                            addressing_control_flow_instructions, arithmetic_instructions,
                            insn, lookup, op, func_max_addr, func_min_addr, constant_handler)
                        insn_tokens.extend(immediate_tokens)

                    elif op.type == 3:  # MEMORY
                        memory_tokens = tokenize_operand_memory(insn, lookup, op, text_end,
                                                               text_start, func_max_addr, func_min_addr,
                                                               vocab_manager, constant_handler)
                        insn_tokens.extend(memory_tokens)

            else:
                print(f"INSTRUCTION WITHOUT OPERANDS: {insn}")
                raise TypeError

            disassembly_list.append(insn_tokens)

        temp_bbs.append((block_addr, disassembly_list))
    return (
        temp_bbs,
        block_list,
        block_dict,
        constant_handler,
    )


def lowlevel_disas(path, cfg, constant_list, with_pickled=False, project=None, **kwargs):
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
    if not with_pickled:
        func_names = []
        block_runlength_dict = {}
        insn_runlength_dict = {}
        opaque_meta_dict = {}


        opaque_const_meta: dict[str, list[str]] = {}

        func_addr_range: dict[int, list[dict[str, tuple[str, str]]]] = (
            {}
        )  # func_addr: [{block_name: (block_min_addr, block_max_addr)}, ... , {block_nr: (block_min_addr, block_max_addr)}]
        func_disas: dict[str, list[dict[str, list[str]]]] = {}

        data = {}
        with open("./data_store.json") as f:
            data = json.load(f)
        arithmetic_instructions: set = set(data["arithmetic_instructions"])
        addressing_control_flow_instructions: set = set(
            data["addressing_control_flow_instructions"]
        )
        string_instructions: set = set(data["string_instructions"])
        bit_manipulation_instructions: set = set(data["bit_manipulation_instructions"])
        floating_point_instructions: set = set(data["floating_point_instructions"])
        system_instructions: set = set(data["system_instructions"])
        inv_prefix_tokens: dict[str, str] = data["inv_prefix_tokens"]

        # Get .text section size
        project = angr.Project(path, auto_load_libs=False) if project is None else project
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

        # Initialize the resolver for token management
        resolver = TokenResolver()

        func_disas_token: dict[str, list[dict[str, list[str]]]] = {}

        func_name_addr = {}
        duplicate_func_names: dict[str, str] = {}
        seen = set()

        kwargs = dict(addressing_control_flow_instructions=addressing_control_flow_instructions,
                      arithmetic_instructions=arithmetic_instructions,
                      bit_manipulation_instructions=bit_manipulation_instructions,
                      block_runlength_dict=block_runlength_dict, cfg=cfg, constant_list=constant_list,
                      duplicate_func_names=duplicate_func_names,
                      floating_point_instructions=floating_point_instructions,
                      func_addr_range=func_addr_range, func_disas=func_disas, func_disas_token=func_disas_token,
                      func_name_addr=func_name_addr, func_names=func_names, insn_runlength_dict=insn_runlength_dict,
                      inv_prefix_tokens=inv_prefix_tokens, lookup=lookup, opaque_const_meta=opaque_const_meta,
                      opaque_meta_dict=opaque_meta_dict, resolver=resolver, seen=seen,
                      string_instructions=string_instructions, system_instructions=system_instructions,
                      text_end=text_end,
                      text_start=text_start)

        pickle_mainloop_file_path = path.parent / f"{path.name}.mainloop.pkl"
        with open(pickle_mainloop_file_path, "wb") as f:
            pickle.dump(kwargs, f)

    else:
        kwargs.update(dict(cfg=cfg, constant_list=constant_list))
        func_disas = kwargs["func_disas"]
        func_disas_token = kwargs["func_disas_token"]
        duplicate_func_names = kwargs["duplicate_func_names"]
        func_names = kwargs["func_names"]

    # Initialize VocabularyManager
    vocab_manager = VocabularyManager("x86")

    function_data_dict = main_loop(vocab_manager=vocab_manager, **kwargs)

    with open("disassembly.csv", encoding="utf-8", mode="w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        for k, v in func_disas.items():
            writer.writerow([f"{k}: {v}"])
    with open("readable_tokenized_disassembly.csv", encoding="utf-8", mode="w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        for k, v in func_disas_token.items():
            writer.writerow([k, v])



    # save_pickles(func_names,
    #              duplicate_func_names, function_data_dict, vocab_manager)

    return (func_names, duplicate_func_names, function_data_dict, vocab_manager)


def main_loop(addressing_control_flow_instructions, arithmetic_instructions, cfg, constant_list, duplicate_func_names,
              func_addr_range, func_disas, func_disas_token, func_name_addr, func_names, inv_prefix_tokens, lookup,
              resolver, seen, text_end, text_start, vocab_manager, **_kwargs) -> dict[str, FunctionData]:

    # Replace the four separate dictionaries with one consolidated dictionary
    function_data_dict: dict[str, FunctionData] = {}

    for func_addr, func in tqdm(iterable=cfg.functions.items(),
                                desc="Retrieving data from alllll functions. Like a big boy."):
        func_name = cfg.functions[func_addr].name
        func_name_addr[func_name] = func_addr
        if func_name in ["UnresolvableCallTarget", "UnresolvableJumpTarget"]:
            continue

        # Reset block counter for each function so block IDs start from 0
        resolver.reset_block_counter()


        (function_analysis) = fill_constant_candidates(
            func_addr=func_addr,
            func=func,
            arithmetic_instructions=arithmetic_instructions,
            addressing_control_flow_instructions=addressing_control_flow_instructions,
            inv_prefix_tokens=inv_prefix_tokens,
            constant_dict=constant_list,
            lookup=lookup,
            text_start=text_start,
            text_end=text_end,
            resolver=resolver,
            vocab_manager=vocab_manager,
        )

        if function_analysis is None:
            continue

        (temp_bbs,
        block_list,
        block_dict,
        constant_handler) = function_analysis

        func_addr_range[func_addr] = sorted(
            block_list, key=lambda d: list(d.values())[0][0]
        )

        # Create mapping from old opaque tokens to new sorted tokens
        opaque_mapping = constant_handler.create_opaque_mapping()

        # Apply the mapping to replace opaque tokens in temp_bbs
        if len(opaque_mapping) > 0:
            temp_bbs = apply_opaque_mapping(temp_bbs, opaque_mapping, constant_handler)

        # Get metadata from constant handler
        opaque_metadata = constant_handler.get_metadata()
        meta_result = list(opaque_metadata.values())

        # Create token stream directly from temp_bbs (which already contains TokensRepl objects)
        temp_tk = [tokens for (addr, tokens) in temp_bbs]

        tokenized_instructions, block_run_lengths, insn_run_lengths = (
            build_vocab_tokenize_and_index(temp_tk)
        )
        if len(tokenized_instructions) == 0:
            continue

        func_disas[func_name] = temp_bbs
        func_disas_token[func_name] = temp_tk

        try:
            tokens_base64 = ndarray_to_base64(tokenized_instructions)
            block_base64 = ndarray_to_base64(block_run_lengths)
            insn_base64 = ndarray_to_base64(insn_run_lengths)

            if func_name in func_names:
                i = 1
                new_name = f"{func_name}_{i}"
                while new_name in seen:
                    i += 1
                    new_name = f"{func_name}_{i}"
                duplicate_func_names[new_name] = func_name  # mapping duplicate->original
                func_name = new_name
                seen.add(func_name)
        except Exception as e:
            print(
                f"Error processing {func_name}: {e}.\nTokenstream: {temp_tk}\nTokens: {tokenized_instructions}\nBlock encoding: {block_run_lengths}\nInstructions: {insn_run_lengths}\nMetaData: {str(meta_result)}")
            raise ValueError

        func_names.append(func_name)

        # Create FunctionData instance instead of updating four separate dictionaries
        function_data_dict[func_name] = FunctionData(
            tokens_base64=tokens_base64,
            block_runlength_base64=block_base64,
            instruction_runlength_base64=insn_base64,
            opaque_metadata=meta_result
        )

    return function_data_dict


def apply_opaque_mapping(temp_bbs, opaque_mapping, constant_handler=None):
    """
    Apply opaque token mapping to replace old tokens with new sorted tokens.
    Also reorders metadata to match the new token ordering.

    Args:
        temp_bbs: List of blocks containing instruction tokens
        opaque_mapping: Dictionary mapping old opaque tokens to new sorted tokens
        constant_handler: Optional ConstantHandler to also reorder metadata

    Returns:
        Updated temp_bbs with remapped tokens
    """
    updated_bbs = []
    #todo i am very very sure we also need to reorder metadata

    for (block_addr, instruction_list) in temp_bbs:
        updated_instructions = []

        for instruction_tokens in instruction_list:
            updated_instruction = []

            for token in instruction_tokens:
                # Check if this token needs to be remapped
                if token in opaque_mapping:
                    updated_instruction.append(opaque_mapping[token])
                else:
                    updated_instruction.append(token)

            updated_instructions.append(updated_instruction)


        updated_bbs.append((block_addr, updated_instructions))

    # If constant_handler is provided, also reorder metadata
    if constant_handler is not None and opaque_mapping:
        constant_handler.reorder_metadata_for_mapping(opaque_mapping)

    return updated_bbs



def token_to_instruction(vocab, tokenstream):
    insn = []
    print(f"TOKENSTREAM NEWNWNWNWNNWNW: {tokenstream}")
    id_to_token = {v: k for k, v in vocab.items()}
    for element in tokenstream:
        insn.append(id_to_token[int(element)])
    return insn


def resolve_metadata(dict1, dict2, metadata_dict, placeholder=('UNKNOWN', -1), key_index=2) -> list[
    tuple[str, str, str, str, str]]:
    """
    Matches addresses from dict1 and dict2 with metadata_dict using exact and range matching.

    :param dict1: dict mapping address to token name
    :param dict2: same as dict1
    :param metadata_dict: dict mapping address to metadata tuple (token_name, range_end, ...)
    :param placeholder: tuple to use when no match is found
    :param key_index: index in metadata tuple that holds the end address
    :return: list of metadata tuples (either matched or placeholder)
    """
    result: list[tuple[str, str, str, str, str]] = []
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






def build_vocab_tokenize_and_index(blocks: list[list[list[Tokens]]]) -> (npt.NDArray[np.int_], npt.NDArray[np.int_], npt.NDArray[np.int_]):
    """
    Updated function to work with TokensRepl objects from create_tokenstream.
    Now expects blocks as list[list[list[TokensRepl]]] instead of tuples.
    """

    # flatten instructions
    insn_run_lengths: list[npt.NDArray[np.int_]] = [np.array([len(insn) for insn in insns]) for insns in blocks]
    block_run_lengths: npt.NDArray[np.int_] = np.array([insns.sum() for insns in insn_run_lengths])
    insn_run_lengths: npt.NDArray[np.int_] = np.concatenate(insn_run_lengths)

    def traverse(o, tree_types=(list, tuple)):
        if isinstance(o, list):
            for value in o:
                for subvalue in traverse(value, tree_types):
                    yield subvalue
        elif isinstance(o, Tokens):
            for id in o.get_token_ids():
                yield id
        else:
            raise TypeError(f"Unsupported type: {type(o)}")

    tokenized_instructions = np.array([x for x in traverse(blocks)], dtype=np.int_)

    return tokenized_instructions, block_run_lengths, insn_run_lengths


def main():
    print(f"STARTING DISASSEMBLY")
    file_path = Path("../src/clamav/x86-gcc-5-O3_minigzipsh").absolute()
    pickle_file_path = file_path.parent / f"{file_path.name}.pkl"
    pickle_mainloop_file_path = file_path.parent / f"{file_path.name}.mainloop.pkl"
    with_pickled = False
    if pickle_mainloop_file_path.exists():
        print("loading existing mainloop pickle to speed up")
        with open(pickle_mainloop_file_path, "rb") as f:
            kvargs = pickle.load(f)
            if "path" not in kvargs:
                kvargs["path"] = file_path
            with_pickled = True
    elif pickle_file_path.exists():
        print("loading existing pickle to speed up")
        with open(pickle_file_path, "rb") as f:
            kvargs = pickle.load(f)
    else:
        project = angr.Project(file_path, auto_load_libs=False)  # was False
        constants: dict[str, list[str]] = parse_and_save_data_sections(project)
        cfg = project.analyses.CFGFast(normalize=True)

        kvargs = dict(project=project, path=file_path, cfg=cfg, constant_list=constants)
        with open(pickle_file_path, "wb") as f:
            pickle.dump(kvargs, f)

    print(f"calling lowlevel_disas")
    (func_names, duplicate_func_names, function_data_dict, vocab_manager) = lowlevel_disas(with_pickled=with_pickled, **kvargs)

    print(f"WRITING OUTPUT")
    with open("output.csv", "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        # Write header with appropriate column names
        writer.writerow(['function_name', 'tokens_base64', 'block_runlength_base64', 'instruction_runlength_base64', 'opaque_metadata', f'"{",".join(vocab_manager.id_to_token)}"'])

        for element in func_names:
            # Resolve original name if duplicate
            if element in duplicate_func_names:
                original_name = duplicate_func_names[element]
            else:
                original_name = element

            # Get function data from function_data_dict
            if element in function_data_dict:
                func_data = function_data_dict[element]
                row = [
                    original_name,
                    func_data.tokens_base64,
                    func_data.block_runlength_base64,
                    func_data.instruction_runlength_base64,
                    str(func_data.opaque_metadata)
                ]
                writer.writerow(row)
            else:
                print(f"Warning: Function {element} not found in function_data_dict")

    print("VERIFY OUTPUT")

    # datastructures_to_insn(vocab=vocab, block_runlength_dict=block_run_length, insn_runlength_dict=insn_runlength, token_dict=tokens, duplicate_map=duplicate_map)
    token_to_insn("output.csv")
    compare_csv_files("reconstructed_disassembly.csv", "readable_tokenized_disassembly.csv")
    # compare_csv_files("reconstructed_disassembly_test.csv", "readable_tokenized_disassembly.csv")

    # print(f"Output and reconstruction equal? {filecmp.cmp("reconstructed_disassembly_test.csv", "reconstructed_disassembly.csv", shallow=False)}")

    """func_names = result["func_names.pkl"]
    token_dict = result["token_dict.pkl"]readable_tokenized_disassembly.csv
    block_runlength_dict = result["block_runlength_dict.pkl"]
    insn_runlength_dict = result["insn_runlength_dict.pkl"]
    opaque_meta_dict = result["opaque_meta_dict.pkl"]
    vocab = result["vocab.pkl"]
    duplicate_func_names = result["duplicate_func_names.pkl"]
    tokenized_instructions = result["tokenized_instructions.pkl"]
    block_run_lengths = result["block_run_lengths.pkl"]
    insn_run_lengths = result["insn_run_lengths.pkl"]
    meta_result = result["meta_result.pkl"]"""

    # token_to_insn("output.csv")
    # compare_csv_files("readable_tokenized_disassembly.csv", "reconstructed_disassembly.csv")
    # print(filecmp.cmp("readable_tokenized_disassembly.csv", "reconstructed_disassembly.csv", shallow=False))




if __name__ == "__main__":
    main()

    # TODO nach csv bauen: Reversecheck ob das auch alles wieder korrekt aufgelöst wird
    # TODO proper placeholder for unresolvable opaque constants
    # TODO bei VALUED_CONST_{} immer zwei stellen bitte also 0F statt F
