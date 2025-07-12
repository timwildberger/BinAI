import angr
import pickle
import csv, json
import time
from pathlib import Path
from tokenizer.address_meta_data_lookup import AddressMetaDataLookup
from tokenizer.compact_base64_utils import ndarray_to_base64
from tokenizer.compact_base64_utils import base64_to_ndarray_vec
from tokenizer.csv_files import parse_and_save_data_sections, token_to_insn, compare_csv_files, vocab_from_output, \
    token_to_functions
from tokenizer.function_token_list import FunctionTokenList
from tokenizer.op_imm_mem import tokenize_operand_memory, tokenize_operand_immediate
from tokenizer.opaque_remapping import apply_opaque_mapping, apply_opaque_mapping_raw_optimized
from tokenizer.token_lists import BlockTokenList
from tokenizer.tokens import TokenResolver, Tokens, BlockToken
from tokenizer.token_manager import VocabularyManager
from tokenizer.constant_handler import ConstantHandler
from tokenizer.function_data_manager import FunctionDataManager, FunctionData
from tokenizer.instruction_sets import InstructionSets
from tokenizer.utils import filter_queue_file_by_existing_output, pop_first_line
from typing import Optional, Any
from tqdm import tqdm
import numpy as np
import numpy.typing as npt
import argparse

VERIFICATION: bool = False
SCRIPT_FOLDER: Path = Path(__file__).parent.resolve()


degenerate_prefixes = {
    0xF2: ["repne", "repnz"],
    0xF3: ["repe", "repz", "rep"], #ordering important due to string comparisons
}


def fill_constant_candidates(
        func_addr: int,
        func: angr.knowledge_plugins.functions.function.Function,
        instr_sets: InstructionSets,
        constant_dict: dict[str, list[str]],
        lookup: AddressMetaDataLookup,
        text_start: int,
        text_end: int,
        resolver: TokenResolver,
        vocab_manager: VocabularyManager,
) -> Optional[
    tuple[
        list[tuple[str, list[list[Tokens]]]], # temp_bbs
        list[dict[BlockToken, tuple[str, str]]], # block_list
        dict[str, BlockToken], # block_dict
        ConstantHandler,
        FunctionTokenList # func_tokens
    ]
]:
    """
    Assigns all operands for a given function to datastructures that are used to determine the token type.

    Args:
        func_addr (int): Integer value of the function's start address
        func (angr.knowledge_plugins.functions.function.Function): angr function object to be analyzed
        instr_sets (InstructionSets): Container with all instruction classification sets
        constant_dict (dict[str, list[str]]): Stores all constants from .rodata
        lookup (AddressMetaDataLookup): lookupObject to quickly parse function libraries to populate opaque_const_meta
        text_start (int): Start address of the .text section
        text_end (int): End address of the .text section
        resolver (TokenResolver): Token resolver for early ID resolution
        vocab_manager (VocabularyManager): Vocabulary manager for token creation"""

    func_min_addr: int = int(func_addr)
    blocks: set = set()

    num_blocks = len(list(func.blocks))
    block_ranges: np.ndarray = np.empty((num_blocks, 2), dtype=np.uint64)  # uint64 for addresses

    for i, block in enumerate(func.blocks):
        block_ranges[i, 0] = block.addr            # start address
        block_ranges[i, 1] = block.addr + block.size  # end address

    # Create constant handler for this function
    constant_handler = ConstantHandler(vocab_manager, resolver, constant_dict, block_ranges)
    temp_bbs: list[tuple[str, list[list[Tokens]]]] = []
    block_list: list[dict[BlockToken, tuple[int, int]]] = []
    block_dict: dict[str, BlockToken] = {}  # hex value of Block address: block_token

    num_blocks = sum(1 for _ in func.blocks)
    
    if num_blocks == 1 and next(func.blocks).capstone.insns is None:
        return None
    
    func_tokens = FunctionTokenList(num_blocks, vocab_manager=vocab_manager)
    ordered_blocks = sorted(func.blocks, key=lambda b: b.addr)
    for block in ordered_blocks:

        func_max_addr = max(block.addr, block.addr + block.size)

        # ------------------Register name of current Block---------------------
        block_addr = hex(block.addr)
        block_id = resolver.get_block_id(block_addr)
        block_token = vocab_manager.Block(block_id)
        block_list.append(
            {
                block_token: (
                    block.addr,
                    block.addr + block.size,
                )
            }
        )
        blocks.add(block_addr)

        assert block.capstone.insns is not None, "Block has no instructions, cannot disassemble"

        block_dict[block_addr] = block_token

        block_def = [vocab_manager.Block_Def(), block_token]

        disassembly_list = BlockTokenList(len(block.capstone.insns)+1, vocab_manager=vocab_manager)
        disassembly_list.append_as_insn(insn_str=f"block {block_addr}", tokens=block_def)

        disassembly_list2 = [block_def]

        # Single loop over instructions to get both disassembly and immediates
        for insn in block.capstone.insns:
            insn_tokens = disassembly_list.view(insn_str = f"{insn.mnemonic} {insn.op_str}")


            (insn_tokens, insn_tokens2) = parse_instruction(instr_sets, constant_handler,
                              func_max_addr, func_min_addr, insn, lookup, text_end, text_start,
                              vocab_manager, insn_tokens)
            disassembly_list.add_insn(insn_tokens)
            if VERIFICATION:
                disassembly_list2.append(insn_tokens2)


        if VERIFICATION:
            for (x, y) in zip([token   for insn in disassembly_list2  for token in insn], disassembly_list.iter_raw_tokens()):
                if x != y:
                    print(f"Token mismatch: {x} != {y}")
                    raise ValueError("Token mismatch in disassembly list")

        if VERIFICATION:
            temp_bbs.append((block_addr, disassembly_list2))
        func_tokens.add_block(disassembly_list, block_addr)
    return (
        temp_bbs,
        block_list,
        block_dict,
        constant_handler,
        func_tokens,
    )


def parse_instruction(instr_sets, constant_handler, func_max_addr, func_min_addr, insn, lookup, text_end, text_start,
                      vocab_manager, insn_tokens):
    insn_tokens2 = [] if VERIFICATION else None

    # Register prefix tokens
    # looking at capstone source: https://github.com/qemu/capstone/blob/9e27c51c2485dd37dd3917919ae781c6153f3688/include/capstone/x86.h#L247C1-L262C14
    for byte in insn.prefix:
        if byte in degenerate_prefixes:
            skip = True
            for prefix_name in degenerate_prefixes[byte]: # Check for ambiguity for repne, repz, repnz, repe, rep
                if insn.mnemonic.startswith(prefix_name):
                    token = vocab_manager.PlatformToken(prefix_name)
                    insn_tokens.append(token)
                    if VERIFICATION:
                        assert insn_tokens2 is not None
                        insn_tokens2.append(token)
                    break
            else:
                skip = False
            if skip:
                continue

        if byte in instr_sets.prefixes:
            prefix_name: str = instr_sets.prefixes[byte]
            token = vocab_manager.PlatformToken(prefix_name)
            insn_tokens.append(token)
            if VERIFICATION:
                assert insn_tokens2 is not None
                insn_tokens2.append(token)

    token = vocab_manager.PlatformToken(insn.insn.insn_name())
    insn_tokens.append(token)
    if VERIFICATION:
        assert insn_tokens2 is not None
        insn_tokens2.append(token)

    # interesting stuff: insn.group_name(insn.groups[0])
    if hasattr(insn, "operands"):
        # print("\n")
        # go through all operands
        for op in insn.operands:
            if op.type == 0 or op.type > 3: # angr wrapper only registers REGISTER (1), IMMEDIATE (2), MEMORY (3)
                raise Exception
            
            if op.type == 1:  # REGISTER
                token = vocab_manager.get_registry_token(insn, op.reg)
                insn_tokens.append(token)
                if VERIFICATION:
                    assert insn_tokens2 is not None
                    insn_tokens2.append(token)
                # reg_name = insn.reg_name(op.reg)
                # if reg_name not in symbol_tokens:
                #     symbol_tokens[reg_name] = vocab_manager.PlatformToken(reg_name)
            elif op.type == 2:  # IMMEDIATE
                immediate_tokens = tokenize_operand_immediate(
                    instr_sets.addressing_control_flow, instr_sets.arithmetic,
                    insn, lookup, op, func_max_addr, func_min_addr, constant_handler)
                insn_tokens.extend(immediate_tokens)
                if VERIFICATION:
                    assert insn_tokens2 is not None
                    insn_tokens2.extend(immediate_tokens)

            elif op.type == 3:  # MEMORY
                memory_tokens = tokenize_operand_memory(insn, lookup, op, text_end,
                                                        text_start, func_max_addr, func_min_addr,
                                                        vocab_manager, constant_handler)
                insn_tokens.extend(memory_tokens)
                if VERIFICATION:
                    assert insn_tokens2 is not None
                    insn_tokens2.extend(memory_tokens)

    else:
        print(f"INSTRUCTION WITHOUT OPERANDS: {insn}")
        raise TypeError

    return insn_tokens, insn_tokens2


def disassemble_to_tokens(path: Path, cfg: angr.analyses.cfg.cfg_fast.CFGFast, constant_list: dict[str, list[str]], with_pickled=False, project=None, **kwargs):
    """
    Wrapper function for the entire disassembly and tokenization.

    Args:
        path (Path): Relative path to the binary.
        cfg (angr.analyses.cfg.cfg_fast.CFGFast): CFGFast, Control Flow Graph of binary.
        constant_list (dict[str, list[str]]): List of all known constants.
        with_pickled (bool): If True, loads pickles of previously parsed binary. Builds everything anew if False.
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
        with open("tokenizer/data_store.json") as f:
            data = json.load(f)

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

        func_disas_token: dict[str, list[dict[str, list[str]]]] = {}

        func_name_addr = {}

        kwargs = dict(block_runlength_dict=block_runlength_dict, cfg=cfg, constant_list=constant_list,
                      func_addr_range=func_addr_range, func_disas=func_disas, func_disas_token=func_disas_token,
                      func_name_addr=func_name_addr, func_names=func_names, insn_runlength_dict=insn_runlength_dict,
                      inv_prefix_tokens=inv_prefix_tokens, lookup=lookup, opaque_const_meta=opaque_const_meta,
                      opaque_meta_dict=opaque_meta_dict,
                      text_end=text_end,
                      text_start=text_start)

        pickle_mainloop_file_path = path.parent / f"{path.name}.mainloop.pkl"
        with open(pickle_mainloop_file_path, "wb") as f:
            pickle.dump(kwargs, f)

    else:
        kwargs.update(dict(cfg=cfg, constant_list=constant_list))
        func_disas = kwargs["func_disas"]
        func_disas_token = kwargs["func_disas_token"]
        func_names = kwargs["func_names"]

    
    # Initialize VocabularyManager
    vocab_manager = VocabularyManager("x86")

    # Initialize the resolver for token management
    resolver = TokenResolver()
    instr_sets = InstructionSets(SCRIPT_FOLDER / "./data_store.json")
    kwargs.update(dict(resolver=resolver, instr_sets=instr_sets))

    function_manager = main_loop(vocab_manager=vocab_manager, path=path, **kwargs)

    # save_pickles(func_names,
    #              duplicate_func_names, function_manager, vocab_manager)

    return (func_names, function_manager, vocab_manager)


def main_loop(instr_sets, cfg, constant_list,
              func_addr_range, func_disas, func_disas_token, func_name_addr, func_names, inv_prefix_tokens, lookup,
              resolver, text_end, text_start, vocab_manager, path, **_kwargs) -> FunctionDataManager:

    # Initialize FunctionDataManager with pre-allocated arrays
    total_functions = len(cfg.functions.items())
    function_manager = FunctionDataManager(total_functions, vocab_manager)
    with open(f"{path.absolute().name}_output.csv", "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        # Write header with occurrence column added
        writer.writerow(['function_name', 'occurrence', 'tokens_base64', 'block_runlength_base64', 'instruction_runlength_base64', 'opaque_metadata', f'"{",".join(vocab_manager.id_to_token)}"'])

    prev_func_name = ""
    occurence = 0
    for func_addr, func in tqdm(iterable=sorted(cfg.functions.items(), key=lambda item: item[1].name),
                                desc="Retrieving data from alllll functions. Like a big boy."):
        func_name = cfg.functions[func_addr].name
        if func_name in ["UnresolvableCallTarget", "UnresolvableJumpTarget"]:
            continue

        # Reset block counter for each function so block IDs start from 0
        resolver.reset_block_counter()

        (function_analysis) = fill_constant_candidates(
            func_addr=func_addr,
            func=func,
            instr_sets=instr_sets,
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
        constant_handler,
        func_tokens) = function_analysis

        func_addr_range[func_addr] = sorted(
            block_list, key=lambda d: list(d.values())[0][0]
        )


        # Create mapping from old opaque tokens to new sorted tokens
        opaque_mapping = constant_handler.create_opaque_mapping()

        # Apply the mapping to replace opaque tokens in temp_bbs
        if len(opaque_mapping) > 0:
            func_tokens = apply_opaque_mapping_raw_optimized(func_tokens, opaque_mapping, vocab_manager, constant_handler)
            if VERIFICATION:
                temp_bbs = apply_opaque_mapping(temp_bbs, opaque_mapping, constant_handler=None) #do not reorder constant_handler twice

        if VERIFICATION:
            for (x, y) in zip([token for (_, block) in temp_bbs for insn in block for token in insn], func_tokens.iter_raw_tokens()):
                if x != y:
                    print(f"Token mismatch: {x} != {y}")
                    raise ValueError("Token mismatch in disassembly list")

        # Get metadata from constant handler
        opaque_metadata = constant_handler.get_metadata()
        meta_result = list(opaque_metadata.values())

        # Create token stream directly from temp_bbs (which already contains TokensRepl objects)
        # temp_tk = [tokens for (addr, tokens) in temp_bbs]

        tokenized_instructions, block_run_lengths, insn_run_lengths = (
            build_vocab_tokenize_and_index(func_tokens)
        )
        if len(tokenized_instructions) == 0:
            continue

        try:
            tokens_base64 = ndarray_to_base64(tokenized_instructions)
            block_base64 = ndarray_to_base64(block_run_lengths)
            insn_base64 = ndarray_to_base64(insn_run_lengths)
            
            with open(f"{path.absolute().name}_output.csv", "a", newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                if func_name == prev_func_name:
                    occurence += 1
                else:
                    occurence = 0
                row = [
                    func_name,  # Keep original function name unchanged
                    str(occurence),  # Add occurrence as separate column
                    tokens_base64,
                    block_base64,
                    insn_base64,
                    str(repr(meta_result))
                ]
                writer.writerow(row)
            prev_func_name = func_name


            if VERIFICATION:
                assert np.all(base64_to_ndarray_vec(tokens_base64) == tokenized_instructions), "Base64 conversion failed for tokens"
                assert np.all(base64_to_ndarray_vec(block_base64) == block_run_lengths), "Base64 conversion failed for block run lengths"
                assert np.all(base64_to_ndarray_vec(insn_base64) == insn_run_lengths), "Base64 conversion failed for instruction run lengths"
                # Create FunctionData instance
                function_data = FunctionData(
                    tokens=func_tokens,
                    tokens_base64=tokens_base64,
                    block_runlength_base64=block_base64,
                    instruction_runlength_base64=insn_base64,
                    opaque_metadata=repr(meta_result)
                )
                # Add all function data in one operation and get the final function name
                final_func_name = function_manager.add_function_data(
                    func_name, func_addr, temp_bbs, func_tokens, function_data
                )

                # Update legacy data structures for backward compatibility
                func_name_addr[final_func_name] = func_addr
                func_disas[final_func_name] = temp_bbs
                func_disas_token[final_func_name] = func_tokens
                func_names.append(final_func_name)


        except Exception as e:
            print(
                f"Error processing {func_name}: {e}.\nTokenstream: {func_tokens}\nTokens: {tokenized_instructions}\nBlock encoding: {block_run_lengths}\nInstructions: {insn_run_lengths}\nMetaData: {str(meta_result)}")
            raise ValueError

    # Compact arrays to save memory
    function_manager.compact_arrays()

    return function_manager


def build_vocab_tokenize_and_index(func_tokens: FunctionTokenList) -> tuple[npt.NDArray[np.int_], npt.NDArray[np.int_], npt.NDArray[np.int_]]:
    """
    Updated function to work with FunctionTokenList for efficient token processing.
    Now expects a FunctionTokenList instance instead of raw block data.
    """
    if func_tokens.last_index == 0:
        return np.array([], dtype=np.int_), np.array([], dtype=np.int_), np.array([], dtype=np.int_)

    # Get the used arrays from FunctionTokenList
    (token_ids, _, _, _,
     insn_idx_run_lengths, _,
     block_insn_run_lengths, _, _) = func_tokens.get_used_arrays()

    block_insn_split_start_indicies = np.cumsum(np.insert(block_insn_run_lengths[:-1], 0, 0))
    block_idx_run_lengths = np.add.reduceat(insn_idx_run_lengths, block_insn_split_start_indicies)

    return token_ids, block_idx_run_lengths, insn_idx_run_lengths


def run_tokenizer(path: Path) -> None:
    print(f"STARTING DISASSEMBLY")

    file_path: Path = path.absolute()
    # file_path = Path("../src/clamav/x86-gcc-5-O3_minigzipsh").absolute()
    pickle_file_path = file_path.parent / f"{file_path.name}.pkl"
    pickle_mainloop_file_path = file_path.parent / f"{file_path.name}.mainloop.pkl"
    with_pickled = False
    start_time = time.time()

    if pickle_mainloop_file_path.exists():
        print("loading existing mainloop pickle to speed up")
        with open(pickle_mainloop_file_path, "rb") as f:
            kvargs = pickle.load(f)
            if "path" not in kvargs:
                kvargs["path"] = file_path
            with_pickled = True
        print(f"Pickle loading time: {time.time() - start_time:.2f} seconds")
    elif pickle_file_path.exists():
        print("loading existing pickle to speed up")
        with open(pickle_file_path, "rb") as f:
            kvargs = pickle.load(f)

        print(f"Pickle loading time: {time.time() - start_time:.2f} seconds")
    else:
        project: angr.Project = angr.Project(file_path, auto_load_libs=False)  # was False
        constants: dict[str, list[str]] = parse_and_save_data_sections(project)
        cfg: angr.analyses.cfg.cfg_fast.CFGFast = project.analyses.CFGFast(normalize=True)

        kvargs: dict = dict(project=project, path=file_path, cfg=cfg, constant_list=constants)
        print(f"Preparation stage 1 time: {time.time() - start_time:.2f} seconds")
        start_time = time.time()
        with open(pickle_file_path, "wb") as f:
            pickle.dump(kvargs, f)

        print(f"Pickle (prep only) saving time: {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print(f"Calling lowlevel_disas")
    (func_names, function_manager, vocab_manager) = disassemble_to_tokens(with_pickled=with_pickled, **kvargs)
    disassembly_time = time.time() - start_time
    print(f"Disassembly time: {disassembly_time:.2f} seconds")

    print(f"WRITING OUTPUT")
    """
    with open("output.csv", "w", newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        # Write header with occurrence column added
        writer.writerow(['function_name', 'occurrence', 'tokens_base64', 'block_runlength_base64', 'instruction_runlength_base64', 'opaque_metadata', f'"{",".join(vocab_manager.id_to_token)}"'])

        # Use the sorted iterator from function_manager
        prev_name = ""
        prev_row = ""
        for func_name, occurrence, function_data in function_manager.iter_function_data():
            row = [
                func_name,  # Keep original function name unchanged
                occurrence,  # Add occurrence as separate column
                function_data.tokens_base64,
                function_data.block_runlength_base64,
                function_data.instruction_runlength_base64,
                str(function_data.opaque_metadata)
            ]
            writer.writerow(row)
            prev_name = func_name
            prev_row = str(row)"""

    if VERIFICATION:
        print("VERIFY OUTPUT")
        # datastructures_to_insn(vocab=vocab, block_run_length_dict=block_runlength, insn_runlength_dict=insn_runlength, token_dict=tokens, duplicate_map=duplicate_map)
        # vocab: list[str] = vocab_from_output("output.csv")
        # token_man = VocabularyManager.from_vocab(platform="x86", vocab_list=vocab)
        for (name, dublicate_idx, tokensRC) in token_to_functions("output.csv"):
            original = function_manager.get_function_data(name, dublicate_idx)
            tokensOG = original.tokens

            assert tokensRC.insn_count == original.tokens.insn_count
            assert tokensRC.block_count == original.tokens.block_count
            assert tokensRC.last_index == original.tokens.last_index
            iterRC = tokensRC.iter_tokens() #here we resolve to check the vocab manager
            iterOG = tokensOG.iter_raw_tokens() #for og we do not care are resolving does not change equality

            for (x, y) in zip(iterRC, iterOG):
                if x != y:
                    print(f"Token mismatch: {x} != {y}")
                    raise ValueError("Token mismatch in disassembly list")

            #iterators should both be done, but zip stops at the shortest one
            assert next(iterRC, None) is None, "Reconstructed function contains more tokens than original"
            assert next(iterOG, None) is None, "Reconstructed functions missing tokens from original"

        print("Verification complete.")


def main():
    parser = argparse.ArgumentParser(description="Tokenize binaries for BinAI.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--batch', type=str, metavar='QUEUE_FILE', help='Process a batch of binaries from a queue file')
    group.add_argument('--single', type=str, metavar='BINARY_FILE', help='Process a single binary file')
    group.add_argument('--debugs', action='store_true', help='Debug mode: process ../src/clamav/x86-gcc-5-O3_minigzipsh')
    group.add_argument('--debugl', action='store_true', help='Debug mode: process ../src/clamav/x86-clang-5.0-O1_sigtool')
    args = parser.parse_args()

    if args.batch:
        queue_file = args.batch
        print(f"[*] Filtering queue: {queue_file}")
        filter_queue_file_by_existing_output(queue_file)
        print(f"Using queue: {queue_file}")
        while True:
            binary_path_str: str | None = pop_first_line(queue_file)
            if binary_path_str is None:
                print("Queue is empty. Exiting.")
                break
            binary_path = Path(binary_path_str).resolve()
            print(f"\n[*] Processing binary: {binary_path}")
            run_tokenizer(binary_path)
    elif args.single:
        binary_path = Path(args.single).resolve()
        print(f"[*] Processing single binary: {binary_path}")
        run_tokenizer(binary_path)
    elif args.debugs:
        binary_path = SCRIPT_FOLDER / "../src/clamav/x86-gcc-5-O3_minigzipsh"
        print(f"[*] Debug mode (gcc): {binary_path}")
        run_tokenizer(binary_path)
    elif args.debugl:
        binary_path = SCRIPT_FOLDER / "../src/clamav/x86-clang-5.0-O1_sigtool"
        print(f"[*] Debug mode (clang): {binary_path}")
        run_tokenizer(binary_path)

if __name__ == "__main__":
    print("loading")
    import sys, csv

    maxInt = sys.maxsize
        # decrease the maxInt value by factor 10
        # as long as the OverflowError occurs.

    while True:
        try:
            csv.field_size_limit(maxInt)
            break
        except OverflowError:
            maxInt = int(maxInt / 10)

    print("running main")
    main()
