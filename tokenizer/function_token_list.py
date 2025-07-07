import numpy as np
from typing import Iterator, Optional

from tokenizer.tokens import Tokens
from tokenizer.token_lists import InsnTokenList, BlockTokenList


class FunctionTokenList:
    """Efficient token list for a function using numpy arrays with three levels of run-length encoding"""

    def __init__(self, num_blocks: int, vocab_manager: Optional['VocabularyManager'] = None, init: bool = True):
        self.vocab_manager = vocab_manager

        if init:
            # Initialize arrays with estimated sizes
            # Estimate based on average tokens per block and instructions per block
            token_ids_size = num_blocks * 32  # ~32 tokens per block on average
            type_lookup_size = num_blocks * 16 + 2  # ~16 types per block
            insn_size = num_blocks * 4 + 2  # ~4 instructions per block


            # Token-level arrays (level 0)
            self.token_ids = np.zeros(token_ids_size, dtype=np.int16)
            self.token_type_ids = np.zeros(type_lookup_size, dtype=np.int8)
            self.token_start_lookup = np.zeros(type_lookup_size, dtype=np.int32)

            # Instruction-level arrays (level 1)
            self.insn_run_lengths = np.zeros(insn_size, dtype=np.int8)
            self.insn_idx_run_lengths = np.zeros(insn_size, dtype=np.int8)
            self.insn_strs = np.zeros(insn_size, dtype=object)

            # Block-level arrays (level 2)
            self.block_insn_run_lengths = np.zeros(num_blocks + 2, dtype=np.int32)
            self.block_token_run_lengths = np.zeros(num_blocks + 2, dtype=np.int32)
            self.block_addrs = np.zeros(num_blocks + 2, dtype=object)

        self.last_index = 0  # Last token index
        self.insn_count = 0  # Total instruction count
        self.block_count = 0  # Total block count
        self.view_child: Optional['BlockTokenList'] = None

        self.view_parent: Optional['FunctionTokenList'] = None  # Parent FunctionTokenList if this is a view child


    @staticmethod
    def reconstruct_func_from_raw_bytes(tokens, block_runlength, insn_runlength, vocab_manager: Optional['VocabularyManager'] = None) -> str:
        """Remaps token ids to string representation."""
        new_list = FunctionTokenList(
            num_blocks=-1,
            vocab_manager=vocab_manager, init=False
        )
        # Token-level arrays (level 0)
        new_list.token_ids = tokens
        print(f"Token list: {new_list.token_ids}")
        types = [t.value for t in vocab_manager.id_to_token_type]
        print(f"Token types: {types}")
        new_list.token_type_ids = np.array(vocab_manager.id_to_token_type)[new_list.token_ids]
        print(new_list.token_type_ids)
        new_list.token_start_lookup = None # TODO

        # Instruction-level arrays (level 1)
        new_list.insn_run_lengths = insn_runlength
        print(f"Insn Run lengths: {new_list.insn_run_lengths}")
        new_list.insn_idx_run_lengths = None # TODO
        new_list.insn_strs = None # TODO

        # Block-level arrays (level 2)
        new_list.block_insn_run_lengths = block_runlength
        print(f"Block run length: {new_list.block_insn_run_lengths}")
        new_list.block_token_run_lengths = None # TODO
        new_list.block_addrs = None # TODO


        raise ValueError

        return ""



    @staticmethod
    def with_same_size(other: 'FunctionTokenList', vocab_manager: Optional['VocabularyManager'] = None) -> 'FunctionTokenList':
        """Create a new FunctionTokenList with the same array sizes as another"""
        new_list = FunctionTokenList(
            num_blocks=len(other.block_insn_run_lengths),
            vocab_manager=vocab_manager, init=False
        )
        # Resize arrays to match other's used sizes
        new_list.token_ids = np.zeros_like(other.token_ids)
        new_list.token_type_ids = np.zeros_like(other.token_type_ids)
        new_list.token_start_lookup = np.zeros_like(other.token_start_lookup)
        new_list.insn_run_lengths = np.zeros_like(other.insn_run_lengths)
        new_list.insn_idx_run_lengths = np.zeros_like(other.insn_idx_run_lengths)
        new_list.insn_strs = np.zeros_like(other.insn_strs)
        new_list.block_insn_run_lengths = np.zeros_like(other.block_insn_run_lengths)
        new_list.block_token_run_lengths = np.zeros_like(other.block_token_run_lengths)
        new_list.block_addrs = np.zeros_like(other.block_addrs)
        return new_list


    def set_vocab_manager(self, vocab_manager: 'VocabularyManager'):
        """Set the vocabulary manager for token reconstruction"""
        self.vocab_manager = vocab_manager

    def view(self) -> 'BlockTokenList':
        """Create a view child BlockTokenList that uses the remaining buffer of this FunctionTokenList"""
        if self.view_child is not None:
            raise RuntimeError("FunctionTokenList already has an active view child")

        # Create BlockTokenList without initializing arrays
        view_child = BlockTokenList(-1, vocab_manager=self.vocab_manager, init=False)

        # Give the view child access to the remaining buffer
        current_token_pos = int(self.token_start_lookup[self.last_index - 1]) if self.last_index > 0 else 0

        # Create views into the remaining buffer
        view_child.token_ids = self.token_ids[current_token_pos:]
        view_child.token_type_ids = self.token_type_ids[self.last_index:]
        view_child.token_start_lookup = self.token_start_lookup[self.last_index:]
        view_child.insn_run_lengths = self.insn_run_lengths[self.insn_count:]
        view_child.insn_idx_run_lengths = self.insn_idx_run_lengths[self.insn_count:]
        view_child.insn_strs = self.insn_strs[self.insn_count:]

        # Set up the view relationship
        view_child.view_parent = self
        self.view_child = view_child

        return view_child


    def add_block(self, block_token_list: BlockTokenList, block_addr: str):
        """Add a block token list to the function"""
        if not isinstance(block_token_list, BlockTokenList):
            raise TypeError(f"Expected InsnTokenList, got {type(block_token_list)}")

        if self.view_child is not None and block_token_list.view_parent is not self:
            raise RuntimeError("Cannot add block while view child is active")

        if block_token_list.last_index == 0:
            return

        (new_token_ids,
         new_token_type_ids,
         new_token_start_lookup,
         new_insn_run_lengths,
         new_insn_strs) = block_token_list.get_used_arrays()

        # Check if we need to resize arrays
        new_tokens = len(new_token_ids)
        new_types = len(new_token_type_ids)
        new_insns = len(new_insn_run_lengths)
        is_view_child = block_token_list.view_parent is self

        start_pos = self.token_start_lookup[self.last_index - 1] if self.last_index > 0 else 0

        # Handle token data
        if is_view_child:
            # For view child, data is already in place, just update metadata
            self.token_start_lookup[self.last_index:self.last_index + new_types] += start_pos
            self.view_child = None
            block_token_list.readonly = True
        else:
            # For non-view child, copy the data
            self._ensure_capacity(new_tokens+1, new_types+1, new_insns+1)

            # Copy token IDs
            self.token_ids[start_pos:start_pos + new_tokens] = new_token_ids

            # Copy token types
            self.token_type_ids[self.last_index:self.last_index + new_types] = new_token_type_ids
            self.token_start_lookup[self.last_index:self.last_index + new_types] = new_token_start_lookup[:] + start_pos

            # Copy instruction data
            self.insn_run_lengths[self.insn_count:self.insn_count + new_insns] = new_insn_run_lengths
            # Calculate insn_idx_run_lengths from block's data
            block_insn_idx_run_lengths = block_token_list.insn_idx_run_lengths[:block_token_list.insn_count]
            self.insn_idx_run_lengths[self.insn_count:self.insn_count + new_insns] = block_insn_idx_run_lengths
            self.insn_strs[self.insn_count:self.insn_count + new_insns] = new_insn_strs

        # Store block-level data (same for both paths)
        self.block_addrs[self.block_count] = block_addr
        self.block_insn_run_lengths[self.block_count] = new_insns
        self.block_token_run_lengths[self.block_count] = new_types

        # Update counters
        self.last_index += new_types
        self.insn_count += new_insns
        self.block_count += 1

    def _resize_view_arrays(self, tokens_needed: int, types_needed: int, insns_needed: int):
        """Resize arrays for view child"""
        if self.view_child is None:
            raise RuntimeError("No active view child")

        # Resize our arrays
        self._ensure_capacity(tokens_needed, types_needed, insns_needed)

        # Update the view child's arrays to point to the new locations
        current_token_pos = int(self.token_start_lookup[self.last_index - 1]) if self.last_index > 0 else 0
        self.view_child.token_ids = self.token_ids[current_token_pos:]
        self.view_child.token_type_ids = self.token_type_ids[self.last_index:]
        self.view_child.token_start_lookup = self.token_start_lookup[self.last_index:]
        self.view_child.insn_run_lengths = self.insn_run_lengths[self.insn_count:]
        self.view_child.insn_idx_run_lengths = self.insn_idx_run_lengths[self.insn_count:]
        self.view_child.insn_strs = self.insn_strs[self.insn_count:]

    def get_used_token_ids(self) -> np.ndarray:
        """Get the used portion of token_ids array"""
        if self.last_index == 0:
            return np.array([], dtype=np.int32)

        # Use the last token's end position
        end_pos = int(self.token_start_lookup[self.last_index - 1])
        return self.token_ids[:end_pos]

    def _get_end_position(self) -> int:
        """Get the end position of used tokens"""
        if self.last_index == 0:
            return 0
        return int(self.token_start_lookup[self.last_index - 1])

    def get_used_arrays(self) -> tuple:
        """Get the used portions of all arrays"""
        end_pos = self._get_end_position()
        return (
            self.token_ids[:end_pos],
            self.token_type_ids[:self.last_index],
            self.token_start_lookup[:self.last_index],
            self.insn_run_lengths[:self.insn_count],
            self.insn_idx_run_lengths[:self.insn_count],
            self.insn_strs[:self.insn_count],
            self.block_insn_run_lengths[:self.block_count],
            self.block_token_run_lengths[:self.block_count],
            self.block_addrs[:self.block_count]
        )

    def _get_last_token_length(self) -> int:
        """Get the length of the last token"""
        if self.last_index == 0:
            return 0
        if self.last_index == 1:
            return int(self.token_start_lookup[0])
        return int(self.token_start_lookup[self.last_index - 1] - self.token_start_lookup[self.last_index - 2])

    def iter_blocks(self, transient=False) -> Iterator[BlockTokenList]:
        """Return an iterator for the blocks in this function"""

        token_last = 0
        insn_last = 0
        block_token_list = None

        for block_i in range(self.block_count):
            token_len = int(self.block_token_run_lengths[block_i])
            insn_len = int(self.block_insn_run_lengths[block_i])


            if block_token_list is None or not transient:
                block_token_list = BlockTokenList(0, vocab_manager=self.vocab_manager, init=False)
                block_token_list.readonly = True

            # Calculate token indices for this block
            token_start = int(self.token_start_lookup[token_last - 1]) if token_last > 0 else 0
            token_end = int(self.token_start_lookup[token_last + token_len - 1])
            token_ids_len = int(token_end - token_start)

            # Set up the block token list
            block_token_list.token_ids = self.token_ids[token_start:token_end]
            block_token_list.token_type_ids = self.token_type_ids[token_last:token_last + token_len]
            block_token_list.token_start_lookup = self.token_start_lookup[token_last:token_last + token_len] - token_start
            block_token_list.insn_run_lengths = self.insn_run_lengths[insn_last:insn_last + insn_len]
            block_token_list.insn_idx_run_lengths = self.insn_idx_run_lengths[insn_last:insn_last + insn_len]
            block_token_list.insn_strs = self.insn_strs[insn_last:insn_last + insn_len]
            block_token_list.last_index = token_len
            block_token_list.insn_count = insn_len

            yield block_token_list

            token_last += token_len
            insn_last += insn_len

    def iter_insns(self, transient=False) -> Iterator[InsnTokenList]:
        """Return an iterator for all instructions in this function"""
        for block in self.iter_blocks(transient):
            for insn in block.iter_insn(transient):
                yield insn

    def iter_tokens(self) -> Iterator[Tokens]:
        """Return an iterator for all tokens in this function"""
        for insn in self.iter_insns(True):
            for token in insn:
                yield token

    def to_asm_original(self) -> str:
        """Convert the function to an original assembly-like string representation"""
        if self.block_count == 0:
            return "-empty-"

        blocks = []
        for i, block in enumerate(self.iter_blocks(True)):
            block_addr = self.block_addrs[i]
            block_asm = block.to_asm_original()
            blocks.append(f"{block_addr}: {block_asm}")

        return " | ".join(blocks)

    def to_asm_like(self) -> str:
        """Convert the function to an assembly-like string representation"""
        return " | ".join(block.to_asm_like() for block in self.iter_blocks(True))

    def __repr__(self):
        """String representation of the function"""
        return f"{self.__class__.__name__}(block_count={self.block_count}, blocks={", ".join(repr(b) for b in self.iter_blocks(True))})"

    def __str__(self):
        """String representation of the function"""
        return f"FunctionTokenList(block_count={self.block_count}, insn_count={self.insn_count}, tokens={" ".join(str(b) for b in self.iter_blocks(True))})"

    def _ensure_capacity(self, tokens_needed: int, types_needed: int, insns_needed: int):
        """Ensure arrays have enough capacity"""
        current_token_pos = int(self.token_start_lookup[self.last_index - 1]) if self.last_index > 0 else 0

        # Resize token_ids if needed
        if current_token_pos + tokens_needed > len(self.token_ids):
            new_size = max(len(self.token_ids) * 2, current_token_pos + tokens_needed)
            if new_size > 2**16:
                1

            new_token_ids = np.zeros(new_size, dtype=np.int32)
            new_token_ids[:len(self.token_ids)] = self.token_ids
            self.token_ids = new_token_ids

        # Resize type arrays if needed
        if self.last_index + types_needed > len(self.token_type_ids):
            new_size = max(len(self.token_type_ids) * 2, self.last_index + types_needed)

            new_token_type_ids = np.zeros(new_size, dtype=np.int32)
            new_token_start_lookup = np.zeros(new_size, dtype=np.int32)

            new_token_type_ids[:len(self.token_type_ids)] = self.token_type_ids
            new_token_start_lookup[:len(self.token_start_lookup)] = self.token_start_lookup

            self.token_type_ids = new_token_type_ids
            self.token_start_lookup = new_token_start_lookup

        # Resize instruction arrays if needed
        if self.insn_count + insns_needed + 1 > len(self.insn_run_lengths):
            new_size = max(len(self.insn_run_lengths) * 2, self.insn_count + insns_needed)

            new_insn_run_lengths = np.zeros(new_size, dtype=np.int32)
            new_insn_idx_run_lengths = np.zeros(new_size, dtype=np.int32)
            new_insn_strs = np.zeros(new_size, dtype=object)

            new_insn_run_lengths[:len(self.insn_run_lengths)] = self.insn_run_lengths
            new_insn_idx_run_lengths[:len(self.insn_idx_run_lengths)] = self.insn_idx_run_lengths
            new_insn_strs[:len(self.insn_strs)] = self.insn_strs

            self.insn_run_lengths = new_insn_run_lengths
            self.insn_idx_run_lengths = new_insn_idx_run_lengths
            self.insn_strs = new_insn_strs

        # Resize block arrays if needed
        if self.block_count >= len(self.block_insn_run_lengths):
            new_size = len(self.block_insn_run_lengths) * 2

            new_block_insn_run_lengths = np.zeros(new_size, dtype=np.int32)
            new_block_token_run_lengths = np.zeros(new_size, dtype=np.int32)
            new_block_addrs = np.zeros(new_size, dtype=object)

            new_block_insn_run_lengths[:len(self.block_insn_run_lengths)] = self.block_insn_run_lengths
            new_block_token_run_lengths[:len(self.block_token_run_lengths)] = self.block_token_run_lengths
            new_block_addrs[:len(self.block_addrs)] = self.block_addrs

            self.block_insn_run_lengths = new_block_insn_run_lengths
            self.block_token_run_lengths = new_block_token_run_lengths
            self.block_addrs = new_block_addrs

    def iter_raw_tokens(self) -> Iterator['TokenRaw']:
        """Return an iterator for all raw tokens in this function"""
        for block in self.iter_blocks(True):
            for raw_token in block.iter_raw_tokens():
                yield raw_token
