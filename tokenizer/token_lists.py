import numpy as np
from typing import Iterator, Optional

from tokenizer.tokens import Tokens, TokenType, TokenRaw
from tokenizer.token_manager import VocabularyManager


class InsnTokenIterator:
    """Iterator for tokens in an InsnTokenList"""

    def __init__(self, insn_token_list: 'InsnTokenList', use_resolved: bool = False):
        self.insn_token_list = insn_token_list
        self.current_index = 0
        self.use_resolved = use_resolved

    def __iter__(self) -> Iterator[TokenRaw]:
        return self

    def __next__(self) -> TokenRaw:
        if self.current_index >= self.insn_token_list.last_index:
            raise StopIteration

        if self.use_resolved:
            if self.insn_token_list.vocab_manager is None:
                raise ValueError("VocabularyManager is required for resolved token iteration")
            token = self.insn_token_list.vocab_manager.create_token_from_insn_list(
                self.insn_token_list, self.current_index
            )
        else:
            token = self.insn_token_list.get_raw_token_at(self.current_index)

        self.current_index += 1
        return token


class InsnTokenList:
    """Efficient token list for a single instruction using numpy arrays"""

    def from_insn_token_list(tokens: list[Tokens], insn_str: str = "", vocab_manager: Optional['VocabularyManager']=None) -> 'InsnTokenList':
        """Create a BlockTokenList from a list of InsnTokenLists"""
        block = InsnTokenList(vocab_manager=vocab_manager, insn_str=insn_str)
        for token in tokens:
            if not isinstance(token, Tokens):
                raise TypeError(f"Expected Tokens instance, got {type(token)}")
            block.append(token)


        return block

    def __init__(self, insn_str: str = None, vocab_manager: Optional['VocabularyManager'] = None, init=True):
        # Initialize arrays
        if init:
            self.token_ids = np.zeros(20, dtype=np.int16)
            self.token_type_ids = np.zeros(10, dtype=np.int8)
            self.token_start_lookup = np.zeros(10, dtype=np.int32)
            self.insn_str = np.array([insn_str], dtype=object)
        elif insn_str is not None:
            raise ValueError("Cannot initialize InsnTokenList with insn_str if init=False")

        self.last_index = 0
        self.vocab_manager = vocab_manager
        self.view_parent: Optional['BlockTokenList'] = None
        self.readonly = False

    def set_vocab_manager(self, vocab_manager: 'VocabularyManager'):
        """Set the vocabulary manager for token reconstruction"""
        self.vocab_manager = vocab_manager

    def __iter__(self) -> Iterator[TokenRaw]:
        """Return an iterator for the raw tokens in this instruction"""
        return InsnTokenIterator(self, use_resolved=False)

    def iter_tokens(self) -> Iterator[Tokens]:
        """Return an iterator for the resolved tokens in this instruction"""
        return InsnTokenIterator(self, use_resolved=True)

    def get_raw_token_at(self, index: int) -> TokenRaw:
        """Get a specific raw token by index"""
        if index < 0 or index >= self.last_index:
            raise IndexError(f"Token index {index} out of bounds (0 to {self.last_index - 1})")

        token_type = TokenType(self.token_type_ids[index])

        # Get token IDs for this specific token
        start_pos = self.token_start_lookup[index-1] if index > 0 else 0
        if index == self.last_index - 1:
            end_pos = len(self.get_used_token_ids())
        else:
            end_pos = self.token_start_lookup[index]

        token_ids = self.token_ids[start_pos:end_pos]
        raw_token_class = TokenRaw.with_type(token_type)
        return raw_token_class(token_ids)

    def append(self, token: Tokens):
        """Add a token to the instruction token list"""
        if self.readonly:
            raise RuntimeError("Cannot append to readonly InsnTokenList")

        token_type = token.token_type
        token_ids = token.get_token_ids()
        num_token_ids = len(token_ids)

        # Ensure capacity for one more type and the token IDs
        self._ensure_capacity(num_token_ids+1, 1)

        # Get start position (assume -1 index equals 0)
        start_pos = self.token_start_lookup[self.last_index - 1] if self.last_index > 0 else 0

        # Add token IDs
        self.token_ids[start_pos:start_pos + num_token_ids] = token_ids

        # Set token type
        self.token_type_ids[self.last_index] = token_type

        # Set token start position
        self.token_start_lookup[self.last_index] = start_pos + num_token_ids

        self.last_index += 1

    def extend(self, tokens: list[Tokens]):
        """Add multiple tokens to the instruction token list"""
        if self.readonly:
            raise RuntimeError("Cannot extend readonly InsnTokenList")

        for token in tokens:
            if not isinstance(token, Tokens):
                raise TypeError(f"Expected Tokens instance, got {type(token)}")
            self.append(token)

    def _ensure_capacity(self, token_idx_needed: int, types_needed: int):
        """Ensure arrays have enough capacity"""
        current_end = self.token_start_lookup[self.last_index - 1] if self.last_index > 0 else 0

        if self.view_parent is not None:
            # Ask parent to resize instead
            self.view_parent._resize_view_arrays(current_end + token_idx_needed, self.last_index + types_needed)
            return

        # Resize token_ids if needed
        if current_end + token_idx_needed > len(self.token_ids):
            new_size = max(len(self.token_ids) * 2, current_end + token_idx_needed)
            self.token_ids.resize(new_size, refcheck=False)

        # Resize type arrays if needed
        if self.last_index + types_needed > len(self.token_type_ids):
            new_size = max(len(self.token_type_ids) * 2, self.last_index + types_needed)

            self.token_type_ids.resize(new_size, refcheck=False)
            self.token_start_lookup.resize(new_size, refcheck=False)

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
            self.insn_str
        )

    def _get_last_token_length(self) -> int:
        """Get the length of the last token"""
        if self.last_index == 0:
            return 0
        if self.last_index == 1:
            return int(self.token_start_lookup[0])
        return int(self.token_start_lookup[self.last_index - 1] - self.token_start_lookup[self.last_index - 2])


    def to_asm_original(self) -> str:
        """Convert the block to an original assembly-like string representation"""
        return str(self.insn_str[0]) if self.insn_str[0] is not None else ""

    def to_asm_like(self) -> str:
        """Convert the block to an assembly-like string representation"""
        return " ".join(t.to_asm_like() for t in self.iter_tokens())

    def __repr__(self):
        """String representation of the block"""
        return f"{self.__class__.__name__}[{" ".join(repr(t) for t in self.iter_tokens())}]"

    def __str__(self):
        """String representation of the block"""
        return f"[{" ".join(str(t) for t in self.iter_tokens())}]"


class BlockTokenList:

    def __init__(self, num_insns: int, vocab_manager: Optional['VocabularyManager'] = None, init=True):
        self.vocab_manager = vocab_manager
        if init:
            # Initialize arrays with estimated sizes
            token_ids_size = num_insns * 8
            type_lookup_size = num_insns * 4 + 2

            self.token_ids = np.zeros(token_ids_size, dtype=np.int16)
            self.token_type_ids = np.zeros(type_lookup_size, dtype=np.int8)
            self.token_start_lookup = np.zeros(type_lookup_size, dtype=np.int32)
            self.insn_run_lengths = np.zeros(num_insns + 2, dtype=np.int8)
            self.insn_idx_run_lengths = np.zeros(num_insns + 2, dtype=np.int8)
            self.insn_strs = np.zeros(num_insns + 2, dtype=object)

        self.last_index = 0
        self.insn_count = 0
        self.view_child: Optional['InsnTokenList'] = None
        self.view_parent: Optional['FunctionTokenList'] = None
        self.readonly = False

    def set_vocab_manager(self, vocab_manager: 'VocabularyManager'):
        """Set the vocabulary manager for token reconstruction"""
        self.vocab_manager = vocab_manager

    def view(self, insn_str: str) -> 'InsnTokenList':
        """Create a view child that uses the remaining buffer of this BlockTokenList"""
        if self.view_child is not None:
            raise RuntimeError("BlockTokenList already has an active view child")

        # Create InsnTokenList without initializing arrays
        view_child = InsnTokenList(vocab_manager=self.vocab_manager, init=False)

        # Give the view child access to the remaining buffer
        current_token_pos = int(self.token_start_lookup[self.last_index - 1]) if self.last_index > 0 else 0

        # Create views into the remaining buffer
        view_child.token_ids = self.token_ids[current_token_pos:]
        view_child.token_type_ids = self.token_type_ids[self.last_index:]
        view_child.token_start_lookup = self.token_start_lookup[self.last_index:]
        view_child.insn_str = self.insn_strs[self.insn_count:self.insn_count + 1]
        view_child.insn_str[0] = insn_str


        # Set up the view relationship
        view_child.view_parent = self

        self.view_child = view_child

        return view_child

    def append_as_insn(self, insn_str: str, tokens: list[Tokens]):
        view = self.view(insn_str)
        view.extend(tokens)
        self.add_insn(view)

    def add_insn(self, insn_token_list: InsnTokenList):
        """Add an instruction token list to the block"""
        if not isinstance(insn_token_list, InsnTokenList):
            raise TypeError(f"Expected InsnTokenList, got {type(insn_token_list)}")

        if self.view_child is not None and insn_token_list.view_parent is not self:
            raise RuntimeError("Cannot add instruction while view child is active")

        if insn_token_list.last_index == 0:
            return

        (new_token_ids,
        new_token_type_ids,
        new_token_start_lookup,
        new_insn_strs) = insn_token_list.get_used_arrays()

        new_tokens = len(new_token_ids)
        new_types = len(new_token_type_ids)
        is_view_child = insn_token_list.view_parent is self

        start_pos = self.token_start_lookup[self.last_index - 1] if self.last_index > 0 else 0

        # Handle token data
        if is_view_child:
            self.token_start_lookup[self.last_index :self.last_index + new_types] += start_pos
            self.view_child.token_start_lookup = None
            insn_token_list.readonly = True
            self.view_child = None
        else:
            self._ensure_capacity(new_tokens + 1, new_types + 1)
            # Copy token IDs and types
            self.token_ids[start_pos:start_pos + new_tokens] = new_token_ids
            self.token_type_ids[self.last_index:self.last_index + new_types] = new_token_type_ids
            self.token_start_lookup[self.last_index:self.last_index + new_types] = new_token_start_lookup + start_pos
            self.insn_strs[self.insn_count] = new_insn_strs[0]

        # Update metadata (same for both paths)
        self.insn_run_lengths[self.insn_count] = new_types
        self.insn_idx_run_lengths[self.insn_count] = new_tokens

        # Update counters
        self.last_index += new_types
        self.insn_count += 1


    def _resize_view_arrays(self, tokens_idx_needed: int, types_needed: int):
        """Resize arrays for view child"""
        if self.view_child is None:
            raise RuntimeError("No active view child")

        # Resize our arrays
        self._ensure_capacity(tokens_idx_needed, types_needed)

        # Update the view child's arrays to point to the new locations
        current_token_pos = int(self.token_start_lookup[self.last_index - 1]) if self.last_index > 0 else 0
        self.view_child.token_ids = self.token_ids[current_token_pos:]
        self.view_child.token_type_ids = self.token_type_ids[self.last_index:]
        self.view_child.token_start_lookup = self.token_start_lookup[self.last_index:]

    def _ensure_capacity(self, token_idx_needed: int, types_needed: int):
        """Ensure arrays have enough capacity"""
        current_token_pos = int(self.token_start_lookup[self.last_index - 1]) if self.last_index > 0 else 0

        if self.view_parent is not None:
            # Ask parent to resize instead
            self.view_parent._resize_view_arrays(current_token_pos + token_idx_needed, self.last_index + types_needed, 1)
            return

        # Resize token_ids if needed
        if current_token_pos + token_idx_needed > len(self.token_ids):
            new_size = max(len(self.token_ids) * 2, current_token_pos + token_idx_needed)
            self.token_ids.resize(new_size, refcheck=False)

        # Resize type arrays if needed
        if self.last_index + types_needed > len(self.token_type_ids):
            new_size = max(len(self.token_type_ids) * 2, self.last_index + types_needed)

            self.token_type_ids.resize(new_size, refcheck=False)
            self.token_start_lookup.resize(new_size, refcheck=False)

        # Resize instruction arrays if needed
        if self.insn_count + 1 >= len(self.insn_run_lengths):
            new_size = len(self.insn_run_lengths) * 2

            self.insn_run_lengths.resize(new_size, refcheck=False)
            self.insn_idx_run_lengths.resize(new_size, refcheck=False)
            self.insn_strs.resize(new_size, refcheck=False)

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
            self.insn_strs[:self.insn_count]
        )

    def _get_last_token_length(self) -> int:
        """Get the length of the last token"""
        if self.last_index == 0:
            return 0
        if self.last_index == 1:
            return int(self.token_start_lookup[0])
        return int(self.token_start_lookup[self.last_index - 1] - self.token_start_lookup[self.last_index - 2])

    def iter_insn(self, transient=False) -> Iterator[InsnTokenList]:
        """Return an iterator for the tokens in this block"""
        idx_last = 0
        token_last = 0
        token_list = None

        for insn_i in range(self.insn_count):

            if token_list is None or not transient:
                token_list = InsnTokenList(vocab_manager=self.vocab_manager, init=False)
                token_list.readonly = True

            idx_len = int(self.insn_idx_run_lengths[insn_i])
            token_len = int(self.insn_run_lengths[insn_i])
            if idx_len == 0 or token_len == 0:
                raise RuntimeError(f"Invalid token length idx_len={idx_len} token_len={token_len} for instruction {insn_i}")

            token_list.token_ids = self.token_ids[idx_last:idx_last + idx_len]
            if token_list.token_ids.size == 0:
                raise RuntimeError(f"Token IDs for instruction {insn_i} are empty")

            token_list.token_start_lookup = self.token_start_lookup[token_last:token_last + token_len] - (self.token_start_lookup[token_last - 1] if token_last > 0 else 0)
            token_list.token_type_ids = self.token_type_ids[token_last:token_last + token_len]
            token_list.insn_str = self.insn_strs[insn_i:insn_i + 1]
            token_list.last_index = token_len

            yield token_list

            idx_last += idx_len
            token_last += token_len

    def iter_tokens(self) -> Iterator[Tokens]:
        """Return an iterator for the resolved tokens in this block"""
        for insn in self.iter_insn(True):
            for token in insn.iter_tokens():
                yield token

    def iter_raw_tokens(self) -> Iterator[TokenRaw]:
        """Return an iterator for raw tokens in this instruction"""
        for insn in self.iter_insn(True):
            for token in insn:
                yield token

    def get_raw_token_at(self, index: int) -> TokenRaw:
        """Get a specific raw token by index"""
        if index < 0 or index >= self.last_index:
            raise IndexError(f"Token index {index} out of bounds (0 to {self.last_index - 1})")

        token_type = TokenType(self.token_type_ids[index])

        # Get token IDs for this specific token
        start_pos = self.token_start_lookup[index-1] if index > 0 else 0
        if index == self.last_index - 1:
            end_pos = len(self.get_used_token_ids())
        else:
            end_pos = self.token_start_lookup[index]

        token_ids = self.token_ids[start_pos:end_pos]
        raw_token_class = TokenRaw.with_type(token_type)
        return raw_token_class(token_ids)

    def to_asm_original(self) -> str:
        """Convert the block to an original assembly-like string representation"""
        if self.insn_count == 0:
            return "-empty-"

        return f"{self.insn_strs[0]}: [" + "], [".join(asm_str for asm_str in self.insn_strs[1:self.insn_count]) + "]"

    def to_asm_like(self) -> str:
        """Convert the block to an assembly-like string representation"""
        return "; ".join(t.to_asm_like() for t in self.iter_insn(True))

    def __repr__(self):
        """String representation of the block"""
        return f"{self.__class__.__name__}(insn_count={self.insn_count}, insn={", ".join(repr(t) for t in self.iter_insn(True))})"

    def __str__(self):
        """String representation of the block"""
        return f"BlockTokenList(insn_count={self.insn_count}, tokens={" ".join(str(t) for t in self.iter_insn(True))})"
