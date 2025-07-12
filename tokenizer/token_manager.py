import typing
from abc import ABC, abstractmethod
from typing import List
import numpy as np
import numpy.typing as npt

from tokenizer.architecture import PlatformInstructionTypes
from tokenizer.token_utils import TokenUtils
from tokenizer.tokens import Tokens, TokenType, PlatformToken, ValuedConstToken, IdentifierToken, BlockDefToken, \
    BlockToken, OpaqueConstToken, MemoryOperandToken, MemoryOperandSymbol, LitTokenType


class VocabularyManager:
    """Manages vocabulary for token-to-ID mapping"""

    def __init__(self, platform: str):
        self.platform = platform
        self.id_to_token: list[str] = []  # array: id to tokenstr
        self.token_to_id: dict[str, int] = {}  # dict: tokenstr to id
        self.last_id: int = 0  # starting with 0 and increasing
        self.registry_token_cache: list[Tokens] = [] # registry cache

        # Preallocated numpy arrays with different initial capacities
        self._id_to_token_type: npt.NDArray[np.int8] = np.full(256, TokenType.ERROR, dtype=np.int8)

        # Smaller initial capacity for lit caches since they're sparse
        self._lit_start_cache: npt.NDArray[np.int_] = np.empty(4, dtype=np.int_)
        self._lit_end_cache: npt.NDArray[np.int_] = np.empty(4, dtype=np.int_)
        self._lit_start_count = 0  # Track actual entries in lit_start_cache
        self._lit_end_count = 0    # Track actual entries in lit_end_cache

        # New cache for platform instruction types
        self._platform_instruction_type_cache: npt.NDArray[np.int8] = np.full(256, PlatformInstructionTypes.AGNOSTIC, dtype=np.int8)

        # Create unique inner classes for this instance
        self._create_inner_classes()

    @staticmethod
    def from_vocab(platform: str, vocab_list: list[str]) -> 'VocabularyManager':
        """Creates vocab from tokenizer output."""
        v_man = VocabularyManager(platform)
        v_man.id_to_token = vocab_list
        v_man.last_id = len(vocab_list)
        platform_token = f"{platform}_"

        # Initialize numpy arrays with proper size
        token_types = []
        lit_start_tokens = []
        lit_end_tokens = []

        for index, value in enumerate(vocab_list):
            v_man.token_to_id[value] = index

            token_type: int = TokenType.ERROR
            if value.startswith(platform_token):
                token_type = TokenType.PLATFORM
            elif value.startswith("VALUED_"):
                token_type = TokenType.VALUED_CONST
            elif value == "Block_Def":
                token_type = TokenType.BLOCK_DEF
            elif value.startswith("Block_"):
                token_type = TokenType.BLOCK
            elif value.startswith("OPAQUE_"):
                token_type = TokenType.OPAQUE_CONST
            elif value.startswith("MEM_"):
                token_type = TokenType.MEMORY_OPERAND
            
            token_types.append(token_type)

            # Track Lit_Start and Lit_End tokens
            if "_LIT_START" in value.upper():
                lit_start_tokens.append(index)

            if "_LIT_END" in value.upper():
                lit_end_tokens.append(index)

        # Convert to numpy arrays
        v_man._id_to_token_type = np.array(token_types, dtype=np.int_)
        v_man._lit_start_cache = np.array(lit_start_tokens, dtype=np.int_)
        v_man._lit_start_count = len(lit_start_tokens)
        v_man._lit_end_cache = np.array(lit_end_tokens, dtype=np.int_)
        v_man._lit_end_count = len(lit_end_tokens)

        return v_man



    def _private_add_token(self, token: str, token_cls: type[Tokens], lit_type: LitTokenType = LitTokenType.REGULAR, insn_type=PlatformInstructionTypes.AGNOSTIC) -> int:
        """Add a token to the vocabulary and return its ID, optionally setting platform instruction type."""
        if token in self.token_to_id:
            return self.token_to_id[token]

        assert (not (token.startswith("Block") or token.startswith("OPAQUE_CONST"))) or \
               (token[-2] == '_' or "Lit" in token or token == "Block_Def"), \
            f"Warning: two digit token thats shouldnt: {token}"

        # Add new token
        token_id = self.last_id
        self.token_to_id[token] = token_id
        self.id_to_token.append(token)

        # Get token type directly from the token class
        token_type = token_cls.token_type

        # Check if we need to expand token type capacity
        if token_id >= len(self._id_to_token_type):
            # Double the capacity
            old_capacity = len(self._id_to_token_type)
            new_capacity = old_capacity * 2

            # Resize id_to_token_type array
            new_token_type_array = np.empty(new_capacity, dtype=np.int8)
            new_platform_instruction_type_cache = np.full(new_capacity, PlatformInstructionTypes.AGNOSTIC, dtype=np.int8)
            new_token_type_array[:old_capacity] = self._id_to_token_type[:old_capacity]
            new_platform_instruction_type_cache[:old_capacity] = self._platform_instruction_type_cache[:old_capacity]
            self._id_to_token_type = new_token_type_array
            self._platform_instruction_type_cache = new_platform_instruction_type_cache


        # Set token type
        self._id_to_token_type[token_id] = token_type
        self._platform_instruction_type_cache[token_id] = token_type

        # Handle lit cache entries - only add if it's a lit token
        if lit_type == LitTokenType.LIT_START:
            # Expand lit_start_cache if needed
            if self._lit_start_count >= len(self._lit_start_cache):
                old_capacity = len(self._lit_start_cache)
                new_capacity = old_capacity * 2
                new_cache = np.empty(new_capacity, dtype=np.int_)
                new_cache[:old_capacity] = self._lit_start_cache[:old_capacity]
                self._lit_start_cache = new_cache

            self._lit_start_cache[self._lit_start_count] = token_id
            self._lit_start_count += 1

        elif lit_type == LitTokenType.LIT_END:
            # Expand lit_end_cache if needed
            if self._lit_end_count >= len(self._lit_end_cache):
                old_capacity = len(self._lit_end_cache)
                new_capacity = old_capacity * 2
                new_cache = np.empty(new_capacity, dtype=np.int_)
                new_cache[:old_capacity] = self._lit_end_cache[:old_capacity]
                self._lit_end_cache = new_cache

            self._lit_end_cache[self._lit_end_count] = token_id
            self._lit_end_count += 1

        # Regular tokens don't get added to lit caches at all

        self.last_id += 1
        return token_id

    @property
    def id_to_token_type(self) -> npt.NDArray[np.int8]:
        """Get readonly view of id_to_token_type array"""
        result = self._id_to_token_type[:self.last_id].view()
        result.flags.writeable = False
        return result

    @property
    def lit_starts(self) -> npt.NDArray[np.int_]:
        """Get readonly view of lit_start_cache array"""
        result = self._lit_start_cache[:self._lit_start_count].view()
        result.flags.writeable = False
        return result

    @property
    def lit_ends(self) -> npt.NDArray[np.int_]:
        """Get readonly view of lit_end_cache array"""
        result = self._lit_end_cache[:self._lit_end_count].view()
        result.flags.writeable = False
        return result

    def get_registry_token(self, insn, reg_id) -> Tokens:
        if len(self.registry_token_cache) <= reg_id:
            # Ensure the list is large enough
            self.registry_token_cache.extend([None] * (reg_id - len(self.registry_token_cache) + 1))

        register_str = insn.reg_name(reg_id)
        token = None
        if self.registry_token_cache[reg_id] is None:
            token = self.PlatformToken(register_str)
            self.registry_token_cache[reg_id] = token
        else:
            token = self.registry_token_cache[reg_id]
            assert str(token) == f"{self.platform}_{register_str}", "Token mismatch for register ID"

        return token

    def get_token_id(self, token: str) -> int:
        """Get the ID for a token, or -1 if not found"""
        return self.token_to_id.get(token, -1)

    def get_token_str(self, token_id: int) -> str:
        """Get the token string for an ID, or empty string if not found"""
        if 0 <= token_id < len(self.id_to_token):
            return self.id_to_token[token_id]
        return ""

    def size(self) -> int:
        """Return the number of tokens in the vocabulary"""
        return len(self.id_to_token)

    def to_dict(self) -> dict[str, int]:
        """Convert to dictionary format for backward compatibility"""
        return self.token_to_id.copy()

    def create_token_from_insn_list(self, insn_token_list: 'InsnTokenList', index: int) -> 'Tokens':
        """Create a single token from an InsnTokenList at the specified index"""
        if insn_token_list.last_index == 0:
            raise IndexError("Cannot get token from empty instruction token list")

        if index < 0 or index >= insn_token_list.last_index:
            raise IndexError(f"Token index {index} out of bounds (0 to {insn_token_list.last_index - 1})")
        if insn_token_list.metatoken_start_lookup is None:
            raise ValueError("Cannot get token from invalidated view")

        token_type = TokenType(insn_token_list.metatoken_type_ids[index])

        # Get token IDs for this specific token
        start_pos = insn_token_list.metatoken_start_lookup[index - 1] if index > 0 else 0
        if index == insn_token_list.last_index - 1:
            end_pos = len(insn_token_list.get_used_token_ids())
        else:
            end_pos = insn_token_list.metatoken_start_lookup[index]

        token_ids = insn_token_list.token_ids[start_pos:end_pos].tolist()
        return self._reconstruct_token_from_ids(token_type, token_ids)

    def get_token_class_for_type(self, token_type: TokenType) -> type[Tokens]:
        """Get the token class for a given token type"""
        if token_type == TokenType.PLATFORM:
            return self.PlatformToken
        elif token_type == TokenType.VALUED_CONST:
            return self.Valued_Const
        elif token_type == TokenType.BLOCK_DEF:
            return self.Block_Def
        elif token_type == TokenType.BLOCK:
            return self.Block
        elif token_type == TokenType.OPAQUE_CONST:
            return self.Opaque_Const
        elif token_type == TokenType.MEMORY_OPERAND:
            return self.MemoryOperand
        elif token_type == TokenType.TOKEN_SET:
            return self.TokenSet
        else:
            raise ValueError(f"Unknown token type: {token_type}")

    def _reconstruct_token_from_ids(self, token_type: TokenType, token_ids: List[int]) -> 'Tokens':
        """Reconstruct a token from its type and token IDs"""
        token_class = self.get_token_class_for_type(token_type)
        return token_class._from_token_ids(token_ids)

    def _create_inner_classes(self):
        """Create inner classes that have access to this VocabularyManager instance"""
        vocab_manager = self  # Capture the instance

        class TokensInner(Tokens, ABC):
            """Abstract base class for all token representations"""

            @abstractmethod
            def get_token_ids(self) -> npt.NDArray[np.int_]:
                """Get the list of token IDs for this token representation (order matters)"""
                pass

            @abstractmethod
            def to_string(self) -> str:
                """Convert token to its string representation (for debugging only)"""
                pass



        # Ensure TokensInner conforms to Tokens protocol
        assert issubclass(TokensInner, Tokens)

        class PlatformTokenInner(TokensInner, PlatformToken):
            """Represents platform-specific tokens like x86 instructions, registers, etc."""
            __slots__ = ('token', '_token_id')

            def __init__(self, token: str, insn_type: PlatformInstructionTypes):
                if ' ' in token:
                    raise ValueError(f"Token cannot contain spaces: '{token}'")
                self.token = token
                # Register the token and cache its ID, passing insn_type
                self._token_id = vocab_manager._private_add_token(f"{vocab_manager.platform}_{token}", self.__class__, insn_type=insn_type)

            @classmethod
            def _from_token_ids(cls, token_ids: List[int]) -> 'PlatformTokenInner':
                """Reconstruct a PlatformToken from token IDs"""
                if len(token_ids) != 1:
                    raise ValueError(f"Platform token must have exactly one ID, got {len(token_ids)}")

                token_str = vocab_manager.get_token_str(token_ids[0])
                if not token_str.startswith(f"{vocab_manager.platform}_"):
                    raise ValueError(f"Invalid platform token string: {token_str}")

                platform_token = token_str[len(vocab_manager.platform) + 1:]
                return cls(platform_token)

            def get_token_ids(self) -> npt.NDArray[np.int_]:
                return np.array([self._token_id], dtype=np.int_)

            def to_string(self) -> str:
                return f"{vocab_manager.platform}_{self.token}"

            def to_asm_like(self) -> str:
                return self.token

            @property
            def platform_instruction_type(self) -> PlatformInstructionTypes:
                """Get the platform instruction type for this token"""
                return PlatformInstructionTypes(vocab_manager._platform_instruction_type_cache[self._token_id])

        # Ensure PlatformTokenInner conforms to both protocols
        assert issubclass(PlatformTokenInner, Tokens)
        assert issubclass(PlatformTokenInner, PlatformToken)

        class ValuedConstTokenInner(TokensInner, ValuedConstToken):
            """Represents a constant with a specific numeric value"""
            __slots__ = ('value', '_token_ids')

            def __init__(self, value: int):
                self.value = value

                # Handle negative values
                is_negative = value < 0
                abs_value = abs(value)

                # Generate hex string with proper padding
                hex_str = f"{abs_value:02X}"  # Always at least 2 digits, uppercase
                if len(hex_str) % 2 == 1:
                    hex_str = "0" + hex_str  # Pad to even length

                # Convert hex string chunks to integer values
                hex_values = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
                hex_values_array = np.array(hex_values, dtype=np.int_)
                self._token_ids = TokenUtils.encode_tokens("VALUED_CONST", "VALUED_CONST", hex_values_array, vocab_manager,
                                                           token_class=self.__class__, inner_token_class=self.__class__,
                                                           max_key=256, include_minus=is_negative)

            @classmethod
            def _from_token_ids(cls, token_ids: List[int]) -> 'ValuedConstTokenInner':
                """Reconstruct a ValuedConstToken from token IDs using utility method"""
                value = TokenUtils.decode_tokens_to_value(
                    token_ids, "VALUED_CONST", "VALUED_CONST", vocab_manager,
                    max_key=256, support_negative=True, token_class=cls, inner_token_class=cls
                )
                return cls(value)

            def get_token_ids(self) -> npt.NDArray[np.int_]:
                return np.array(self._token_ids, dtype=np.int_)

            def to_string(self) -> str:
                """Generate string representation for debugging"""
                is_negative = self.value < 0
                abs_value = abs(self.value)
                hex_str = f"{abs_value:02X}"  # Always at least 2 digits, uppercase

                if abs_value <= 0xFF and not is_negative:
                    return f"VALUED_CONST_{hex_str}"
                else:
                    # Multi-token representation or negative value
                    if len(hex_str) % 2 == 1:
                        hex_str = "0" + hex_str

                    chunks = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]

                    name = "VALUED_CONST_Lit_Start"
                    if is_negative:
                        name += " MEM_MINUS"
                    for chunk in chunks:
                        name += f" VALUED_CONST_{chunk}"
                    name += " VALUED_CONST_Lit_End"
                    return name

            def to_asm_like(self) -> str:
                return f"v:{self.value:x}"

        # Ensure ValuedConstTokenInner conforms to both protocols
        assert issubclass(ValuedConstTokenInner, Tokens)
        assert issubclass(ValuedConstTokenInner, ValuedConstToken)

        class IdentifierInner(TokensInner, IdentifierToken, ABC):
            """Abstract base class for identifiers with IDs"""
            __slots__ = ('id', '_token_ids')


            def __init__(self, identifier_id: int):
                IdentifierToken.__init__(self, identifier_id)
                TokensInner.__init__(self)
                self.id = identifier_id

                basename = self._get_basename()

                hex_str = f"{self.id:X}"
                # Convert hex string characters to integer values
                hex_values = [int(c, 16) for c in hex_str]
                hex_values_array = np.array(hex_values, dtype=np.int_)
                self._token_ids = TokenUtils.encode_tokens(basename, "Identifier_Lit", hex_values_array,
                                                           vocab_manager, token_class=self.__class__,
                                                           inner_token_class=IdentifierInner, max_key=16)

            @classmethod
            def singleton_token_index(cls, id: int) -> typing.Optional[int]:
                """Get the index of a singleton token with a single hex digit"""
                if 0 <= id < 16:
                    result = TokenUtils.cache_numeric_token(cls, cls._get_basename(), id, lambda: -1, max_key=16)
                    if result >= 0:
                        return result

                return None

            @classmethod
            def value_by_singleton_token_index(cls, index: int) -> typing.Optional[int]:
                result = TokenUtils.cache_numeric_reverse(cls, index, cls._get_basename(), vocab_manager)
                if result >= 0:
                    return result
                return None

            @classmethod
            def _from_token_ids(cls, token_ids: List[int]) -> 'IdentifierInner':
                """Reconstruct an IdentifierToken from token IDs using utility method"""
                identifier_id = TokenUtils.decode_tokens_to_value(
                    token_ids, cls._get_basename(), "Identifier_Lit", vocab_manager,
                    max_key=16, support_negative=False, token_class=cls, inner_token_class=IdentifierInner
                )

                return cls(identifier_id)

            def get_token_ids(self) -> npt.NDArray[np.int_]:
                return np.array(self._token_ids, dtype=np.int_)

            def to_string(self) -> str:
                """Generate string representation for debugging (recreates register_name_range output)"""
                basename = self._get_basename()
                if self.id < 16:
                    hex_str = f"{self.id:X}"
                    return f"{basename}_{hex_str}"
                else:
                    id_str = f"{self.id:X}"
                    name = f"{basename}_Lit_Start"
                    for hex_digit in id_str:
                        name += f" Identifier_Lit_{hex_digit}"
                    name += f" {basename}_Lit_End"
                    return name

        # Ensure IdentifierInner conforms to both protocols
        assert issubclass(IdentifierInner, Tokens)
        assert issubclass(IdentifierInner, IdentifierToken)

        class BlockDefInner(TokensInner, BlockDefToken):
            """Represents block definition tokens (Block_Def)"""
            __slots__ = ('_token_id',)

            def __init__(self):
                # Register the token and cache its ID
                self._token_id = vocab_manager._private_add_token("Block_Def", self.__class__)

            @classmethod
            def _from_token_ids(cls, token_ids: List[int]) -> 'BlockDefInner':
                """Reconstruct a BlockDefToken from token IDs"""
                if len(token_ids) != 1:
                    raise ValueError(f"Block def token must have exactly one ID, got {len(token_ids)}")

                token_str = vocab_manager.get_token_str(token_ids[0])
                if token_str != "Block_Def":
                    raise ValueError(f"Invalid block def token string: {token_str}")

                return cls()

            def get_token_ids(self) -> npt.NDArray[np.int_]:
                return np.array([self._token_id], dtype=np.int_)

            def to_string(self) -> str:
                return "Block_Def"

            def to_asm_like(self) -> str:
                return "_def"

        # Ensure BlockDefInner conforms to both protocols
        assert issubclass(BlockDefInner, Tokens)
        assert issubclass(BlockDefInner, BlockDefToken)

        class BlockInner(IdentifierInner, BlockToken):
            """Represents block identifiers"""
            __slots__ = ()

            def __init__(self, block_id: int):
                super().__init__(block_id)

            @classmethod
            def _get_basename(cls) -> str:
                return "Block"

            def to_asm_like(self) -> str:
                return f"block:{self.id}"

        # Ensure BlockInner conforms to both protocols
        assert issubclass(BlockInner, IdentifierToken)
        assert issubclass(BlockInner, BlockToken)

        class OpaqueConstInner(IdentifierInner, OpaqueConstToken):
            """Represents opaque constant identifiers"""
            __slots__ = ()

            def __init__(self, opaque_id: int):
                super().__init__(opaque_id)

            @classmethod
            def _get_basename(cls) -> str:
                return "OPAQUE_CONST"

            def to_asm_like(self) -> str:
                return f"opaque:{self.id}"

        # Ensure OpaqueConstInner conforms to both protocols
        assert issubclass(OpaqueConstInner, IdentifierToken)
        assert issubclass(OpaqueConstInner, OpaqueConstToken)

        class MemoryOperandTokenInner(TokensInner, MemoryOperandToken):
            """Represents memory operand symbols like [, ], +, *"""
            __slots__ = ('symbol', '_token_id')
            _token_cache = MemoryOperandToken.EnumTokenCache()

            def __init__(self, symbol: MemoryOperandSymbol):
                self.symbol = symbol
                # Register the token and cache its ID
                self._token_id = vocab_manager._private_add_token(symbol.token_str(), self.__class__)

            @classmethod
            def _from_enum(cls, symbol):
                return cls(symbol)

            @classmethod
            def _get_enum_token_cache(cls) -> MemoryOperandToken.EnumTokenCache:
                return cls._token_cache

            @classmethod
            def _from_token_ids(cls, token_ids: List[int]) -> 'MemoryOperandTokenInner':
                """Reconstruct a MemoryOperandToken from token IDs"""
                if len(token_ids) != 1:
                    raise ValueError(f"Memory operand token must have exactly one ID, got {len(token_ids)}")

                token_str = vocab_manager.get_token_str(token_ids[0])
                for symbol in MemoryOperandSymbol:
                    if symbol.token_str() == token_str:
                        return cls(symbol)

                raise ValueError(f"Invalid memory operand token string: {token_str}")

            def get_token_ids(self) -> npt.NDArray[np.int_]:
                return np.array([self._token_id], dtype=np.int_)

            def to_string(self) -> str:
                return self.symbol.token_str()

            def to_asm_like(self) -> str:
                return str(self.symbol.value)

        # Ensure MemoryOperandTokenInner conforms to both protocols
        assert issubclass(MemoryOperandTokenInner, Tokens)
        assert issubclass(MemoryOperandTokenInner, MemoryOperandToken)
        assert MemoryOperandTokenInner.token_type == TokenType.MEMORY_OPERAND

        class TokenSetInner(TokensInner):
            """Represents a collection of tokens"""
            __slots__ = ('tokens',)

            def __init__(self, tokens: List[TokensInner]):
                self.tokens = tokens

            def get_token_ids(self) -> npt.NDArray[np.int_]:
                token_ids = []
                for token in self.tokens:
                    token_ids.extend(token.get_token_ids())
                return np.array(token_ids, dtype=np.int_)

            def to_string(self) -> str:
                return " ".join(token.to_string() for token in self.tokens)

            def to_asm_like(self) -> str:
                return " ".join(token.to_asm_like() for token in self.tokens)

            def __iter__(self):
                return iter(self.tokens)

            def __len__(self):
                return len(self.tokens)

            def append(self, token: TokensInner):
                self.tokens.append(token)

            def extend(self, tokens: List[TokensInner]):
                self.tokens.extend(tokens)

        # Assign the inner classes to instance variables WITHOUT the Inner suffix
        self.TokensRepl = TokensInner
        self.PlatformToken = PlatformTokenInner
        self.Valued_Const = ValuedConstTokenInner
        self.Identifier = IdentifierInner
        self.Block_Def = BlockDefInner
        self.Block = BlockInner
        self.Opaque_Const = OpaqueConstInner
        self.MemoryOperand = MemoryOperandTokenInner
        self.TokenSet = TokenSetInner

