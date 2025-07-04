from abc import ABC, abstractmethod
from typing import List, Set, Protocol, runtime_checkable
from enum import Enum

from tokenizer.utils import register_name_range


class MemoryOperandSymbol(Enum):
    """Enum for memory operand symbols"""
    OPEN_BRACKET = "mem["
    CLOSE_BRACKET = "]mem"
    PLUS = "+"
    MINUS = "-"
    MULTIPLY = "*"

    def token_str(self) -> str:
        """Get the string representation of the memory operand symbol"""
        if self == MemoryOperandSymbol.OPEN_BRACKET:
            return "MEM_OPEN_BRACKET"
        elif self == MemoryOperandSymbol.CLOSE_BRACKET:
            return "MEM_CLOSE_BRACKET"
        elif self == MemoryOperandSymbol.PLUS:
            return "MEM_PLUS"
        elif self == MemoryOperandSymbol.MINUS:
            return "MEM_MINUS"
        elif self == MemoryOperandSymbol.MULTIPLY:
            return "MEM_MULTIPLY"
        else:
            raise ValueError(f"Unknown memory operand symbol: {self}")


class Tokens(ABC):
    """Protocol for token representation objects"""

    @abstractmethod
    def get_token_ids(self) -> List[int]:
        """Get the list of token IDs for this token representation (order matters)"""
        ...

    @abstractmethod
    def to_string(self) -> str:
        """Convert token to its string representation (for debugging only)"""
        ...

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__.replace("Inner","Token").replace("TokenToken","Token")}({self.to_string()})"

    def __hash__(self) -> int:
        """Make tokens hashable based on class and token IDs"""
        return hash((self.__class__.__name__, tuple(self.get_token_ids())))

    def __eq__(self, other) -> bool:
        """Tokens are equal if they have the same class and same token IDs"""
        if not isinstance(other, Tokens):
            return False
        return (self.__class__.__name__ == other.__class__.__name__ and
                self.get_token_ids() == other.get_token_ids())


class PlatformToken(Tokens, ABC):
    """Protocol for platform-specific tokens"""

    token: str

    @abstractmethod
    def __init__(self, token: str) -> None:
        ...


class ValuedConstToken(Tokens, ABC):
    """Protocol for valued constants"""

    value: int

    @abstractmethod
    def __init__(self, value: int) -> None:
        ...


class IdentifierToken(Tokens, ABC):
    """Protocol for identifier tokens"""

    id: int

    @abstractmethod
    def __init__(self, identifier_id: int) -> None:
        ...

    @abstractmethod
    def _get_basename(self) -> str:
        """Get the base name for this identifier type"""
        ...


class BlockDefToken(Tokens, ABC):
    """Protocol for block definition tokens"""

    @abstractmethod
    def __init__(self) -> None:
        ...


class BlockToken(IdentifierToken, ABC):
    """Protocol for block identifiers"""

    @abstractmethod
    def __init__(self, block_id: int) -> None:
        ...


class OpaqueConstToken(IdentifierToken, ABC):
    """Protocol for opaque constants"""

    @abstractmethod
    def __init__(self, opaque_id: int) -> None:
        ...


class MemoryOperandToken(Tokens, ABC):
    """Protocol for memory operand symbol tokens"""

    symbol: MemoryOperandSymbol

    @abstractmethod
    def __init__(self, symbol: MemoryOperandSymbol) -> None:
        ...


class VocabularyManager:
    """Manages vocabulary for token-to-ID mapping"""

    def __init__(self, platform: str):
        self.platform = platform
        self.id_to_token: list[str] = []  # array: id to tokenstr
        self.token_to_id: dict[str, int] = {}  # dict: tokenstr to id
        self.last_id: int = 0  # starting with 0 and increasing
        self.register_tokens = []

        # Create unique inner classes for this instance
        self._create_inner_classes()

    def _private_add_token(self, token: str) -> int:
        """Add a token to the vocabulary and return its ID"""
        if token in self.token_to_id:
            return self.token_to_id[token]

        assert (not (token.startswith("Block") or token.startswith("OPAQUE_CONST"))) or \
               (token[-2] == '_' or "Lit" in token or token == "Block_Def"), \
            f"Warning: two digit token thats shouldnt: {token}"

        # Add new token
        token_id = self.last_id
        self.token_to_id[token] = token_id
        self.id_to_token.append(token)
        self.last_id += 1
        return token_id

    def get_registry_token(self, insn, reg_id) -> Tokens:
        if len(self.register_tokens) <= reg_id:
            # Ensure the list is large enough
            self.register_tokens.extend([None] * (reg_id - len(self.register_tokens) + 1))

        register_str = insn.reg_name(reg_id)
        token = None
        if self.register_tokens[reg_id] is None:
            token = self.PlatformToken(register_str)
            self.register_tokens[reg_id] = token
        else:
            token = self.register_tokens[reg_id]
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

    def _get_or_create_class_cache_token(self, cls, cache_attr: str, token_string: str) -> int:
        """Utility method to get or create a class-level cached token ID"""
        if not hasattr(cls, cache_attr) or getattr(cls, cache_attr) is None:
            setattr(cls, cache_attr, self._private_add_token(token_string))
        return getattr(cls, cache_attr)

    def _create_inner_classes(self):
        """Create inner classes that have access to this VocabularyManager instance"""
        vocab_manager = self  # Capture the instance

        class TokensInner(Tokens, ABC):
            """Abstract base class for all token representations"""

            @abstractmethod
            def get_token_ids(self) -> List[int]:
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

            def __init__(self, token: str):
                if ' ' in token:
                    raise ValueError(f"Token cannot contain spaces: '{token}'")
                self.token = token
                # Register the token and cache its ID
                self._token_id = vocab_manager._private_add_token(f"{vocab_manager.platform}_{token}")

            def get_token_ids(self) -> List[int]:
                return [self._token_id]

            def to_string(self) -> str:
                return f"{vocab_manager.platform}_{self.token}"

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

                if 0 <= value <= 0xFF:
                    # Positive small value: single token
                    token_string = f"VALUED_CONST_{hex_str}"
                    self._token_ids = [vocab_manager._private_add_token(token_string)]
                else:
                    # Complex case: multiple tokens for values > 0xFF
                    # Split hex string into 2-character chunks (bytes)
                    if len(hex_str) % 2 == 1:
                        hex_str = "0" + hex_str  # Pad to even length

                    chunks = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]

                    self._token_ids = []

                    # Start token
                    start_token_id = vocab_manager._get_or_create_class_cache_token(
                        self.__class__, '_start_token_id', "VALUED_CONST_Lit_Start"
                    )
                    self._token_ids.append(start_token_id)

                    # Minus token for negative values
                    if is_negative:
                        self._token_ids.append(vocab_manager.MemoryOperand(MemoryOperandSymbol.MINUS)._token_id)

                    # 2-digit hex chunk tokens (00-FF)
                    for chunk in chunks:
                        token_string = f"VALUED_CONST_{chunk}"
                        self._token_ids.append(vocab_manager._private_add_token(token_string))

                    # End token
                    end_token_id = vocab_manager._get_or_create_class_cache_token(
                        self.__class__, '_end_token_id', "VALUED_CONST_Lit_End"
                    )
                    self._token_ids.append(end_token_id)

            def get_token_ids(self) -> List[int]:
                return self._token_ids.copy()

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
                        name += " VALUED_CONST_MINUS"
                    for chunk in chunks:
                        name += f" VALUED_CONST_{chunk}"
                    name += " VALUED_CONST_Lit_End"
                    return name

        # Ensure ValuedConstTokenInner conforms to both protocols
        assert issubclass(ValuedConstTokenInner, Tokens)
        assert issubclass(ValuedConstTokenInner, ValuedConstToken)

        class IdentifierInner(TokensInner, IdentifierToken, ABC):
            """Abstract base class for identifiers with IDs"""
            __slots__ = ('id', '_token_ids')

            # Static cache for single hex digit tokens - shared across all Identifier instances
            _digit_token_cache = {}  # "digit" -> token_id (0-F only)

            def __init__(self, identifier_id: int):
                IdentifierToken.__init__(self, identifier_id)
                TokensInner.__init__(self)
                self.id = identifier_id

                # Generate and register tokens directly without using _generate_token_string
                basename = self._get_basename()

                if self.id < 16:
                    hex_str = f"{self.id:X}"
                    token_string = f"{basename}_{hex_str}"
                    self._token_ids = [vocab_manager._private_add_token(token_string)]
                else:
                    # Complex case: multiple tokens using single hex digits
                    id_str = f"{self.id:X}"  # Uppercase hex without padding for multi-token case

                    # Register all tokens in sequence
                    self._token_ids = []

                    # Start token - use class-specific cache
                    start_token_id = vocab_manager._get_or_create_class_cache_token(
                        self.__class__, '_start_token_id', f"{basename}_Lit_Start"
                    )
                    self._token_ids.append(start_token_id)

                    # Individual hex digit tokens (0-F only) - use shared cache
                    for hex_digit in id_str:
                        if hex_digit not in IdentifierInner._digit_token_cache:
                            IdentifierInner._digit_token_cache[hex_digit] = vocab_manager._private_add_token(f"Identifier_Lit_{hex_digit}")
                        self._token_ids.append(IdentifierInner._digit_token_cache[hex_digit])

                    # End token - use class-specific cache
                    end_token_id = vocab_manager._get_or_create_class_cache_token(
                        self.__class__, '_end_token_id', f"{basename}_Lit_End"
                    )
                    self._token_ids.append(end_token_id)

            @abstractmethod
            def _get_basename(self) -> str:
                """Get the base name for this identifier type"""
                pass

            def get_token_ids(self) -> List[int]:
                return self._token_ids.copy()

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
                self._token_id = vocab_manager._private_add_token("Block_Def")

            def get_token_ids(self) -> List[int]:
                return [self._token_id]

            def to_string(self) -> str:
                return "Block_Def"

        # Ensure BlockDefInner conforms to both protocols
        assert issubclass(BlockDefInner, Tokens)
        assert issubclass(BlockDefInner, BlockDefToken)

        class BlockInner(IdentifierInner, BlockToken):
            """Represents block identifiers"""
            __slots__ = ()

            def __init__(self, block_id: int):
                super().__init__(block_id)

            def _get_basename(self) -> str:
                return "Block"

        # Ensure BlockInner conforms to both protocols
        assert issubclass(BlockInner, IdentifierToken)
        assert issubclass(BlockInner, BlockToken)

        class OpaqueConstInner(IdentifierInner, OpaqueConstToken):
            """Represents opaque constant identifiers"""
            __slots__ = ()

            def __init__(self, opaque_id: int):
                super().__init__(opaque_id)

            def _get_basename(self) -> str:
                return "OPAQUE_CONST"

        # Ensure OpaqueConstInner conforms to both protocols
        assert issubclass(OpaqueConstInner, IdentifierToken)
        assert issubclass(OpaqueConstInner, OpaqueConstToken)

        class MemoryOperandTokenInner(TokensInner, MemoryOperandToken):
            """Represents memory operand symbols like [, ], +, *"""
            __slots__ = ('symbol', '_token_id')

            def __init__(self, symbol: MemoryOperandSymbol):
                self.symbol = symbol
                # Register the token and cache its ID
                self._token_id = vocab_manager._private_add_token(symbol.token_str())

            def get_token_ids(self) -> List[int]:
                return [self._token_id]

            def to_string(self) -> str:
                return self.symbol.token_str()

        # Ensure MemoryOperandTokenInner conforms to both protocols
        assert issubclass(MemoryOperandTokenInner, Tokens)
        assert issubclass(MemoryOperandTokenInner, MemoryOperandToken)

        class TokenSetInner(TokensInner):
            """Represents a collection of tokens"""
            __slots__ = ('tokens',)

            def __init__(self, tokens: List[TokensInner]):
                self.tokens = tokens

            def get_token_ids(self) -> List[int]:
                token_ids = []
                for token in self.tokens:
                    token_ids.extend(token.get_token_ids())
                return token_ids

            def to_string(self) -> str:
                return " ".join(token.to_string() for token in self.tokens)

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



class TokenResolver:
    """Manages ID resolution for different token types"""

    def __init__(self):
        self.block_counter = 0
        self.opaque_counter = 0
        self.block_ids = {}  # addr -> id
        self.opaque_ids = {}  # addr -> id

    def get_block_id(self, addr: str = None) -> int:
        """Get or create a block ID"""
        if addr and addr in self.block_ids:
            return self.block_ids[addr]

        block_id = self.block_counter
        if addr:
            self.block_ids[addr] = block_id
        self.block_counter += 1
        return block_id

    def get_opaque_id(self, addr: str = None) -> int:
        """Get or create an opaque constant ID"""
        if addr and addr in self.opaque_ids:
            return self.opaque_ids[addr]

        opaque_id = self.opaque_counter
        if addr:
            self.opaque_ids[addr] = opaque_id
        self.opaque_counter += 1
        return opaque_id

    def reset_block_counter(self):
        """Reset the block counter and block IDs for a new function"""
        self.block_counter = 0
        self.block_ids.clear()
