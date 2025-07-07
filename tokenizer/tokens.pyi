from abc import ABC, abstractmethod
from typing import List, Type, TypeVar, ClassVar
from enum import Enum, IntEnum
from dataclasses import dataclass
import numpy as np
import numpy.typing as npt

T = TypeVar('T', bound='Tokens')

class TokenType(IntEnum):
    ERROR: 'TokenType'
    PLATFORM: 'TokenType'
    VALUED_CONST: 'TokenType'
    BLOCK_DEF: 'TokenType'
    BLOCK: 'TokenType'
    OPAQUE_CONST: 'TokenType'
    MEMORY_OPERAND: 'TokenType'
    TOKEN_SET: 'TokenType'
    UNRESOLVED: 'TokenType'

class MemoryOperandSymbol(Enum):
    OPEN_BRACKET: str
    CLOSE_BRACKET: str
    PLUS: str
    MINUS: str
    MULTIPLY: str
    def token_str(self) -> str: ...

class Tokens(ABC):
    @property
    @classmethod
    @abstractmethod
    def token_type(cls) -> TokenType: ...

    @classmethod
    @abstractmethod
    def _from_token_ids(cls, token_ids: List[int]) -> 'Tokens': ...

    @abstractmethod
    def get_token_ids(self) -> npt.NDArray[np.int_]: ...

    @abstractmethod
    def to_string(self) -> str: ...

    @abstractmethod
    def to_asm_like(self) -> str: ...

    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other) -> bool: ...

class PlatformToken(Tokens, ABC):
    token: str
    @property
    @classmethod
    def token_type(cls) -> TokenType: ...
    @abstractmethod
    def __init__(self, token: str) -> None: ...

class ValuedConstToken(Tokens, ABC):
    value: int
    @property
    @classmethod
    def token_type(cls) -> TokenType: ...
    @abstractmethod
    def __init__(self, value: int) -> None: ...

class IdentifierToken(Tokens, ABC):
    id: int
    @abstractmethod
    def __init__(self, identifier_id: int) -> None: ...
    @classmethod
    @abstractmethod
    def _get_basename(cls) -> str: ...

class BlockDefToken(Tokens, ABC):
    @property
    @classmethod
    def token_type(cls) -> TokenType: ...
    @abstractmethod
    def __init__(self) -> None: ...

class BlockToken(IdentifierToken, ABC):
    @property
    @classmethod
    def token_type(cls) -> TokenType: ...
    @abstractmethod
    def __init__(self, block_id: int) -> None: ...

class OpaqueConstToken(IdentifierToken, ABC):
    @property
    @classmethod
    def token_type(cls) -> TokenType: ...
    @abstractmethod
    def __init__(self, opaque_id: int) -> None: ...

class MemoryOperandToken(Tokens, ABC):
    symbol: MemoryOperandSymbol

    # This dataclass is created by the decorator as a class member
    @dataclass
    class EnumTokenCache:
        OPEN_BRACKET: 'MemoryOperandToken | None' = None
        CLOSE_BRACKET: 'MemoryOperandToken | None' = None
        PLUS: 'MemoryOperandToken | None' = None
        MINUS: 'MemoryOperandToken | None' = None
        MULTIPLY: 'MemoryOperandToken | None' = None

    @property
    @classmethod
    def token_type(cls) -> TokenType: ...

    @classmethod
    @abstractmethod
    def _get_enum_token_cache(cls) -> EnumTokenCache: ...

    @classmethod
    @abstractmethod
    def _from_enum(cls, symbol: MemoryOperandSymbol) -> 'MemoryOperandToken': ...

    # Class properties that will be created by the decorator
    @classmethod
    @property
    def OPEN_BRACKET(cls) -> 'MemoryOperandToken': ...

    @classmethod
    @property
    def CLOSE_BRACKET(cls) -> 'MemoryOperandToken': ...

    @classmethod
    @property
    def PLUS(cls) -> 'MemoryOperandToken': ...

    @classmethod
    @property
    def MINUS(cls) -> 'MemoryOperandToken': ...

    @classmethod
    @property
    def MULTIPLY(cls) -> 'MemoryOperandToken': ...

    @abstractmethod
    def __init__(self, symbol: MemoryOperandSymbol) -> None: ...

class TokenResolver:
    block_counter: int
    opaque_counter: int
    block_ids: dict[str, int]
    opaque_ids: dict[str, int]

    def __init__(self) -> None: ...
    def get_block_id(self, addr: str = None) -> int: ...
    def get_opaque_id(self, addr: str = None) -> int: ...
    def reset_block_counter(self) -> None: ...

def EnumTokenCls(enum_class: Type[Enum]) -> Type[T]: ...

class TokenRaw(Tokens):
    token_ids_array: npt.NDArray[np.int_]
    token_type_enum: TokenType


    @property
    @classmethod
    def token_type(cls) -> TokenType: ...

    def resolve(self, vocab_manager: 'VocabularyManager') -> 'Tokens': ...

    @staticmethod
    def with_type(token_type_enum: TokenType) -> type['TokenRaw']: ...
