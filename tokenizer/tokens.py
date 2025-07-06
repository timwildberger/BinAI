from abc import ABC, abstractmethod
from typing import List, Type, TypeVar, cast, Any, Optional
from enum import Enum, IntEnum
from dataclasses import dataclass
import numpy as np
import numpy.typing as npt
from tokenizer.hashing_numpy import hash_continuous_array as np_hash

T = TypeVar('T', bound='Tokens')

def EnumTokenCls(enum_class: Type[Enum]) -> Any:
    """Decorator to create lazy class properties for all enum members and required infrastructure"""
    def decorator(cls: Type[T]) -> Type[T]:
        # Get the enum name and create dataclass name
        enum_name = enum_class.__name__
        dataclass_name = "EnumTokenCache"

        # Create the dataclass dynamically
        dataclass_fields = {}
        for member in enum_class:
            dataclass_fields[member.name] = 'MemoryOperandToken | None'

        # Create the dataclass type
        dataclass_type = type(dataclass_name, (), {
            '__annotations__': {name: typ for name, typ in dataclass_fields.items()},
            '__module__': cls.__module__,
            '__doc__': f"Dataclass containing all {enum_name.lower()} symbol tokens",
            **{name: None for name in dataclass_fields.keys()}
        })
        # Apply dataclass decorator with type ignore for the warning
        dataclass_type = dataclass(dataclass_type)  # type: ignore

        # Add the dataclass as a class member instead of module globals
        setattr(cls, dataclass_name, dataclass_type)

        # Add abstract methods to the class
        def _get_enum_token_cache(cls):
            """Return a dataclass instance containing all symbol tokens"""
            pass
        _get_enum_token_cache.__doc__ = f"Return a dataclass instance containing all {enum_name.lower()} symbol tokens"

        def _from_enum(cls, symbol):
            """Create token from enum member"""
            pass
        _from_enum.__doc__ = f"Create token from {enum_name} member"

        # Make them abstract methods
        _get_enum_token_cache = classmethod(abstractmethod(_get_enum_token_cache))
        _from_enum = classmethod(abstractmethod(_from_enum))

        # Add to class
        setattr(cls, '_get_enum_token_cache', _get_enum_token_cache)
        setattr(cls, '_from_enum', _from_enum)

        # Create properties for each enum member
        for member in enum_class:
            property_name = member.name

            # Create the property method
            def create_property_method(enum_member):
                def property_method(cls):
                    syms = cls._get_enum_token_cache()
                    attr_name = enum_member.name
                    if getattr(syms, attr_name) is None:
                        setattr(syms, attr_name, cls._from_enum(enum_member))
                    return getattr(syms, attr_name)
                return property_method

            property_method = create_property_method(member)
            property_method.__doc__ = f"Return a {enum_name.lower()} token for {property_name.lower().replace('_', ' ')} symbol"

            # Create a class property using a descriptor approach
            class ClassPropertyDescriptor:
                def __init__(self, func):
                    self.func = func
                    self.__doc__ = func.__doc__

                def __get__(self, obj, cls):
                    return self.func(cls)

            # Add as class property
            setattr(cls, property_name, ClassPropertyDescriptor(property_method))

        return cls
    return decorator

class classproperty(property):
    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)

class TokenType(IntEnum):
    """Enum for token types to identify token classes"""
    ERROR = 0
    PLATFORM = 1
    VALUED_CONST = 2
    BLOCK_DEF = 3
    BLOCK = 4
    OPAQUE_CONST = 5
    MEMORY_OPERAND = 6
    TOKEN_SET = 7


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

    @classproperty
    @abstractmethod
    def token_type(cls) -> TokenType:
        """Return the type of this token representation"""
        ...

    @classmethod
    @abstractmethod
    def _from_token_ids(cls, token_ids: List[int]) -> 'Tokens': ...


    @abstractmethod
    def get_token_ids(self) -> npt.NDArray[np.int_]:
        """Get the list of token IDs for this token representation (order matters)"""
        ...

    @abstractmethod
    def to_string(self) -> str:
        """Convert token to its string representation (for debugging only)"""
        ...

    @abstractmethod
    def to_asm_like(self) -> str:
        """Convert token to its string representation that resembles assembly syntax"""
        ...

    def __str__(self) -> str:
        return self.to_string()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__.replace("Inner","Token").replace("TokenToken","Token")}({self.to_string()})"

    def __hash__(self) -> int:
        """Make tokens hashable based on class and token IDs"""
        return int(np_hash(self.get_token_ids()))

    def __eq__(self, other) -> bool:
        """Tokens are equal if they have the same class and same token IDs"""
        if (not isinstance(other, Tokens)) or self.token_type != other.token_type:
            return False
        myids = self.get_token_ids()
        otherids = other.get_token_ids()

        return (myids.shape == otherids.shape and
                np.all(myids == otherids))


class PlatformToken(Tokens, ABC):
    """Protocol for platform-specific tokens"""

    token: str
    
    @classproperty
    def token_type(cls) -> TokenType:
        """Return the type of this token representation"""
        return TokenType.PLATFORM

    @abstractmethod
    def __init__(self, token: str) -> None:
        ...


class ValuedConstToken(Tokens, ABC):
    """Protocol for valued constants"""

    @classproperty
    def token_type(cls) -> TokenType:
        """Return the type of this token representation"""
        return TokenType.VALUED_CONST
    
    
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

    @classmethod
    def singleton_token_index(cls, id: int) -> Optional[int]:
        """
        Get the index of this identifier token in the vocabulary. If the identifier can be represented as a singleton token,


        Returns:
            Index of this identifier token in the vocabulary
        """
        ...

    @classmethod
    def value_by_singleton_token_index(cls, index: int) -> Optional[int]:
        """
        Get the value of this identifier token by its index in the vocabulary. If the identifier can be represented as a singleton token,


        Args:
            index: Index of the identifier token in the vocabulary

        Returns:
            Value of this identifier token
        """
        ...

    @classmethod
    @abstractmethod
    def _get_basename(cls) -> str:
        """Get the base name for this identifier type"""
        ...


class BlockDefToken(Tokens, ABC):
    """Protocol for block definition tokens"""


    @classproperty
    def token_type(cls) -> TokenType:
        """Return the type of this token representation"""
        return TokenType.BLOCK_DEF

    @abstractmethod
    def __init__(self) -> None:
        ...


class BlockToken(IdentifierToken, ABC):
    """Protocol for block identifiers"""

    @classproperty
    def token_type(cls) -> TokenType:
        """Return the type of this token representation"""
        return TokenType.BLOCK
    
    
    @abstractmethod
    def __init__(self, block_id: int) -> None:
        ...


class OpaqueConstToken(IdentifierToken, ABC):
    """Protocol for opaque constants"""

    @classproperty
    def token_type(cls) -> TokenType:
        """Return the type of this token representation"""
        return TokenType.OPAQUE_CONST

    @abstractmethod
    def __init__(self, opaque_id: int) -> None:
        ...

@EnumTokenCls(MemoryOperandSymbol)
class MemoryOperandToken(Tokens, ABC):
    """Protocol for memory operand symbol tokens"""

    @classproperty
    def token_type(cls) -> TokenType:
        """Return the type of this token representation"""
        return TokenType.MEMORY_OPERAND

    symbol: MemoryOperandSymbol

    @abstractmethod
    def __init__(self, symbol: MemoryOperandSymbol) -> None:
        ...

class TokenRaw(Tokens, ABC):
    _cache: dict[TokenType, type['TokenRaw']] = {}

    @abstractmethod
    def resolve(self, vocab_manager: 'VocabularyManager') -> 'Tokens': ...

    def with_type(token_type_enum: TokenType) -> type['TokenRaw']:
        """
        Create a new TokenRaw with the specified token type.

        Args:
            token_type_enum: TokenType enum value to set for the new token

        Returns:
            New TokenRaw instance with the specified type
        """

        if token_type_enum in TokenRaw._cache:
            return TokenRaw._cache[token_type_enum]
        else:
            class TokenRawInner(TokenRaw):
                """Raw token representation with numpy array of IDs and token type"""

                def __init__(self, token_ids: npt.NDArray[np.int_]):
                    """
                    Initialize TokenRaw with token IDs and type

                    Args:
                        token_ids: Numpy array of token IDs
                        token_type_enum: TokenType enum value
                    """
                    super().__init__()
                    self.token_ids_array = token_ids
                    if len(token_ids) == 0:
                        raise ValueError("TokenRaw must have at least one token ID")

                @classproperty
                def token_type(cls) -> TokenType:
                    """Return the type of this token representation"""
                    return token_type_enum

                @classmethod
                def _from_token_ids(cls, token_ids: List[int]) -> 'TokenRawInner':
                    """Create TokenRaw from token IDs - type must be determined from context"""
                    return cls(np.array(token_ids, dtype=np.int_))

                def get_token_ids(self) -> npt.NDArray[np.int_]:
                    """Get the list of token IDs for this token representation"""
                    return self.token_ids_array

                def to_string(self) -> str:
                    """Convert token to its string representation (for debugging only)"""
                    return f"TokenRaw({token_type_enum.name}, {self.token_ids_array.tolist()})"

                def to_asm_like(self) -> str:
                    """Convert token to its string representation that resembles assembly syntax"""
                    return f"raw:{token_type_enum.name}:{','.join(map(str, self.token_ids_array))}"

                def resolve(self, vocab_manager: 'VocabularyManager') -> 'Tokens':
                    """
                    Resolve this TokenRaw into a concrete token using the VocabularyManager

                    Args:
                        vocab_manager: VocabularyManager instance to resolve token IDs

                    Returns:
                        Concrete token instance based on the token type and IDs
                    """
                    token_ids_list = self.get_token_ids()
                    return vocab_manager._reconstruct_token_from_ids(token_type_enum, token_ids_list)

            TokenRaw._cache[token_type_enum] = TokenRawInner
            return TokenRawInner





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
