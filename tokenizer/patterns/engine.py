from enum import Enum, auto
from typing import Iterator, Any, Optional, List
import traceback
from abc import ABC, abstractmethod

from tokenizer.architecture import PlatformInstructionTypes
from tokenizer.token_manager import VocabularyManager
from tokenizer.tokens import TokenType, MemoryOperandSymbol, TokenRaw

DEBUG_PATTERN = True  # Set to True to enable debug prints

class RepeatType(Enum):
    MAYBE = auto()
    MULTI = auto()
    LOOKAHEAD = auto()

class MatchError(RuntimeError):
    def __init__(self, message: str):
        super().__init__(message)
        

class PatternMatchError(MatchError):
    def __init__(self, message: str, trace: Optional[List[str]] = None):
        super().__init__(message)
        self.trace = trace if trace is not None else []
        self._traceback = traceback.format_exc()

    def __str__(self):
        if self.trace is None:
            return f"{super().__str__()}\n\tMatch tracing was disable."
        else:
            return f"{super().__str__()}\nMatching Trace:\n\t{"\n\t".join(self.trace)}\n\n"
            # return f"{super().__str__()}\nMatching Trace: {self.trace}\nTraceback:\n{self._traceback}"


class TokenBuffer:
    def __init__(self, token_iter: Iterator[Any]):
        self._iter = token_iter
        self._buffer: List[Any] = []
        self._stack: List[int] = []
        self.forgotten_len: int = 0
        self.current_rel_index: int = 0
        self._finished = False

    def __enter__(self):
        top = self._stack[-1] if self._stack else 0
        abs_index = top + self.current_rel_index
        self._stack.append(abs_index)
        self.current_rel_index = 0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pop = self._stack.pop()
        if self._stack:
            new_top = self._stack[-1]
            self.current_rel_index = pop - new_top + self.current_rel_index
        else:
            self.forgotten_len += pop
            self._buffer = self._buffer[pop:]
            self.current_rel_index = 0

    def rollback(self):
        self.current_rel_index = 0

    def _buf_index(self):
        top = self._stack[-1] if self._stack else 0
        return top - self.forgotten_len + self.current_rel_index

    @property
    def current_index(self):
        top = self._stack[-1] if self._stack else 0
        return top + self.current_rel_index - 1

    def getCurrent(self, require_resolved=False, pat=None, vocab_manager=None) -> Any:
        buf_index = self._buf_index()
        while len(self._buffer) <= buf_index:
            if self.finished:
                raise MatchError(f"Expected token at position {buf_index + self.forgotten_len}, but iterator is finished")


        if pat is not None and isinstance(pat, CheckSingleBase):
            require_resolved = pat.__class__.require_resolved()
        tok = self._buffer[buf_index]
        self.current_rel_index += 1
        if require_resolved and isinstance(tok, TokenRaw):
            if vocab_manager is None:
                raise MatchError(f"Token {tok} must be resolved but does not support resolve()")
            tok2 = tok.resolve(vocab_manager)
            self._buffer[buf_index] = tok2
            return tok2
        return tok


    @property
    def finished(self) -> bool:
        if self._finished:
            return True
        try:
            self._buffer.append(next(self._iter))
            return False
        except StopIteration:
            self._finished = True
            return True



    def resolved(self, idx: int) -> bool:
        self.current_rel_index = idx
        buf_index = self._buf_index()
        return buf_index < len(self._buffer) and not isinstance(self._buffer[buf_index], TokenRaw)



class PatternElem:
    def __init__(self):
        pass

    def match_throw(self, buf: TokenBuffer, vocab_manager: Optional[VocabularyManager], trace=None):
        raise NotImplementedError

    def __repr__(self):
        return f"{self.__class__.__name__}({self.__dict__})"


class CheckSingleBase(PatternElem, ABC):
    class_field = None  # If set to an Enum, use for error reporting

    def __init__(self, pat):
        super().__init__()
        self.pat = pat

    @classmethod
    @abstractmethod
    def require_resolved(cls):
        pass

    @classmethod
    @abstractmethod
    def get_check_property(cls, tok, pat):
        """
        Returns the property value to be compared for the token.
        For OpaqueWithValue, ValuedWithValue, BlockWithValue, returns None if the attribute is missing.
        """
        pass

    def get_token(self, buf, vocab_manager):
        return buf.getCurrent(require_resolved=self.__class__.require_resolved(), pat=self.pat,
                              vocab_manager=vocab_manager)

    @classmethod
    def _format_enum(cls, value):
        enum_cls = cls.class_field
        if enum_cls is not None and value in enum_cls._value2member_map_:
            return f"{enum_cls.__name__}.{enum_cls(value).name}"
        return str(value)

    def match_throw(self, buf, vocab_manager, trace=None):
        tok = self.get_token(buf, vocab_manager)
        expected = self.pat
        actual = self.__class__.get_check_property(tok, self.pat)
        class_name = self.__class__.__name__.replace("Elem", "")
        if hasattr(self, 'value'):
            expected = self.value
        expected_str = self._format_enum(expected)
        actual_str = self._format_enum(actual)
        if actual == expected:
            if trace is not None:
                trace.append(f"[ACCEPT] {str(self)} at pos {buf.current_index}")
            return
        if trace is not None:
            trace.append(f"[REJECT] {str(self)} at pos {buf.current_index}: expected {expected_str}, got {actual_str}")
        raise MatchError(
            f"{class_name}: Token at position {buf.current_index} expected {expected_str}, got {actual_str}"
        )

class RequireResolved(CheckSingleBase):
    @classmethod
    def require_resolved(cls):
        return True

class AllowUnresolved(CheckSingleBase):
    @classmethod
    def require_resolved(cls):
        return False

class TokenTypeElem(AllowUnresolved):
    class_field = TokenType

    @classmethod
    def get_check_property(cls, tok, pat):
        return tok.token_type

    # def __str__(self):
    #     # Show only enum member name for TokenType
    #     if isinstance(self.pat, TokenType):
    #         return f"TokenType ({self.pat.name})"
    #     return f"TokenType ({self.pat})"

    def with_value(self, value) -> Optional['WithValueSequence']:
        result = None
        if self.pat == TokenType.BLOCK:
            result = BlockWithValue(value)
        elif self.pat == TokenType.OPAQUE_CONST:
            result = OpaqueWithValue(value)
        elif self.pat == TokenType.VALUED_CONST:
            result = ValuedWithValue(value)

        if result is not None:
            return WithValueSequence(self, result)


    def __repr__(self):
        return f"{camelcase(self.pat.name)}"

class PlatformInstructionTypesElem(RequireResolved):
    class_field = PlatformInstructionTypes

    @classmethod
    def get_check_property(cls, tok, pat):
        return getattr(tok, "platform_instruction_type", None)

    # def __str__(self):
    #     if isinstance(self.pat, PlatformInstructionTypes):
    #         return f"PlatformInstructionTypes ({self.pat.name})"
    #     return f"PlatformInstructionTypes ({self.pat})"

    def __repr__(self):
        return f"Insn{camelcase(self.pat.name)}"

class MemoryOperandSymbolElem(RequireResolved):
    class_field = MemoryOperandSymbol

    @classmethod
    def get_check_property(cls, tok, pat):
        return getattr(tok, "symbol", None)

    # def __str__(self):
    #     if isinstance(self.pat, MemoryOperandSymbol):
    #         return f"MemoryOperandSymbol ({self.pat.name})"
    #     return f"MemoryOperandSymbol ({self.pat})"

    def __repr__(self):
        return f"Mem{camelcase(self.pat.name)}"

class WithValueBase(RequireResolved, ABC):
    unresolved_value = None

    def __init__(self, value):
        super().__init__(value)

    def __str__(self):
        return str(self.pat)

class OpaqueWithValue(WithValueBase):
    unresolved_value = TokenType.OPAQUE_CONST

    def __init__(self, value):
        super().__init__(value)

    @classmethod
    def get_check_property(cls, tok, pat):
        return tok.id


    def __repr__(self):
        return f"OpaqueWithValue ({self.pat})"

class ValuedWithValue(WithValueBase):
    unresolved_value = TokenType.VALUED_CONST

    def __init__(self, value):
        super().__init__(value)

    @classmethod
    def get_check_property(cls, tok, pat):
        return tok.value

    def __repr__(self):
        return f"ValuedWithValue ({self.pat})"


class BlockWithValue(WithValueBase):
    unresolved_value = TokenType.BLOCK

    def __init__(self, value):
        super().__init__(value)

    @classmethod
    def get_check_property(cls, tok, pat):
        return getattr(tok, "id", None)

    def __repr__(self):
        return f"BlockWithValue ({self.pat})"


class MaybeElem(PatternElem):
    def __init__(self, pat):
        super().__init__()
        self.pat = pat

    def match_throw(self, buf: TokenBuffer, vocab_manager: Optional[VocabularyManager], trace=None):
        with buf:
            try:
                self.pat.match_throw(buf, vocab_manager, trace)
                if trace is not None:
                    trace.append(f"[ACCEPT] {str(self.pat)} at pos {buf.current_index}")
            except MatchError as e:
                if trace is not None:
                    trace.append(f"[REJECT] {str(self.pat)} at pos {buf.current_index}: {e}")
                buf.rollback()

    def __str__(self):
        return f"Maybe + {str(self.pat)}"
    def __repr__(self):
        return f"Maybe + {repr(self.pat)}"

class MultiElem(PatternElem):
    def __init__(self, pat):
        super().__init__()
        self.pat = pat

    def match_throw(self, buf: TokenBuffer, vocab_manager: Optional[VocabularyManager], trace=None):
        if trace is not None:
            trace.append(f"Entering OneOrMore at pos {buf.current_index}")
        errors = []
        with buf:
            try:
                self.pat.match_throw(buf, vocab_manager, trace)
                if trace is not None:
                    trace.append(f"[ACCEPT] OneOrMore({str(self.pat)}) first at pos {buf.current_index}")
            except MatchError as e:
                if trace is not None:
                    trace.append(f"[REJECT] OneOrMore({str(self.pat)}) first at pos {buf.current_index}: {e}")
                errors.append(f"OneOrMore expected at least one match at position {buf.current_index}: {str(e)}")
                raise MatchError(errors[-1])
            while True:
                try:
                    self.pat.match_throw(buf, vocab_manager, trace)
                    if trace is not None:
                        trace.append(f"[ACCEPT] OneOrMore({str(self.pat)}) iteration at pos {buf.current_index}")
                except MatchError as e:
                    if trace is not None:
                        trace.append(f"[REJECT] OneOrMore({str(self.pat)}) iteration at pos {buf.current_index}: {e}")
                    errors.append(f"OneOrMore failed at position {buf.current_index}: {str(e)}")
                    break

    def __str__(self):
        return f"Multi + {str(self.pat)}"
    def __repr__(self):
        return f"Multi + {repr(self.pat)}"

class Alternatives(PatternElem):
    def __init__(self, alternatives: List[PatternElem]):
        super().__init__()
        if len(alternatives) < 2:
            raise ValueError("Alternatives must have at least two options")
        self.alternatives = alternatives

    def match_throw(self, buf: TokenBuffer, vocab_manager: Optional[VocabularyManager], trace=None):
        if trace is not None:
            trace.append(f"Entering Alternatives at pos {buf.current_index}")
        errors = []
        for alt in self.alternatives:
            with buf:
                try:
                    alt.match_throw(buf, vocab_manager, trace)
                    if trace is not None:
                        trace.append(f"[ACCEPT] Alternatives({str(alt)}) at pos {buf.current_index}")
                    return
                except MatchError as e:
                    buf.rollback()
                    if trace is not None:
                        trace.append(f"[REJECT] Alternatives({str(alt)}) at pos {buf.current_index}: {e}")
                    errors.append(str(e))
        self._last_error = MatchError(f"None of the alternatives matched at position {buf.current_index}: {errors}")
        raise self._last_error

    def __str__(self):
        return "(" + " | ".join(str(alt) for alt in self.alternatives) + ")"
    def __repr__(self):

        return "(" + " | ".join(repr(alt) for alt in self.alternatives) + ")"
        # return f"Alternatives({", ".join(repr(elem) for elem in self.alternatives)})"

class LookaheadElem(PatternElem):
    def __init__(self, pat_elem):
        super().__init__()
        self.pat_elem = pat_elem

    def match_throw(self, buf: TokenBuffer, vocab_manager: Optional[VocabularyManager], trace=None):
        if trace is not None:
            trace.append(f"Entering Lookahead at pos {buf.current_index}")
        with buf:
            try:
                self.pat_elem.match_throw(buf, vocab_manager, trace)
                return
            except MatchError as e:
                if trace is not None:
                    trace.append(f"[REJECT] Lookahead {str(self.pat_elem)} at pos {buf.current_index}: {e}")
                # Pass through the original error message
                raise MatchError(f"Lookahead failed at pos {buf.current_index}: {e}") from e
            finally:
                buf.rollback()

    def __str__(self):
        return f"Lookahead + {str(self.pat_elem)}"
    def __repr__(self):
        return f"Lookahead + {repr(self.pat_elem)}"

class Sequence(PatternElem):
    def __init__(self, sequence: List['PatternElem']):
        super().__init__()
        self.sequence = sequence

    def match_throw(self, buf: TokenBuffer, vocab_manager: Optional[VocabularyManager], trace=None):
        if trace is not None:
            trace.append(f"Entering Sequence at pos {buf.current_index}")
        with buf:
            for elem in self.sequence:
                try:
                    elem.match_throw(buf, vocab_manager, trace)
                    if trace is not None:
                        trace.append(f"[ACCEPT] Sequence element {str(elem)} at pos {buf.current_index}")
                except MatchError as e:
                    index = buf.current_index
                    buf.rollback()
                    if trace is not None:
                        trace.append(f"[REJECT] Sequence element {str(elem)} at pos {index}: {e}")
                    # Pass through the original error message
                    raise MatchError(f"Sequence failed at position {index} for element {str(elem)}: {e}") from e
        # No return needed

    def __str__(self):
        return "[" + ", ".join(str(elem) for elem in self.sequence) + "]"

    def __repr__(self):
        return "[" + ", ".join(repr(elem) for elem in self.sequence) + "]"
        # return f"Sequence[{", ".join(repr(elem) for elem in self.sequence)}]"

class WithValueSequence(Sequence):
    def __init__(self, unresolved: AllowUnresolved, value: WithValueBase):
        super().__init__([LookaheadElem(unresolved), value])

    def __str__(self):
        return f"{self.sequence[0].pat_elem} + {self.sequence[1]}"
    def __repr__(self):
        return f"{repr(self.sequence[0].pat_elem)} + {repr(self.sequence[1])}"


def camelcase(name):
    parts = name.lower().split('_')
    return parts[0].capitalize() + ''.join(p.capitalize() for p in parts[1:])