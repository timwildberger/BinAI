from enum import Enum, auto
from typing import Iterator, Any, Optional, List

from tokenizer.architecture import PlatformInstructionTypes
from tokenizer.tokens import TokenType, MemoryOperandSymbol


class RepeatType(Enum):
    MAYBE = auto()
    ONE = auto()
    MULTIPLE = auto()


class TokenBuffer:
    def __init__(self, token_iter: Iterator[Any]):
        self._iter = token_iter
        self._buffer: List[Any] = []
        self._resolved: List[bool] = []

    def get(self, idx: int) -> Any:
        while len(self._buffer) <= idx:
            try:
                self._buffer.append(next(self._iter))
                self._resolved.append(False)
            except StopIteration:
                return None
        return self._buffer[idx]

    def set(self, idx: int, value: Any):
        self._buffer[idx] = value
        self._resolved[idx] = True

    def resolved(self, idx: int) -> bool:
        return idx < len(self._resolved) and self._resolved[idx]

    def length(self) -> int:
        # Try to exhaust the iterator to get full length
        while True:
            try:
                self._buffer.append(next(self._iter))
                self._resolved.append(False)
            except StopIteration:
                break
        return len(self._buffer)

    def slice(self, start: int, end: int) -> List[Any]:
        for i in range(end):
            self.get(i)
        return self._buffer[start:end]


class PatternElem:
    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any]) -> Optional[int]:
        raise NotImplementedError


class One(PatternElem):
    def __init__(self, pat):
        self.pat = pat

    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any]) -> Optional[int]:
        tok = buf.get(start)
        if tok is None:
            return None
        if not buf.resolved(start):
            tok2 = TokenPattern._resolve_token_or_error(tok, self.pat, vocab_manager)
            if tok2 is not tok:
                buf.set(start, tok2)
            tok = tok2
        if TokenPattern._token_matches(tok, self.pat):
            return 1
        return None


class WithValue(PatternElem):
    def __init__(self, token_type, value):
        self.token_type = token_type
        self.value = value

    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any]) -> Optional[int]:
        tok = buf.get(start)
        if tok is None:
            return None
        if not (hasattr(tok, "token_type") and tok.token_type == self.token_type):
            return None
        if hasattr(tok, "resolve") and not buf.resolved(start):
            tok2 = tok.resolve(vocab_manager)
            buf.set(start, tok2)
            tok = tok2
        if self.token_type == TokenType.VALUED_CONST or self.token_type == TokenType.OPAQUE_CONST:
            if hasattr(tok, "value") and tok.value == self.value:
                return 1
        elif self.token_type == TokenType.BLOCK:
            if hasattr(tok, "id") and tok.id == self.value:
                return 1
        elif self.token_type == TokenType.PLATFORM:
            if hasattr(tok, "token") and tok.token == self.value:
                return 1
        return None


class MaybeOne(PatternElem):
    def __init__(self, pat):
        self.pat = pat

    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any]) -> Optional[int]:
        res = self.pat.match(buf, start, vocab_manager)
        if res is not None:
            return res
        return 0


class ZeroOrMore(PatternElem):
    def __init__(self, pat):
        self.pat = pat

    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any]) -> Optional[int]:
        idx = start
        while True:
            res = self.pat.match(buf, idx, vocab_manager)
            if res is not None and res > 0:
                idx += res
            else:
                break
        return idx - start


class OneOrMore(PatternElem):
    def __init__(self, pat):
        self.pat = pat

    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any]) -> Optional[int]:
        idx = start
        first = self.pat.match(buf, idx, vocab_manager)
        if first is None or first == 0:
            return None
        idx += first
        while True:
            res = self.pat.match(buf, idx, vocab_manager)
            if res is not None and res > 0:
                idx += res
            else:
                break
        return idx - start


class Alternatives(PatternElem):
    def __init__(self, alternatives: List[PatternElem]):
        self.alternatives = alternatives

    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any]) -> Optional[int]:
        for alt in self.alternatives:
            res = alt.match(buf, start, vocab_manager)
            if res is not None:
                return res
        return None


class Sequence(PatternElem):
    def __init__(self, sequence: List[PatternElem]):
        self.sequence = sequence

    def match(self, buf: TokenBuffer, start: int, vocab_manager: Optional[Any]) -> Optional[int]:
        idx = start
        for elem in self.sequence:
            res = elem.match(buf, idx, vocab_manager)
            if res is None:
                return None
            idx += res
        return idx - start


class TokenPattern(PatternElem):
    def __init__(self, *args):
        self.pattern = self._parse_args(args)
        if isinstance(self.pattern, list) and len(self.pattern) == 1:
            self.pattern = self.pattern[0]

    @staticmethod
    def _is_resolvable_type(pat):
        return isinstance(pat, (MemoryOperandSymbol, PlatformInstructionTypes))

    @staticmethod
    def _token_matches(tok, pat):
        return (
            hasattr(tok, "token_type") and tok.token_type == pat or
            hasattr(tok, "symbol") and tok.symbol == pat or
            hasattr(tok, "platform_instruction_type") and tok.platform_instruction_type == pat
        )

    @staticmethod
    def _resolve_token_or_error(tok, pat, vocab_manager):
        if vocab_manager is not None and TokenPattern._is_resolvable_type(pat):
            if hasattr(tok, "resolve"):
                return tok.resolve(vocab_manager)
            else:
                raise RuntimeError(f"Token {tok} must be resolved but does not support resolve()")
        return tok

    def _parse_args(self, args):
        pattern = []
        i = 0
        while i < len(args):
            arg = args[i]
            if isinstance(arg, tuple):
                # Flatten alternatives
                alt_elems = []
                for a in arg:
                    parsed = self._parse_args([a])
                    if isinstance(parsed, list):
                        alt_elems.extend(parsed)
                    else:
                        alt_elems.append(parsed)
                pattern.append(Alternatives(alt_elems))
            elif isinstance(arg, list):
                # Flatten sequence
                seq_elems = []
                for a in arg:
                    parsed = self._parse_args([a])
                    if isinstance(parsed, list):
                        seq_elems.extend(parsed)
                    else:
                        seq_elems.append(parsed)
                pattern.append(Sequence(seq_elems))
            elif isinstance(arg, RepeatType):
                if i + 1 < len(args):
                    next_arg = args[i + 1]
                    if arg == RepeatType.MAYBE and next_arg == RepeatType.ONE:
                        pat = self._parse_args([args[i + 2]]) if i + 2 < len(args) else None
                        pattern.append(MaybeOne(pat))
                        i += 2
                        continue
                    elif arg == RepeatType.MAYBE and next_arg == RepeatType.MULTIPLE:
                        pat = self._parse_args([args[i + 2]]) if i + 2 < len(args) else None
                        pattern.append(ZeroOrMore(pat))
                        i += 2
                        continue
                    elif arg == RepeatType.ONE:
                        pat = self._parse_args([next_arg])
                        pattern.append(One(pat if not isinstance(pat, list) else pat[0]))
                        i += 1
                        continue
                    elif arg == RepeatType.MULTIPLE:
                        pat = self._parse_args([next_arg])
                        pattern.append(OneOrMore(pat if not isinstance(pat, list) else pat[0]))
                        i += 1
                        continue
                    elif arg == RepeatType.MAYBE:
                        pat = self._parse_args([next_arg])
                        pattern.append(MaybeOne(pat if not isinstance(pat, list) else pat[0]))
                        i += 1
                        continue
                else:
                    raise ValueError("RepeatType must be followed by a pattern")
            elif self._is_resolvable_type(arg):
                pattern.append(One(arg))
            elif (
                isinstance(arg, tuple)
                and len(arg) == 2
                and isinstance(arg[0], TokenType)
                and (
                    isinstance(arg[1], (int, str))
                )
            ):
                pattern.append(WithValue(arg[0], arg[1]))
            else:
                pattern.append(One(arg))
            i += 1
        # If only one element, return it directly
        if len(pattern) == 1:
            return pattern[0]
        return pattern

    def match(self, token_iter: Iterator[Any], vocab_manager: Optional[Any] = None) -> bool:
        buf = TokenBuffer(token_iter)
        res = None
        if isinstance(self.pattern, PatternElem):
            res = self.pattern.match(buf, 0, vocab_manager)
        else:
            # Should not happen, but fallback
            res = Sequence(self.pattern).match(buf, 0, vocab_manager)
        return res is not None and res == buf.length()
