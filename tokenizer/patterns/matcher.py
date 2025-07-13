from typing import Iterator, Optional, List

from .engine import Sequence, PatternElem, TokenBuffer, MatchError, PatternMatchError, Alternatives
from .patterns import TokenPatternType, listToPatternParseResult, PatternSinglet
from tokenizer.token_manager import VocabularyManager
from tokenizer.tokens import Tokens


class TokenPattern():
    def __init__(self, *pattern: TokenPatternType ):
        super().__init__()
        if len(pattern) == 0:
            raise ValueError("TokenPattern must have at least one pattern element")
        elif len(pattern) == 1:
            pattern = pattern[0]
        else:
            pattern = listToPatternParseResult(pattern)


        if isinstance(pattern, PatternSinglet):
            self.pattern: PatternElem = pattern.to_pattern_elem()
        else:
            self.pattern: PatternElem = pattern.finalize()
        self._last_error = None


    def match_throw(self, token_iter: Iterator[Tokens], vocab_manager: Optional[VocabularyManager] = None, trace=False):
        buf = TokenBuffer(token_iter)
        self._last_error = None
        trace = [] if trace else None
        try:
            self.pattern.match_throw(buf, vocab_manager, trace)
        except MatchError as e:
            try:
                raise PatternMatchError(f"Pattern match failed: {e}", trace) from e
            except PatternMatchError as re:
                self._last_error = re
                raise
        if not buf.finished:
            raise PatternMatchError(f"Pattern match did not consume all tokens, remaining at position {buf.current_index}",
                                    trace)


    def match(self, token_iter: Iterator[Tokens], vocab_manager: Optional[VocabularyManager] = None, trace=False) -> bool:
        try:
            self.match_throw(token_iter, vocab_manager, trace)
            return True
        except PatternMatchError:
            return False

    def get_error(self) -> Optional[PatternMatchError]:
        """
        Returns the last error encountered during matching, if any.
        """
        return self._last_error

    def get_trace(self) -> Optional[List[str]]:
        """
        Returns the trace of matching steps if available.
        """
        if self._last_error is not None:
            return self._last_error.trace
        return None

    def __str__(self):
        inner = str(self.pattern)
        # Remove outer [] or () if present and pattern is Sequence or Alternatives
        if isinstance(self.pattern, Sequence) and inner.startswith("[") and inner.endswith("]"):
            inner = inner[1:-1]
        elif isinstance(self.pattern, Alternatives) and inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1]
        return f"TokenPattern: {inner}"

    def __repr__(self):
        inner = repr(self.pattern)
        # Remove leading 'Sequence' or 'Alternatives' if present
        if isinstance(self.pattern, Sequence) and inner.startswith("Sequence["):
            inner = inner[len("Sequence["):-1]
        elif isinstance(self.pattern, Alternatives) and inner.startswith("Alternatives("):
            inner = inner[len("Alternatives["):-1]
        return f"TokenPattern({inner})"
