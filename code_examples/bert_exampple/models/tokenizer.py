import os
import re

class AsmTokenizer:
    # vocab txt, each line is a vocab
    # self.vocab: a dictionary with token as key and index as value
    # self.rev_vocab: a dictionary with index as key and token as value
    def __init__(self, corpus=None, vocab_file=None, max_vocab_size=50000):
        self.max_vocab_size = max_vocab_size
        # better to always make [PAD] with index 0
        self.vocab = {"[PAD]": 0, "[CLS]": 1, "[SEP]": 2, "[MASK]": 3, "[UNK]": 4}
        self.rev_vocab = {v: k for k, v in self.vocab.items()}
        if vocab_file and os.path.exists(vocab_file):
            self.load_vocab(vocab_file)
        elif corpus:
            self.build_vocab(corpus)
            self.save_vocab(vocab_file)
                    
    def build_vocab(self, corpus):
        idx = len(self.vocab)
        for line in corpus:
            tokens = self.tokenize(line)
            for tok in tokens:
                if tok not in self.vocab:
                    if len(self.vocab) >= self.max_vocab_size:
                        return
                    self.vocab[tok] = idx
                    self.rev_vocab[idx] = tok
                    idx += 1

    def save_vocab(self, filepath):
        with open(filepath, "w") as f:
            for token, idx in sorted(self.vocab.items(), key=lambda x: x[1]):
                f.write(f"{token}\n")
        print(f"Vocab saved to {filepath}")
    
    def load_vocab(self, filepath):
        with open(filepath, "r") as f:
            for i, line in enumerate(f):
                token = line.strip()
                if i >= self.max_vocab_size:
                    break
                self.vocab[token] = i
                self.rev_vocab[i] = token
        print(f"Vocab loaded from {filepath}")

    def tokenize(self, text):
        # Todo: Custom regex-based tokenization for assembly

        return tokens
    
    def encode(self, text):
        tokens = self.tokenize(text)
        #  If the token is not found in the vocab, return the ID of [UNK]
        return [self.vocab.get(tok, self.vocab["[UNK]"]) for tok in tokens]

    def decode(self, token_ids):
        return " ".join([self.rev_vocab.get(tok_id, "[UNK]") for tok_id in token_ids])
