import torch
from torch.utils.data import Dataset
import random


class BERTDataset(Dataset):
    # must reimplement __getitem__(self, item) which returns the input and labels
    def __init__(self, data_pairs, tokenizer, seq_len=16, device="cuda"):
        self.tokenizer = tokenizer
        self.seq_len = seq_len
        self.corpus_lines = len(data_pairs) # sample: (instr1, instr2)
        self.lines = data_pairs
        self.device = device

    def __len__(self):
        return len(self.lines)
        
    def random_word(self, tokens):
        output = []
        labels = []
        for token in tokens:
            if random.random() < 0.15:
                if random.random() < 0.8:
                    output.append(self.tokenizer.vocab['[MASK]'])  # 80% Replace with MASK
                elif random.random() < 0.9:
                    output.append(random.choice(list(self.tokenizer.vocab.values())))  # 10% Random token
                else:
                    output.append(token)  # 10% Keep original
                # TODO: update labels

                labels.append(token) # Label is original token ID for masked tokens

            else:
                output.append(token)
                #TODO: update labels
                labels.append(0) # Not masked, ignore in loss

        assert(len(output) == len(labels))
        return output, labels    
        
    def __getitem__(self, item):
        t1, t2 = self.get_sent(item)

        # Tokenizing Assembly Code
        t1_tokens = self.tokenizer.encode(t1)
        t2_tokens = self.tokenizer.encode(t2)

        # Masking random words
        t1_random, t1_label = self.random_word(t1_tokens)
        t2_random, t2_label = self.random_word(t2_tokens)
        
        t1_random = t1_random[:self.seq_len] + [self.tokenizer.vocab['[PAD]']] * (self.seq_len - len(t1_random))
        t2_random = t2_random[:self.seq_len] + [self.tokenizer.vocab['[PAD]']] * (self.seq_len - len(t2_random))
        t1_label = t1_label[:self.seq_len] + [0] * (self.seq_len - len(t1_label))
        t2_label = t2_label[:self.seq_len] + [0] * (self.seq_len - len(t2_label))
        
        # TODO: Adding CLS and SEP tokens
        cls_id = self.tokenizer.vocab['[CLS]']
        sep_id = self.tokenizer.vocab['[SEP]']

        bert_input = [cls_id] + t1_random + [sep_id] + t2_random + [sep_id]
        bert_label = [0] + t1_label + [0] + t2_label + [0]
        
        #bert_input = t1 + t2
        #bert_label = (t1_label + t2_label)
        return {
            "bert_input": torch.tensor(bert_input, dtype=torch.long),
            "bert_label": torch.tensor(bert_label, dtype=torch.long)
        }
        
    def get_sent(self, index):
        t1, t2 = self.lines[index]
        return t1, t2
