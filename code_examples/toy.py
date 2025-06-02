import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from torchtext.data.utils import get_tokenizer
from torchtext.datasets import AG_NEWS
from collections import Counter
import pickle
from torchtext.vocab import build_vocab_from_iterator
from torchtext.datasets import AG_NEWS
from torchviz import make_dot

class MyTokenizer:
    def __init__(self, min_freq=10, max_len=32):
        self.basic_tokenizer = get_tokenizer("basic_english")
        self.max_len = max_len
        counter = Counter()
        for label, line in AG_NEWS(split='train'):
            counter.update(self.basic_tokenizer(line))

        self.vocab = build_vocab_from_iterator([self.basic_tokenizer(line) for _, line in AG_NEWS(split='train')],
                                               min_freq=min_freq,
                                               specials=["<pad>", "<unk>"])

        self.pad_idx = self.vocab["<pad>"]
        self.unk_idx = self.vocab["<unk>"]
        self.vocab.set_default_index(self.unk_idx)

    def encode(self, text):
        tokens = self.basic_tokenizer(text)
        ids = [self.vocab[token] if token in self.vocab.get_stoi() else self.unk_idx for token in tokens][:self.max_len]
        padding = [self.pad_idx] * (self.max_len - len(ids))
        return ids + padding

    def decode(self, ids):
        return ' '.join([self.vocab.itos[i] for i in ids if i != self.pad_idx])

    def save(self, path):
        with open(path, "wb") as f:
            pickle.dump((self.vocab, self.max_len), f)

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            vocab, max_len = pickle.load(f)
        tokenizer = cls.__new__(cls)
        tokenizer.basic_tokenizer = get_tokenizer("basic_english")
        tokenizer.vocab = vocab
        tokenizer.max_len = max_len
        tokenizer.pad_idx = vocab["<pad>"]
        tokenizer.unk_idx = vocab["<unk>"]
        return tokenizer


class TextDataset(Dataset):
    def __init__(self, tokenizer, split='train'):
        self.data = list(AG_NEWS(split=split))
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        label, text = self.data[idx]
        input_ids = torch.tensor(self.tokenizer.encode(text), dtype=torch.long)
        return input_ids, torch.tensor(label - 1)


class FeedForward(nn.Module):
    def __init__(self, vocab_size, d_model=128, middle_dim=256, dropout=0.1, num_classes=4):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=0)
        self.ffn = nn.Sequential(
            nn.Linear(d_model, middle_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(middle_dim, num_classes)
        )

    def forward(self, x):
        emb = self.embedding(x)        # (B, T, D)
        rep = emb.mean(dim=1)          # (B, D)
        out = self.ffn(rep)            # (B, C)
        return out  


def train():
    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = MyTokenizer()
    dataset = TextDataset(tokenizer, "train")
    dataloader = DataLoader(dataset, batch_size=64, shuffle=True)
    print("vocab size:", len(tokenizer.vocab))
    model = FeedForward(vocab_size=len(tokenizer.vocab)).to(device)
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.CrossEntropyLoss()

    for epoch in range(1):
        print(f"\nEpoch {epoch + 1} Training Start...")
        model.train()  # Set model to training mode
        total_loss = 0
        total_batches = len(dataloader)

        for batch_idx, (x, y) in enumerate(dataloader):
            print("x.shape: ", x.shape)
            x, y = x.to(device), y.to(device)
            logits = model(x)
            loss = criterion(logits, y)
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            if(batch_idx==0):
                #print(model.embedding.weight.grad)
                dot = make_dot(logits, params=dict(model.named_parameters()))
                dot.format = 'png'
                dot.render('ffn_graph')

            if (batch_idx + 1) % 10 == 0 or batch_idx + 1 == total_batches:
                print(f"  Batch [{batch_idx + 1}/{total_batches}], Loss: {loss.item():.4f}")

        print(f"Epoch {epoch + 1} Training Complete, Average Loss: {total_loss / total_batches:.4f}")


if __name__ == "__main__":
    train()
