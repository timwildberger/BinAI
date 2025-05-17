import torch
import math
import torch.nn.functional as F
import torch.nn as nn



class PositionalEmbedding(nn.Module):
    def __init__(self, max_len, d_model):
        super(PositionalEmbedding, self).__init__()
        self.pos_embedding = nn.Embedding(max_len, d_model)

    def forward(self, x):
        # x shape: (batch_size, seq_len)
        seq_len = x.size(1)
        positions = torch.arange(seq_len, device=x.device).unsqueeze(0).expand_as(x)
        return self.pos_embedding(positions)


class FeedForward(torch.nn.Module):
    "Implements FFN equation."

    def __init__(self, d_model, middle_dim=2048, dropout=0.1):
        super(FeedForward, self).__init__()
        
        self.fc1 = torch.nn.Linear(d_model, middle_dim)
        self.fc2 = torch.nn.Linear(middle_dim, d_model)
        self.dropout = torch.nn.Dropout(dropout)
        self.activation = torch.nn.GELU()

    def forward(self, x):
        out = self.activation(self.fc1(x))
        out = self.fc2(self.dropout(out))
        return out


### attention layers
class ScaledDotProductAttention(nn.Module):
    def __init__(self, dropout=0.1, d_k=8):
        super(ScaledDotProductAttention, self).__init__()
        self.dropout = nn.Dropout(dropout)
        self.d_k = d_k # hidden dim of k

    def forward(self, query, key, value, mask=None):
        # TODO: calculate attention score "scores"
        # NOTE: query, key and value are tensors
        
        scores = torch.matmul(query, key.transpose(-2, -1) / math.sqrt(self.d_k))

        if mask is not None:
            scores = scores.masked_fill(mask == 0, -1e9)

        # TODO: calculate attention weights "attn_weights"
        # Softmax to get attention weights as a probability distribution
        attn_weights = F.softmax(scores, dim=-1)

        attn_weights = self.dropout(attn_weights)

        # TODO: calculate final outputs "output"
        output = torch.matmul(attn_weights, value)

        return output, attn_weights

class MultiHeadedAttention(nn.Module):
    def __init__(self, heads, d_model, dropout=0.1):
        super(MultiHeadedAttention, self).__init__()
        assert d_model % heads == 0
        self.d_k = d_model // heads
        self.heads = heads
        self.d_model = d_model

        self.q_linear = nn.Linear(d_model, d_model)
        self.k_linear = nn.Linear(d_model, d_model)
        self.v_linear = nn.Linear(d_model, d_model)
        self.out_proj = nn.Linear(d_model, d_model)

        self.attention = ScaledDotProductAttention(dropout, self.d_k)
    
    def forward(self, query, key, value, mask=None):
        B, L, _ = query.size()

        # Linear projections
        Q = self.q_linear(query).view(B, L, self.heads, self.d_k).transpose(1, 2)  # [B, h, L, d_k]
        K = self.k_linear(key).view(B, L, self.heads, self.d_k).transpose(1, 2)
        V = self.v_linear(value).view(B, L, self.heads, self.d_k).transpose(1, 2)

        # Apply attention for all heads
        attn_output, _ = self.attention(Q, K, V, mask)  # [B, h, L, d_k]
        # Concatenate heads
        attn_output = attn_output.transpose(1, 2).contiguous().view(B, L, self.d_model)  # [B, L, d_model]
        return self.out_proj(attn_output)
    
class MaskedLanguageModel(torch.nn.Module):
    """
    predicting origin token from masked input sequence
    n-class classification problem, n-class = vocab_size
    """

    def __init__(self, hidden, vocab_size):
        """
        :param hidden: output size of BERT model
        :param vocab_size: total vocab size
        """
        super().__init__()
        self.linear = torch.nn.Linear(hidden, vocab_size)
        self.softmax = torch.nn.LogSoftmax(dim=-1)

    def forward(self, x):
        return self.softmax(self.linear(x))

class EncoderLayer(torch.nn.Module):
    def __init__(
        self, 
        d_model=768,
        heads=12, 
        feed_forward_hidden=768 * 4, 
        dropout=0.1
        ):
        super(EncoderLayer, self).__init__()
        self.layernorm = torch.nn.LayerNorm(d_model)
        self.self_multihead = MultiHeadedAttention(heads, d_model)
        self.feed_forward = FeedForward(d_model, middle_dim=feed_forward_hidden)
        self.dropout = torch.nn.Dropout(dropout)

    def forward(self, embeddings, mask):
        # embeddings:   (batch_size, max_len,   d_model)
        # encoder mask: (batch_size, 1,         1,          max_len)
        # result:       (batch_size, max_len,   d_model)
        interacted = self.dropout(self.self_multihead(embeddings, embeddings, embeddings, mask))
        # TODO: add and normalization layer 
        out1 = self.layernorm(embeddings + interacted)

        # bottleneck
        feed_forward_out = self.dropout(self.feed_forward(interacted))
        # TODO: add and normalization layer 
        encoded = self.layernorm(out1 + feed_forward_out)

        return encoded


class BERTEmbedding(torch.nn.Module):
    """
    BERT Embedding which is consisted with under features
        1. TokenEmbedding : normal embedding matrix
        2. PositionalEmbedding : adding positional information using sin, cos
        2. SegmentEmbedding : adding sentence segment info, (sent_A:1, sent_B:2)
        sum of all these features are output of BERTEmbedding
    """

    def __init__(self, vocab_size, embed_size, seq_len=64, dropout=0.1):
        """
        :param vocab_size: total vocab size
        :param embed_size: embedding size of token embedding
        :param dropout: dropout rate
        """

        super().__init__()
        self.embed_size = embed_size
        # (m, seq_len) --> (m, seq_len, embed_size)
        # padding_idx is not updated during training, remains as fixed pad (0)
        self.token = torch.nn.Embedding(vocab_size, embed_size, padding_idx=0)
        self.position = PositionalEmbedding(d_model=embed_size, max_len=seq_len)
        self.dropout = torch.nn.Dropout(p=dropout)
       
    def forward(self, sequence):
        # TODO: get embedding of sequence
        token_embed = self.token(sequence)
        pos_embed = self.position(sequence)
        x = token_embed + pos_embed
        return self.dropout(x)

class BERT(torch.nn.Module):
    """
    BERT model : Bidirectional Encoder Representations from Transformers.
    """

    def __init__(self, vocab_size, d_model=768, n_layers=12, heads=12, dropout=0.1, device="cuda"):
        """
        :param vocab_size: vocab_size of total words
        :param hidden: BERT model hidden size
        :param n_layers: numbers of Transformer blocks(layers)
        :param attn_heads: number of attention heads
        :param dropout: dropout rate
        """

        super().__init__()
        self.d_model = d_model
        self.n_layers = n_layers
        self.heads = heads

        # paper noted they used 4 * hidden_size for ff_network_hidden_size
        self.feed_forward_hidden = d_model * 4

        # embedding for BERT, sum of positional, segment, token embeddings
        self.embedding = BERTEmbedding(vocab_size=vocab_size, embed_size=d_model)

        # multi-layers transformer blocks, deep network
        self.encoder_blocks = torch.nn.ModuleList(
            [EncoderLayer(d_model, heads, d_model * 4, dropout) for _ in range(n_layers)])
        self.mask_lm = MaskedLanguageModel(self.d_model, vocab_size)
        self.device = device

    def forward(self, x):
        # attention masking for padded token
        # (batch_size, 1, seq_len, seq_len)
        # mask = (x > 0).unsqueeze(1).repeat(1, x.size(1), 1).unsqueeze(1)
        x = x.to(self.device)
        mask = (x > 0).unsqueeze(1).unsqueeze(2)

        # TODO: complete the whole process for BERT
        # 0. embedding the indexed sequence to sequence of vectors
        x = self.embedding(x)


        # 1. running over multiple transformer blocks
        for encoder in self.encoder_blocks:
            x = encoder(x, mask)
        # 2. add MLM
        x = self.mask_lm(x)

        return x
