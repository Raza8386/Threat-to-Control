"""Embedding backends. Anthropic has no embedding model, so we use Voyage AI.

- NanoEmbedder: voyage-4-nano, open-weight, runs locally (no API key, no cost).
- VoyageAPIEmbedder: hosted Voyage API (VOYAGE_API_KEY), e.g. voyage-4-lite.
- HashEmbedder: deterministic, dependency-free stand-in used only by tests.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol

from app.config import Settings, settings as default_settings


class Embedder(Protocol):
    name: str
    dim: int

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...
    def embed_query(self, text: str) -> list[float]: ...


class NanoEmbedder:
    """Local sentence-transformers model. Default voyage-4-nano; any ST model id works (e.g. BAAI/bge-small-en-v1.5)."""

    def __init__(self, model: str, dim: int | None, max_tokens: int = 768, batch_size: int = 8):
        from sentence_transformers import SentenceTransformer  # heavy import, load lazily

        kwargs = {"trust_remote_code": True}
        if dim:
            kwargs["truncate_dim"] = dim
        self._model = SentenceTransformer(model, **kwargs)
        # voyage-4-nano supports 32k tokens; left uncapped, CPU runs crawl. Our chunks are ~500 tokens.
        self._model.max_seq_length = max_tokens
        self.dim = dim or self._model.get_sentence_embedding_dimension()
        self.name = f"{model}@{self.dim}"
        self.batch_size = batch_size
        self._has_prompts = hasattr(self._model, "encode_document") and bool(getattr(self._model, "prompts", None))

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        encode = self._model.encode_document if self._has_prompts else self._model.encode
        vecs = encode(texts, batch_size=self.batch_size, normalize_embeddings=True, show_progress_bar=True)
        return vecs.tolist()

    def embed_query(self, text: str) -> list[float]:
        encode = self._model.encode_query if self._has_prompts else self._model.encode
        return encode(text, normalize_embeddings=True).tolist()


class VoyageAPIEmbedder:
    def __init__(self, model: str, dim: int, batch_size: int = 64):
        import voyageai

        self.name = f"voyage-api:{model}@{dim}"
        self.dim = dim
        self.model = model
        self.batch_size = batch_size
        self._client = voyageai.Client()  # reads VOYAGE_API_KEY

    def _embed(self, texts: list[str], input_type: str) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), self.batch_size):
            res = self._client.embed(
                texts[i : i + self.batch_size], model=self.model, input_type=input_type, output_dimension=self.dim
            )
            out.extend(res.embeddings)
        return out

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._embed(texts, "document")

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text], "query")[0]


class HashEmbedder:
    """Bag-of-hashed-words vectors. Only for tests; it has no semantic understanding."""

    def __init__(self, dim: int = 256):
        self.name = f"hash@{dim}"
        self.dim = dim

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.dim
        for tok in re.findall(r"[a-z0-9]+", text.lower()):
            h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
            v[h % self.dim] += 1.0
        norm = math.sqrt(sum(x * x for x in v)) or 1.0
        return [x / norm for x in v]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._vec(text)


def get_embedder(cfg: Settings = default_settings) -> Embedder:
    if cfg.embed_backend in ("nano", "local"):
        dim = cfg.embed_dim if cfg.embed_backend == "nano" else None
        return NanoEmbedder(cfg.embed_model, dim, max_tokens=cfg.embed_max_tokens, batch_size=cfg.embed_batch)
    if cfg.embed_backend == "voyage":
        return VoyageAPIEmbedder(cfg.voyage_api_model, cfg.embed_dim)
    if cfg.embed_backend == "hash":
        return HashEmbedder(cfg.embed_dim)
    raise ValueError(f"Unknown EMBED_BACKEND={cfg.embed_backend!r} (use nano, local, voyage or hash)")
