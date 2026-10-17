"""Runtime settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BACKEND_DIR / "data"

# Load backend/.env if present. Real environment variables still win over the file.
load_dotenv(BACKEND_DIR / ".env", override=False)


@dataclass(frozen=True)
class Settings:
    # Embeddings: "nano" = local voyage-4-nano, "voyage" = hosted Voyage API.
    embed_backend: str = os.getenv("EMBED_BACKEND", "nano")
    embed_model: str = os.getenv("EMBED_MODEL", "voyageai/voyage-4-nano")
    embed_dim: int = int(os.getenv("EMBED_DIM", "1024"))
    voyage_api_model: str = os.getenv("VOYAGE_API_MODEL", "voyage-4-lite")
    embed_max_tokens: int = int(os.getenv("EMBED_MAX_TOKENS", "768"))
    embed_batch: int = int(os.getenv("EMBED_BATCH", "8"))

    # Claude models (used from Phase 2 on).
    answer_model: str = os.getenv("ANSWER_MODEL", "claude-sonnet-5-5")
    guardrail_model: str = os.getenv("GUARDRAIL_MODEL", "claude-haiku-5-5")

    # Retrieval.
    candidates: int = int(os.getenv("RETRIEVE_CANDIDATES", "20"))
    top_k: int = int(os.getenv("RETRIEVE_TOP_K", "6"))
    rrf_k: int = int(os.getenv("RRF_K", "60"))

    data_dir: Path = Path(os.getenv("DATA_DIR", str(DATA_DIR)))

    @property
    def chunks_dir(self) -> Path:
        return self.data_dir / "chunks"

    @property
    def chroma_dir(self) -> Path:
        return self.data_dir / "chroma"

    @property
    def bm25_path(self) -> Path:
        return self.data_dir / "bm25.pkl"

    @property
    def manifest_path(self) -> Path:
        return self.data_dir / "index_manifest.json"


settings = Settings()
