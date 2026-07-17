"""
models.py
=========
Loads the SecureBERT bi-encoder and cross-encoder exactly once.

This is the ONLY file that initialises the ML models. Import from here
in any file that needs embedder or reranker. Because Python caches module
imports, the models load once per process regardless of how many files
import from here.

Nothing else lives here. No ingestion, no DB calls, no side effects.
"""

import os

from sentence_transformers import SentenceTransformer, CrossEncoder
from config import EMBED_MODEL, RERANK_MODEL


def _resolve_device() -> str:
    """
    Pick the compute device. FURIX_DEVICE env wins ('cuda' | 'cpu' | 'mps');
    otherwise auto-detect CUDA and fall back to CPU. This lets the pipeline boot
    on a CPU-only Ubuntu box (slower embeddings, still functional) instead of
    crashing on a hard-coded 'cuda'.
    """
    forced = os.environ.get("FURIX_DEVICE", "").strip().lower()
    if forced:
        return forced
    try:
        import torch  # torch is a transitive dep of sentence_transformers
        if torch.cuda.is_available():
            return "cuda"
    except Exception:
        pass
    return "cpu"


DEVICE = _resolve_device()


class SecureBERTEmbedder:
    def __init__(self, model_name: str = EMBED_MODEL):
        print(f"  Loading bi-encoder: {model_name} (device={DEVICE})")
        self.model = SentenceTransformer(model_name, device=DEVICE)
        print("  Bi-encoder loaded ✅")

    def embed(self, texts: list, batch_size: int = 32) -> list:
        vecs = self.model.encode(
            texts, batch_size=batch_size, normalize_embeddings=True
        )
        return vecs.tolist()


print("Loading bi-encoder (SecureBERT2.0-biencoder)...")
embedder = SecureBERTEmbedder(EMBED_MODEL)

print(f"\nLoading cross-encoder (SecureBERT2.0-cross_encoder) (device={DEVICE})...")
reranker = CrossEncoder(
    RERANK_MODEL, device=DEVICE,
    trust_remote_code=True,
    max_length=512,
)
print("Cross-encoder ready ✅")
