"""Local CPU embedding provider using FastEmbed (sentence-transformers/all-MiniLM-L6-v2)."""

import logging
from typing import Final

from fastembed import TextEmbedding

logger = logging.getLogger("ai_sre.rag.embeddings")

DEFAULT_MODEL_NAME: Final[str] = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIMENSION: Final[int] = 384


class LocalEmbedder:
    """Generates normalized vector embeddings locally on CPU with zero network egress."""

    def __init__(self, model_name: str = DEFAULT_MODEL_NAME) -> None:
        self.model_name = model_name
        self._model: TextEmbedding | None = None

    @property
    def model(self) -> TextEmbedding:
        """Lazy-loads the ONNX model into memory upon first invocation."""
        if self._model is None:
            logger.info("Initializing FastEmbed ONNX model: %s", self.model_name)
            self._model = TextEmbedding(model_name=self.model_name)
        return self._model

    def embed_text(self, text: str) -> list[float]:
        """Embeds a single string into a 384-dimensional float vector."""
        vectors = list(self.model.embed([text]))
        return [float(x) for x in vectors[0]]

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embeds a batch of strings efficiently in parallel on CPU."""
        if not texts:
            return []
        vectors = list(self.model.embed(texts))
        return [[float(x) for x in vec] for vec in vectors]
