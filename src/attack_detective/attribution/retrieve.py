"""Rank ATT&CK techniques for an explanation text with TF-IDF or MiniLM embeddings."""
import pickle
from pathlib import Path
from typing import Callable, List, Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from attack_detective.contracts.schemas import Technique
from .keywords import KEYWORDS
from .stix_loader import AttackTechnique

MINILM = "sentence-transformers/all-MiniLM-L6-v2"


def technique_document(t: AttackTechnique, enriched: bool) -> str:
    doc = f"{t.name}. {t.description}"
    if enriched and t.technique_id in KEYWORDS:
        doc = f"{t.name}. {KEYWORDS[t.technique_id]}. {KEYWORDS[t.technique_id]}. {t.description}"
    return doc


def _l2(a: np.ndarray) -> np.ndarray:
    return a / (np.linalg.norm(a, axis=1, keepdims=True) + 1e-12)


class Retriever:
    """method: 'tfidf' or 'minilm'. enriched: add KEYWORDS to technique documents."""

    def __init__(self, techniques: List[AttackTechnique], method: str = "tfidf",
                 enriched: bool = True, encoder: Optional[Callable] = None):
        self.techniques, self.method, self.enriched = techniques, method, enriched
        docs = [technique_document(t, enriched) for t in techniques]
        if method == "tfidf":
            self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2),
                                       sublinear_tf=True, min_df=1)
            self.doc_matrix = self.vec.fit_transform(docs)     # sparse, rows already L2-normalised
        elif method == "minilm":
            self.encoder = encoder or _minilm_encoder()
            self.doc_matrix = _l2(self.encoder(docs))
        else:
            raise ValueError(method)
        self._cache = {}

    def _embed(self, texts: List[str]) -> np.ndarray:
        if self.method == "tfidf":
            return self.vec.transform(texts)
        return _l2(self.encoder(texts))

    def attribute_many(self, texts: List[str], k: int = 3) -> List[List[Technique]]:
        """Top-k techniques for each text. Identical texts are embedded once (cache)."""
        new = [t for t in dict.fromkeys(texts) if t not in self._cache]
        if new:
            sims = self._embed(new) @ self.doc_matrix.T
            sims = sims.toarray() if hasattr(sims, "toarray") else sims
            for text, row in zip(new, sims):
                top = np.argsort(-row)[:k]
                self._cache[text] = [Technique(self.techniques[j].technique_id,
                                               self.techniques[j].name, round(float(row[j]), 4))
                                     for j in top]
        return [self._cache[t][:k] for t in texts]

    def attribute(self, text: str, k: int = 3) -> List[Technique]:
        return self.attribute_many([text], k)[0]

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        enc, self.encoder = getattr(self, "encoder", None), None     # model is not pickled
        with open(path, "wb") as f:
            pickle.dump(self, f)
        self.encoder = enc

    @staticmethod
    def load(path, encoder: Optional[Callable] = None) -> "Retriever":
        with open(path, "rb") as f:
            r = pickle.load(f)
        if r.method == "minilm":
            r.encoder = encoder or _minilm_encoder()
        return r


def _minilm_encoder():
    from sentence_transformers import SentenceTransformer      # imported only when needed
    model = SentenceTransformer(MINILM, device="cpu")
    return lambda texts: model.encode(list(texts), batch_size=64, convert_to_numpy=True,
                                      show_progress_bar=False).astype(np.float32)
