"""Download and cache the MiniLM sentence-embedding model (about 90 MB) used by step 06."""
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
print("MiniLM ready, embedding shape:", model.encode(["ok"]).shape)
