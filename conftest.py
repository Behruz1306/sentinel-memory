# Ensures the project root is importable (so `from src.core...` works) and that
# tests run fully offline: no Moss / LLM / CloudWatch credentials are loaded, so
# the trust engine uses its deterministic heuristics and the local index.
