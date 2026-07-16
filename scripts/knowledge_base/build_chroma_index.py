"""Build or rebuild the persistent Chroma knowledge index."""
import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from utils.detection.rag_knowledge_base import RAGKnowledgeBase


def main():
    parser = argparse.ArgumentParser(description="Build DeepSecurity Chroma RAG index")
    parser.add_argument("--reset", action="store_true", help="Delete the existing Chroma index before rebuilding")
    parser.add_argument("--chroma-dir", default="data/chroma", help="Persistent Chroma directory")
    parser.add_argument("--collection-name", default="deepsecurity_kb", help="Chroma collection name")
    parser.add_argument("--embedding-backend", default="stable-hash", help="Embedding backend name stored in metadata")
    parser.add_argument("--embedding-version", default="stable-hash-v1", help="Embedding algorithm version")
    parser.add_argument("--embedding-dimension", type=int, default=256, help="Embedding dimension")
    args = parser.parse_args()

    kb = RAGKnowledgeBase(
        chroma_dir=args.chroma_dir,
        collection_name=args.collection_name,
        prefer_chroma=True,
        embedding_backend=args.embedding_backend,
        embedding_version=args.embedding_version,
        embedding_dimension=args.embedding_dimension,
    )
    info = kb.rebuild_chroma_index(reset=args.reset)
    print(json.dumps(info, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
