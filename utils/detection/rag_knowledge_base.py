"""
RAG知识库构建器
优先使用 Chroma 持久化向量检索，失败时自动回退到本地 TF-IDF。
"""
import json
import logging
import math
import os
import re
import shutil
import gc
from collections import Counter
from hashlib import blake2b
from typing import Any

try:
    import chromadb
except Exception:  # pragma: no cover - 运行时可选依赖
    chromadb = None


LOGGER = logging.getLogger(__name__)


class RAGKnowledgeBase:
    """RAG检索增强知识库"""

    def __init__(
        self,
        kb_dir: str = "knowledge_base",
        chroma_dir: str = "data/chroma",
        collection_name: str = "deepsecurity_kb",
        prefer_chroma: bool = True,
        embedding_backend: str | None = None,
        embedding_version: str | None = None,
        embedding_dimension: int | None = None,
    ):
        self.kb_dir = kb_dir
        self.chroma_dir = chroma_dir
        self.collection_name = collection_name
        self.prefer_chroma = prefer_chroma
        self.embedding_backend = embedding_backend or os.getenv("RAG_EMBEDDING_BACKEND", "stable-hash")
        self.embedding_version = embedding_version or os.getenv("RAG_EMBEDDING_VERSION", "stable-hash-v1")
        self.embedding_dimension = int(embedding_dimension or os.getenv("RAG_EMBEDDING_DIMENSION", "256"))

        self.documents: list[dict[str, Any]] = []
        self.documents_by_id: dict[str, dict[str, Any]] = {}
        self.vocabulary: dict[str, int] = {}
        self.inverted_index: dict[str, list[int]] = {}
        self.doc_vectors: list[dict[str, float]] = []
        self.doc_frequencies: dict[str, int] = {}
        self._loaded = False

        self.search_backend = "tfidf"
        self.collection_metadata: dict[str, Any] = {}
        self._chroma_client = None
        self._chroma_collection = None

    def load(self, reset: bool = False):
        """加载知识库与索引"""
        if self._loaded and not reset:
            return

        self.documents = []
        self.documents_by_id = {}
        self.vocabulary = {}
        self.inverted_index = {}
        self.doc_vectors = []
        self.doc_frequencies = {}
        self.collection_metadata = {}
        self._chroma_client = None
        self._chroma_collection = None
        self.search_backend = "tfidf"

        self._load_documents()
        self._build_index()
        self._init_chroma(reset=reset)
        self._loaded = True

    def rebuild_chroma_index(self, reset: bool = False) -> dict[str, Any]:
        """重建 Chroma 索引"""
        self.load(reset=reset)
        if self._chroma_collection is None:
            raise RuntimeError("Chroma backend is unavailable")
        return self.get_runtime_info()

    def close(self):
        """释放 Chroma 客户端句柄，便于 Windows 下清理临时目录"""
        self._chroma_collection = None
        self._chroma_client = None
        gc.collect()

    def get_runtime_info(self) -> dict[str, Any]:
        return {
            "documents_count": len(self.documents),
            "vocabulary_size": len(self.vocabulary),
            "categories": sorted({d.get("category", "") for d in self.documents}),
            "search_backend": self.search_backend,
            "collection_name": self.collection_name,
            "collection_metadata": self.collection_metadata,
        }

    def _project_root(self) -> str:
        return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def _resolve_path(self, path: str) -> str:
        return path if os.path.isabs(path) else os.path.join(self._project_root(), path)

    def _safe_load_json(self, path: str) -> dict[str, Any]:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _load_documents(self):
        """加载知识库文档"""
        kb_path = self._resolve_path(self.kb_dir)

        corpus_path = os.path.join(kb_path, "rag_corpus.json")
        corpus_data = self._safe_load_json(corpus_path)
        for item in corpus_data.get("corpus", []):
            self._append_document({
                "id": item["id"],
                "title": item["title"],
                "category": item["category"],
                "content": item["content"],
                "keywords": item.get("keywords", []),
                "metadata": {
                    "doc_id": item["id"],
                    "title": item["title"],
                    "category": item["category"],
                    "source_file": "rag_corpus.json",
                    "technique_id": "",
                    "apt_group": "",
                    "cve_id": "",
                    "version": str(corpus_data.get("version", "v1")),
                    "updated_at": str(corpus_data.get("updated", "")),
                },
            })

        attck_path = os.path.join(kb_path, "attck_techniques.json")
        attck_data = self._safe_load_json(attck_path)
        for tech in attck_data.get("techniques", []):
            tid = tech["id"]
            self._append_document({
                "id": f"attck_{tid.replace('.', '_')}",
                "title": f"{tid} - {tech['name']}",
                "category": "attck_technique",
                "content": (
                    f"ATT&CK技术 {tid}: {tech['name']}。"
                    f"战术: {tech.get('tactic', '')}。"
                    f"描述: {tech.get('description', '')}。"
                    f"检测模式: {', '.join(tech.get('detection_patterns', []))}。"
                ),
                "keywords": [tid, tech.get("name", ""), tech.get("tactic", "")] + tech.get("detection_patterns", []),
                "metadata": {
                    "doc_id": f"attck_{tid.replace('.', '_')}",
                    "title": f"{tid} - {tech['name']}",
                    "category": "attck_technique",
                    "source_file": "attck_techniques.json",
                    "technique_id": tid,
                    "apt_group": "",
                    "cve_id": "",
                    "version": str(attck_data.get("version", "v1")),
                    "updated_at": str(attck_data.get("updated", "")),
                },
            })

        apt_path = os.path.join(kb_path, "apt_groups.json")
        apt_data = self._safe_load_json(apt_path)
        for group in apt_data.get("apt_groups", []):
            aliases = group.get("aliases", [])
            exploited_cves = group.get("exploited_cves", [])
            self._append_document({
                "id": f"apt_{group['id']}",
                "title": f"{group['name']} ({group.get('country', 'Unknown')})",
                "category": "apt_group",
                "content": (
                    f"APT组织 {group['name']}。"
                    f"别名: {', '.join(aliases)}。"
                    f"动机: {', '.join(group.get('motivation', []))}。"
                    f"目标行业: {', '.join(group.get('target_sectors', []))}。"
                    f"特征TTP: {', '.join(group.get('signature_ttps', []))}。"
                    f"常用恶意软件: {', '.join(group.get('signature_malware', []))}。"
                    f"利用CVE: {', '.join(exploited_cves)}。"
                    f"描述: {group.get('description', '')}"
                ),
                "keywords": (
                    [group["name"], group.get("country", "")]
                    + aliases
                    + group.get("signature_ttps", [])
                    + group.get("signature_malware", [])
                    + exploited_cves
                ),
                "metadata": {
                    "doc_id": f"apt_{group['id']}",
                    "title": f"{group['name']} ({group.get('country', 'Unknown')})",
                    "category": "apt_group",
                    "source_file": "apt_groups.json",
                    "technique_id": "",
                    "apt_group": group["name"],
                    "cve_id": ",".join(exploited_cves),
                    "version": str(apt_data.get("updated", "v1")),
                    "updated_at": str(apt_data.get("updated", "")),
                    "aliases": ",".join(aliases),
                },
            })

    def _append_document(self, doc: dict[str, Any]):
        self.documents.append(doc)
        self.documents_by_id[doc["id"]] = doc

    def _tokenize(self, text: str) -> list[str]:
        """中文+英文+技术编号混合分词，确保 T1059/CVE/mimikatz 可稳定命中"""
        lowered = text.lower()
        tokens: list[str] = []
        for match in re.findall(r"t\d{4}(?:\.\d{3})?|cve-\d{4}-\d{4,7}|apt\d+|[a-z0-9_./-]{2,}", lowered):
            cleaned = match.strip(".,:;()[]{}<>\"'")
            if cleaned:
                tokens.append(cleaned)
                if "." in cleaned:
                    tokens.extend(part for part in cleaned.split(".") if len(part) >= 2)

        chinese_segments = re.findall(r"[\u4e00-\u9fff]+", text)
        for segment in chinese_segments:
            tokens.append(segment)
            for i in range(len(segment) - 1):
                tokens.append(segment[i:i + 2])
        return tokens

    def _document_text(self, doc: dict[str, Any]) -> str:
        meta = doc.get("metadata", {})
        parts = [
            doc.get("title", ""),
            doc.get("content", ""),
            " ".join(str(k) for k in doc.get("keywords", []) if k),
            str(meta.get("technique_id", "")),
            str(meta.get("apt_group", "")),
            str(meta.get("cve_id", "")),
            str(meta.get("aliases", "")),
        ]
        return " ".join(part for part in parts if part)

    def _build_index(self):
        """构建 TF-IDF 索引，作为回退链路和本地辅助评分"""
        doc_count = len(self.documents)
        if doc_count == 0:
            return

        df: dict[str, int] = Counter()
        all_doc_tokens: list[list[str]] = []
        for doc in self.documents:
            tokens = self._tokenize(self._document_text(doc))
            all_doc_tokens.append(tokens)
            for token in set(tokens):
                df[token] = df.get(token, 0) + 1

        self.doc_frequencies = df
        self.vocabulary = {word: idx for idx, word in enumerate(sorted(df.keys()))}
        self.inverted_index = {word: [] for word in self.vocabulary}

        for doc_idx, tokens in enumerate(all_doc_tokens):
            for word in set(tokens):
                if word in self.inverted_index:
                    self.inverted_index[word].append(doc_idx)

        for tokens in all_doc_tokens:
            tf = Counter(tokens)
            vec: dict[str, float] = {}
            norm = 0.0
            for word, count in tf.items():
                if word in self.vocabulary:
                    idf = self._idf(word)
                    weight = count * idf
                    vec[word] = weight
                    norm += weight * weight
            norm = math.sqrt(norm) if norm > 0 else 1.0
            self.doc_vectors.append({word: value / norm for word, value in vec.items()})

    def _idf(self, token: str) -> float:
        doc_count = max(len(self.documents), 1)
        return math.log((doc_count + 1) / (self.doc_frequencies.get(token, 0) + 1)) + 1

    def _stable_embedding(self, text: str) -> list[float]:
        """使用稳定哈希生成跨进程一致的本地 embedding"""
        tokens = self._tokenize(text)
        if not tokens:
            return [0.0] * self.embedding_dimension

        vec = [0.0] * self.embedding_dimension
        tf = Counter(tokens)
        total = sum(tf.values()) or 1

        for token, count in tf.items():
            digest = blake2b(token.encode("utf-8"), digest_size=16, person=b"DeepSecRAG").digest()
            primary = int.from_bytes(digest[:8], "big") % self.embedding_dimension
            secondary = int.from_bytes(digest[8:], "big") % self.embedding_dimension
            sign = 1.0 if digest[0] % 2 == 0 else -1.0
            weight = (count / total) * self._idf(token)
            vec[primary] += sign * weight
            vec[secondary] += 0.5 * weight

        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def _expected_collection_metadata(self) -> dict[str, Any]:
        versions = sorted({
            str(doc.get("metadata", {}).get("version", ""))
            for doc in self.documents
            if doc.get("metadata")
        })
        updated_values = sorted({
            str(doc.get("metadata", {}).get("updated_at", ""))
            for doc in self.documents
            if doc.get("metadata", {}).get("updated_at")
        })
        kb_version = "|".join(v for v in versions if v) or "v1"
        updated_at = updated_values[-1] if updated_values else ""
        return {
            "embedding_backend": self.embedding_backend,
            "embedding_version": self.embedding_version,
            "embedding_dimension": self.embedding_dimension,
            "knowledge_version": kb_version,
            "knowledge_updated_at": updated_at,
            "documents_count": len(self.documents),
            "hnsw:space": "cosine",
        }

    def _needs_rebuild(self, metadata: dict[str, Any]) -> bool:
        expected = self._expected_collection_metadata()
        for key in ("embedding_backend", "embedding_version", "embedding_dimension", "knowledge_version"):
            if str(metadata.get(key, "")) != str(expected.get(key, "")):
                return True
        try:
            if int(metadata.get("documents_count", 0)) != int(expected["documents_count"]):
                return True
        except Exception:
            return True
        return False

    def _init_chroma(self, reset: bool = False):
        if not self.prefer_chroma or chromadb is None:
            self.search_backend = "tfidf"
            return

        chroma_path = self._resolve_path(self.chroma_dir)
        expected_meta = self._expected_collection_metadata()

        try:
            if reset and os.path.isdir(chroma_path):
                shutil.rmtree(chroma_path)
            os.makedirs(chroma_path, exist_ok=True)
            self._chroma_client = chromadb.PersistentClient(path=chroma_path)

            collection = None
            try:
                collection = self._chroma_client.get_collection(self.collection_name)
            except Exception:
                collection = None

            if collection is not None and self._needs_rebuild(collection.metadata or {}):
                self._chroma_client.delete_collection(self.collection_name)
                collection = None

            if collection is None:
                collection = self._chroma_client.create_collection(
                    name=self.collection_name,
                    metadata=expected_meta,
                )
                self._populate_chroma_collection(collection)

            self._chroma_collection = collection
            self.collection_metadata = dict(collection.metadata or expected_meta)
            self.search_backend = "chroma"
        except Exception as exc:
            LOGGER.warning("Chroma initialization failed, fallback to TF-IDF: %s", exc)
            self._chroma_client = None
            self._chroma_collection = None
            self.collection_metadata = {}
            self.search_backend = "tfidf"

    def _populate_chroma_collection(self, collection):
        ids = []
        documents = []
        metadatas = []
        embeddings = []

        for doc in self.documents:
            ids.append(doc["id"])
            documents.append(self._document_text(doc))
            embeddings.append(self._stable_embedding(self._document_text(doc)))
            meta = dict(doc.get("metadata", {}))
            for key, value in list(meta.items()):
                if value is None:
                    meta[key] = ""
                elif not isinstance(value, (str, int, float, bool)):
                    meta[key] = json.dumps(value, ensure_ascii=False)
            metadatas.append(meta)

        batch_size = 64
        for start in range(0, len(ids), batch_size):
            end = start + batch_size
            collection.add(
                ids=ids[start:end],
                documents=documents[start:end],
                metadatas=metadatas[start:end],
                embeddings=embeddings[start:end],
            )

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        """检索最相关的知识条目"""
        if not self._loaded:
            self.load()

        if not query.strip():
            return []

        if self._chroma_collection is not None:
            try:
                return self._search_chroma(query, top_k=top_k)
            except Exception as exc:
                LOGGER.warning("Chroma search failed, fallback to TF-IDF: %s", exc)

        return self._search_tfidf(query, top_k=top_k)

    def _search_tfidf(self, query: str, top_k: int = 5) -> list[dict]:
        if not self.doc_vectors:
            return []

        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        tf = Counter(query_tokens)
        query_vec: dict[str, float] = {}
        norm = 0.0
        for word, count in tf.items():
            if word in self.vocabulary:
                weight = count * self._idf(word)
                query_vec[word] = weight
                norm += weight * weight
        norm = math.sqrt(norm) if norm > 0 else 1.0
        query_vec = {word: value / norm for word, value in query_vec.items()}

        candidates = []
        for idx, doc_vec in enumerate(self.doc_vectors):
            dot = sum(doc_vec.get(word, 0.0) * query_vec.get(word, 0.0) for word in query_vec)
            doc = self.documents[idx]
            rank_score = self._rank_score(query, doc, dot)
            if rank_score > 0.04:
                candidates.append((rank_score, doc))

        candidates.sort(key=lambda item: item[0], reverse=True)
        return [self._format_result(doc, score) for score, doc in candidates[:top_k]]

    def _search_chroma(self, query: str, top_k: int = 5) -> list[dict]:
        if self._chroma_collection is None:
            return []

        query_embedding = self._stable_embedding(query)
        n_results = min(max(top_k * 4, 8), max(len(self.documents), 1))
        raw = self._chroma_collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )

        ids = raw.get("ids", [[]])[0]
        distances = raw.get("distances", [[]])[0]
        results = []
        for idx, doc_id in enumerate(ids):
            doc = self.documents_by_id.get(doc_id)
            if not doc:
                continue
            distance = float(distances[idx]) if idx < len(distances) else 1.0
            base_similarity = max(0.0, 1.0 - distance)
            rank_score = self._rank_score(query, doc, base_similarity)
            if rank_score > 0.04:
                results.append((rank_score, doc))

        results.sort(key=lambda item: item[0], reverse=True)
        return [self._format_result(doc, score) for score, doc in results[:top_k]]

    def _rank_score(self, query: str, doc: dict[str, Any], base_similarity: float) -> float:
        """在向量相似度基础上做精确标识符与关键词重排"""
        query_tokens = set(self._tokenize(query))
        doc_tokens = set(self._tokenize(self._document_text(doc)))
        overlap = len(query_tokens & doc_tokens) / max(len(query_tokens), 1)

        score = base_similarity * 0.7 + overlap * 0.3
        query_upper = query.upper()
        doc_upper = self._document_text(doc).upper()
        meta = doc.get("metadata", {})

        techniques = set(re.findall(r"T\d{4}(?:\.\d{3})?", query_upper))
        if techniques:
            technique_id = str(meta.get("technique_id", "")).upper()
            if technique_id in techniques:
                score += 0.7
            elif any(tid in doc_upper for tid in techniques):
                score += 0.3

        apt_candidates = [
            str(meta.get("apt_group", "")),
            str(meta.get("aliases", "")),
            doc.get("title", ""),
        ]
        for candidate in apt_candidates:
            for fragment in [part.strip().lower() for part in candidate.split(",") if part.strip()]:
                if fragment and fragment in query.lower():
                    score += 0.55
                    break

        for keyword in doc.get("keywords", [])[:12]:
            keyword_text = str(keyword).strip().lower()
            if keyword_text and keyword_text in query.lower():
                score += 0.08

        return score

    def _format_result(self, doc: dict[str, Any], score: float) -> dict[str, Any]:
        similarity = round(max(0.0, min(score, 1.0)), 4)
        content = doc.get("content", "")
        return {
            "id": doc["id"],
            "title": doc["title"],
            "category": doc["category"],
            "content": content[:500],
            "similarity": similarity,
            "metadata": doc.get("metadata", {}),
            "backend": self.search_backend,
        }

    def get_attck_context(self, technique_ids: list[str]) -> list[dict]:
        """获取特定 ATT&CK 技术的上下文"""
        if not self._loaded:
            self.load()

        targets = {tid.upper() for tid in technique_ids}
        results = []
        for doc in self.documents:
            if doc["category"] != "attck_technique":
                continue
            technique_id = str(doc.get("metadata", {}).get("technique_id", "")).upper()
            if technique_id in targets:
                results.append(doc)
        return results

    def get_apt_context(self, apt_name: str) -> dict | None:
        """获取特定 APT 组织的上下文"""
        if not self._loaded:
            self.load()

        apt_name_lower = apt_name.lower()
        for doc in self.documents:
            if doc["category"] != "apt_group":
                continue
            haystacks = [
                doc.get("title", "").lower(),
                str(doc.get("metadata", {}).get("apt_group", "")).lower(),
                str(doc.get("metadata", {}).get("aliases", "")).lower(),
            ]
            if any(apt_name_lower in text for text in haystacks):
                return doc
        return None


_rag_kb: RAGKnowledgeBase | None = None


def get_rag_kb() -> RAGKnowledgeBase:
    global _rag_kb
    if _rag_kb is None:
        _rag_kb = RAGKnowledgeBase()
        _rag_kb.load()
    return _rag_kb
