import os
import shutil
import tempfile
import unittest

from utils.detection.rag_knowledge_base import RAGKnowledgeBase


class TestRagKnowledgeBase(unittest.TestCase):
    def _make_chroma_dir(self) -> str:
        return tempfile.mkdtemp(prefix="rag_kb_", dir=os.getcwd())

    def test_search_finds_expected_entries(self):
        temp_dir = self._make_chroma_dir()
        try:
            kb = RAGKnowledgeBase(chroma_dir=temp_dir, prefer_chroma=True)
            kb_reloaded = None
            kb.load(reset=True)

            try:
                mimikatz_results = kb.search("mimikatz", top_k=5)
                self.assertTrue(
                    any(
                        result["metadata"].get("technique_id") == "T1003.001"
                        or "Credential Dumping" in result["title"]
                        or "LSASS" in result["title"]
                        for result in mimikatz_results
                    )
                )

                lazarus_results = kb.search("Lazarus", top_k=5)
                self.assertTrue(
                    any("Lazarus Group" in result["title"] for result in lazarus_results)
                )

                t1059_results = kb.search("T1059", top_k=5)
                self.assertTrue(
                    any(result["metadata"].get("technique_id") == "T1059" for result in t1059_results)
                )

                kb_reloaded = RAGKnowledgeBase(chroma_dir=temp_dir, prefer_chroma=True)
                kb_reloaded.load()
                t1059_reloaded = kb_reloaded.search("T1059", top_k=5)
                self.assertTrue(
                    any(result["metadata"].get("technique_id") == "T1059" for result in t1059_reloaded)
                )
            finally:
                kb.close()
                if kb_reloaded is not None:
                    kb_reloaded.close()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_search_combines_technique_and_apt_relevance(self):
        temp_dir = self._make_chroma_dir()
        try:
            kb = RAGKnowledgeBase(chroma_dir=temp_dir, prefer_chroma=True)
            kb.load(reset=True)
            try:
                results = kb.search("T1059 Lazarus", top_k=5)
                top_ids = {result["id"] for result in results[:3]}
                self.assertIn("attck_T1059", top_ids)
                self.assertIn("apt_G0032", top_ids)
            finally:
                kb.close()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_rebuild_when_embedding_metadata_changes(self):
        temp_dir = self._make_chroma_dir()
        try:
            kb = RAGKnowledgeBase(
                chroma_dir=temp_dir,
                prefer_chroma=True,
                embedding_dimension=64,
                embedding_version="stable-hash-v1",
            )
            reloaded = None
            kb.load(reset=True)
            try:
                self.assertEqual(kb.collection_metadata.get("embedding_dimension"), 64)

                reloaded = RAGKnowledgeBase(
                    chroma_dir=temp_dir,
                    prefer_chroma=True,
                    embedding_dimension=128,
                    embedding_version="stable-hash-v2",
                )
                reloaded.load()

                self.assertEqual(reloaded.collection_metadata.get("embedding_dimension"), 128)
                self.assertEqual(reloaded.collection_metadata.get("embedding_version"), "stable-hash-v2")
                self.assertEqual(reloaded.search_backend, "chroma")
            finally:
                kb.close()
                if reloaded is not None:
                    reloaded.close()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
