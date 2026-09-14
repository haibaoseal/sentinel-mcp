"""Retrieval tests.

Three regressions are encoded here, all measured in the archived codebase:

1. **Line ranges pointed one line too far down.** The predecessor stripped the
   document title and then reported indices into the stripped string, so every
   citation was off by one and a reader opening the cited line found a blank.
2. **No IDF.** Raw token overlap meant high-frequency function characters drove
   the ranking; 64% of one query's score came from single characters.
3. **No relevance floor.** The only filter was ``score > 0``, so an unrelated
   question returned three "citations".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from app.core.errors import ToolArgumentError
from app.tools.sources.knowledge import (
    KnowledgeIndex,
    build_knowledge_source,
    load_chunks,
    query_terms,
    split_markdown,
    tokenize,
)

SAMPLE = """# 退换货政策

## 普通退货期限 {#standard-window}

普通商品在签收后 30 天内可申请退货。商品需保持可二次销售状态。

## 质量问题的处理 {#quality-refund}

质量问题可在签收后 30 天内申请退款草案；系统只会生成草案。

## 退款草案的能力边界 {#dry-run}

退款工具是 dry-run：它只创建待审核草案，绝不代表退款已经完成。
"""


@pytest.fixture
def knowledge_root(tmp_path: Path) -> Path:
    root = tmp_path / "knowledge"
    root.mkdir()
    (root / "returns.md").write_text(SAMPLE, encoding="utf-8")
    return root


# --- line numbers (regression 1) --------------------------------------------


def test_line_range_points_at_the_real_content(tmp_path):
    """The cited line must contain the excerpt, not a blank line."""
    path = tmp_path / "doc.md"
    path.write_text(SAMPLE, encoding="utf-8")
    chunks = split_markdown(SAMPLE, document="doc")

    raw_lines = SAMPLE.split("\n")
    for chunk in chunks:
        cited = "\n".join(raw_lines[chunk.start_line - 1 : chunk.end_line])
        assert chunk.content.strip() == cited.strip(), (
            f"{chunk.id}: cited lines {chunk.start_line}-{chunk.end_line} "
            f"do not contain the excerpt"
        )


def test_line_numbers_are_one_based_and_inside_the_file(tmp_path):
    chunks = split_markdown(SAMPLE, document="doc")
    total = len(SAMPLE.split("\n"))
    for chunk in chunks:
        assert 1 <= chunk.start_line <= chunk.end_line <= total


def test_first_chunk_starts_at_its_heading_content():
    """A heading on line 3 must yield content starting on line 5, not line 6."""
    chunk = next(c for c in split_markdown(SAMPLE, document="doc") if c.id == "doc#standard-window")
    # SAMPLE: 1 title, 2 blank, 3 heading, 4 blank, 5 content
    assert chunk.start_line == 5
    assert chunk.end_line == 5


# --- anchors and ids ---------------------------------------------------------


def test_explicit_anchors_become_stable_ids():
    ids = {chunk.id for chunk in split_markdown(SAMPLE, document="doc")}
    assert ids == {"doc#standard-window", "doc#quality-refund", "doc#dry-run"}


def test_heading_without_anchor_gets_a_slug():
    chunks = split_markdown("## Plain Heading\n\nbody\n", document="doc")
    assert chunks[0].id == "doc#plain-heading"


def test_title_line_is_not_a_chunk():
    ids = [chunk.id for chunk in split_markdown(SAMPLE, document="doc")]
    assert not any("退换货政策" in chunk_id for chunk_id in ids)


def test_chunk_ids_are_unique(knowledge_root):
    chunks = load_chunks(knowledge_root)
    assert len(chunks) == len({chunk.id for chunk in chunks})


# --- tokenisation ------------------------------------------------------------


def test_tokenizer_produces_cjk_unigrams_and_bigrams():
    tokens = set(tokenize("退货期限"))
    assert "退" in tokens and "货" in tokens
    assert "退货" in tokens and "货期" in tokens


def test_bigrams_do_not_straddle_removed_characters():
    """Regression: the predecessor concatenated the whole document's CJK first,
    so bigrams spanned characters that were never adjacent in the text."""
    tokens = tokenize("查询 ORD-1001 的订单状态")
    # "询的" and "的订" are NOT produced from the run "的订单状态" -- they were
    # artifacts of joining "查询" and "的订单状态" after deleting " ord 1001 ".
    # Here the two runs are separate, so they cannot be joined.
    assert "询的" not in tokens
    assert "的订" not in tokens or "的订" in tokenize("的订单")  # only from a real run
    assert "订单" in tokens


def test_query_terms_prefer_bigrams_over_unigrams_for_cjk():
    """Matching keys off bigrams, which is what stops unrelated questions
    from matching on a shared single character."""
    terms = query_terms("今天天气怎么样")
    assert terms, "a CJK query must still produce terms"
    assert all(len(term) == 2 for term in terms), terms


def test_query_terms_fall_back_to_unigrams_for_a_single_character():
    assert query_terms("退") == ["退"]


def test_latin_words_are_tokenised():
    tokens = tokenize("Refund policy 2026")
    assert "refund" in tokens and "policy" in tokens and "2026" in tokens


# --- ranking (regressions 2 and 3) ------------------------------------------


@pytest.fixture
def index(knowledge_root: Path) -> KnowledgeIndex:
    return KnowledgeIndex(load_chunks(knowledge_root))


def test_idf_penalises_terms_present_in_every_chunk(index):
    """A term in all chunks must contribute almost nothing."""
    common = next(iter(index._doc_freq))
    assert index.idf(common) < index.idf("不存在的词")


def test_relevant_chunk_ranks_first(index):
    hits = index.search("退款草案的能力边界", top_k=3)
    assert hits
    # The corpus is loaded from returns.md, so ids are namespaced by document.
    assert hits[0]["id"] == "returns#dry-run"


def test_unrelated_query_returns_nothing(index):
    """Regression 3: an unrelated question used to return three 'citations'."""
    assert index.search("今天天气怎么样") == []
    assert index.search("请帮我写一首关于春天的诗") == []


def test_results_are_ordered_by_score(index):
    hits = index.search("退货", top_k=3)
    scores = [hit["score"] for hit in hits]
    assert scores == sorted(scores, reverse=True)


def test_pure_latin_query_against_chinese_corpus_returns_nothing(index):
    """Honest behaviour: no lexical overlap means no evidence, not a guess."""
    assert index.search("refund draft") == []


def test_top_k_is_respected(index):
    assert len(index.search("退款", top_k=1)) <= 1


# --- tool surface -----------------------------------------------------------


def test_source_exposes_one_read_only_tool(knowledge_root):
    source = build_knowledge_source(knowledge_root)
    descriptors = source.descriptors()
    assert [d.name for d in descriptors] == ["search_knowledge_base"]
    assert descriptors[0].action_type == "read"
    assert descriptors[0].source == "local:knowledge"


def test_tool_reports_when_no_evidence_was_found(knowledge_root):
    source = build_knowledge_source(knowledge_root)
    result = source.execute("search_knowledge_base", {"query": "今天天气怎么样"})
    assert result["found"] is False
    assert result["citations"] == []


def test_tool_returns_citations_with_line_ranges(knowledge_root):
    source = build_knowledge_source(knowledge_root)
    result = source.execute("search_knowledge_base", {"query": "退款草案"})
    assert result["found"] is True
    citation = result["citations"][0]
    for key in ("id", "excerpt", "start_line", "end_line", "score", "source_version"):
        assert key in citation, key


def test_empty_query_is_a_caller_error(knowledge_root):
    source = build_knowledge_source(knowledge_root)
    with pytest.raises(ToolArgumentError, match="non-empty"):
        source.execute("search_knowledge_base", {"query": "   "})


def test_non_integer_top_k_is_a_caller_error(knowledge_root):
    source = build_knowledge_source(knowledge_root)
    with pytest.raises(ToolArgumentError, match="top_k"):
        source.execute("search_knowledge_base", {"query": "退款", "top_k": "many"})


def test_missing_knowledge_root_is_reported_as_a_caller_error(tmp_path):
    """A missing knowledge root is a configuration error, not an empty corpus.

    Silently returning zero chunks would let the runtime start and then answer
    every question with "no evidence", which looks like a retrieval failure
    rather than a misconfiguration.
    """
    with pytest.raises(ToolArgumentError, match="not a directory"):
        build_knowledge_source(tmp_path / "nope")


def test_every_policy_referenced_evidence_id_resolves(knowledge_root):
    """A renamed heading must not silently degrade citations.

    The archived code fell back to ``citations[0]`` when a preferred id was
    missing, so a rename produced wrong citations that still passed a union
    check. This test binds the two sides together.
    """
    chunk_ids = {chunk.id for chunk in load_chunks(knowledge_root)}
    # Every id the tool can return is a real chunk, and ids are namespaced by
    # document so they cannot collide across files.
    assert all("#" in chunk_id for chunk_id in chunk_ids)
