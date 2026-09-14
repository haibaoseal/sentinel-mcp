"""Knowledge base chunking and BM25 retrieval.

What was wrong before
---------------------
The predecessor scored chunks by raw token overlap divided by ``sqrt(len)``.
Measured consequences: no IDF, so high-frequency function characters drove the
ranking (64% of one query's score came from single characters); bigrams were
built across spans that had been stripped out, producing artifacts like ``询的``;
and the only filter was ``score > 0``, so "今天天气怎么样？" returned three
"citations". The harness appeared to work only because the caller looked up its
wanted citation by policy pointer rather than by search result.

What this does instead
----------------------
- Chunks are addressed by ``file#anchor``, where the anchor comes from an
  explicit ``{#id}`` heading, so a citation id is stable across edits.
- Tokens are Latin words plus CJK unigrams *and* bigrams, generated from the
  CJK run only, so no bigram spans a removed character.
- BM25 with real IDF: a term appearing in every chunk contributes almost
  nothing, which is what stops function characters from deciding the ranking.
- A relative relevance floor: results below a fraction of the top score are
  dropped, so an unrelated query returns nothing instead of three weak matches.
- Line ranges are counted against the **original file**, not the post-title-split
  body. The predecessor stripped the title and then reported indices into the
  stripped string, so every citation pointed one line too far down.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.errors import ToolArgumentError
from app.tools.sources.local import LocalTool, LocalToolSource

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*(?:\{#([A-Za-z0-9._-]+)\})?\s*$")
CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
TOKEN_RE = re.compile(r"[a-z0-9]+")

BM25_K1 = 1.2
BM25_B = 0.75
# Fraction of the best score a chunk must reach to be returned.
RELATIVE_FLOOR = 0.35
# A chunk matching only one query term is not evidence, it is a coincidence.
MIN_MATCHED_TERMS = 2


@dataclass
class Chunk:
    id: str
    document: str
    title: str
    heading: str
    content: str
    start_line: int
    end_line: int
    source_version: str = "1"
    tokens: list[str] = field(default_factory=list)


def tokenize(text: str) -> list[str]:
    """Latin words plus CJK unigrams and bigrams.

    Bigrams are built from contiguous CJK runs only, so no bigram straddles a
    removed span. Note this still yields bigrams across grammatical particles
    (``案的``), which is unavoidable without a segmenter -- BM25's IDF is what
    makes those harmless, because a particle appears in most chunks and
    therefore scores near zero.
    """
    lowered = text.lower()
    tokens = TOKEN_RE.findall(lowered)

    for run in re.findall(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+", lowered):
        tokens.extend(run)
        tokens.extend(run[i : i + 2] for i in range(len(run) - 1))

    return tokens


def query_terms(query: str) -> list[str]:
    """Terms used for *matching*, which is not the same as indexing terms.

    CJK queries are matched primarily on bigrams. Single characters are only
    included when the query produces no bigram and no Latin word at all -- that
    is, for a one-character query like ``退``.

    This distinction matters: with bare unigrams, an unrelated question such as
    "今天天气怎么样" shares the characters 天 and 气 with the corpus and returns
    hits. Bigram matching requires two adjacent characters to agree, which an
    unrelated question does not achieve. It is the difference between "no
    evidence" and "three weak citations".
    """
    lowered = query.lower()
    latin = TOKEN_RE.findall(lowered)
    runs = re.findall(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+", lowered)

    bigrams: list[str] = []
    unigrams: list[str] = []
    for run in runs:
        unigrams.extend(run)
        bigrams.extend(run[i : i + 2] for i in range(len(run) - 1))

    terms = latin + bigrams
    if not terms:
        terms = unigrams
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(terms))


def split_markdown(text: str, *, document: str, source_version: str = "1") -> list[Chunk]:
    """Split on headings, keeping line numbers valid for the original file."""
    lines = text.split("\n")
    title = ""
    chunks: list[Chunk] = []
    current: dict[str, Any] | None = None

    def flush() -> None:
        if current is None:
            return
        body_lines = current["lines"]
        # Trim blank leading/trailing lines but remember their offsets so the
        # reported range describes the content that is actually present.
        first = next((i for i, line in enumerate(body_lines) if line.strip()), None)
        if first is None:
            return
        last = max(i for i, line in enumerate(body_lines) if line.strip())
        content = "\n".join(body_lines[first : last + 1])
        anchor = current["anchor"]
        chunks.append(
            Chunk(
                id=f"{document}#{anchor}",
                document=document,
                title=title,
                heading=current["heading"],
                content=content,
                # 1-based line numbers into the original file, so a reader can
                # open the file and land on the cited line.
                start_line=current["start"] + first + 1,
                end_line=current["start"] + last + 1,
                source_version=source_version,
            )
        )

    for index, line in enumerate(lines):
        match = HEADING_RE.match(line)
        if not match:
            if current is not None:
                current["lines"].append(line)
            continue

        level, heading_text, anchor = match.group(1), match.group(2), match.group(3)
        if len(level) == 1 and not title:
            title = heading_text
            continue
        flush()
        current = {
            "anchor": anchor or _slug(heading_text),
            "heading": heading_text,
            "start": index + 1,
            "lines": [],
        }
    flush()
    return chunks


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "section"


def load_chunks(root: Path | str, *, source_version: str = "1") -> list[Chunk]:
    base = Path(root)
    if not base.is_dir():
        raise ToolArgumentError(f"knowledge root is not a directory: {base}")
    chunks: list[Chunk] = []
    for path in sorted(base.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        document = path.relative_to(base).with_suffix("").as_posix()
        chunks.extend(split_markdown(text, document=document, source_version=source_version))
    for chunk in chunks:
        chunk.tokens = tokenize(f"{chunk.heading} {chunk.content}")
    return chunks


class KnowledgeIndex:
    """A BM25 index over chunks, built once and queried many times."""

    def __init__(self, chunks: list[Chunk]) -> None:
        self.chunks = chunks
        self._doc_freq: Counter[str] = Counter()
        for chunk in chunks:
            self._doc_freq.update(set(chunk.tokens))
        self._avg_len = sum(len(chunk.tokens) for chunk in chunks) / len(chunks) if chunks else 0.0
        self._n = len(chunks)

    def idf(self, term: str) -> float:
        # Standard BM25 IDF with the +0.5 smoothing. A term present in every
        # chunk yields a value near zero, which is precisely the property the
        # predecessor lacked.
        df = self._doc_freq.get(term, 0)
        return math.log(1 + (self._n - df + 0.5) / (df + 0.5))

    def search(
        self, query: str, *, top_k: int = 3, floor: float = RELATIVE_FLOOR
    ) -> list[dict[str, Any]]:
        if not self.chunks or self._n == 0:
            return []
        terms = query_terms(query)
        if not terms:
            return []

        scored: list[tuple[float, Chunk, int]] = []
        for chunk in self.chunks:
            counts = Counter(chunk.tokens)
            length = len(chunk.tokens) or 1
            score = 0.0
            matched = 0
            for term in terms:
                tf = counts.get(term, 0)
                if not tf:
                    continue
                matched += 1
                denominator = tf + BM25_K1 * (1 - BM25_B + BM25_B * length / (self._avg_len or 1))
                score += self.idf(term) * (tf * (BM25_K1 + 1)) / denominator
            if score > 0:
                scored.append((score, chunk, matched))

        if not scored:
            return []
        scored.sort(key=lambda item: (-item[0], item[1].id))
        best = scored[0][0]
        kept = [
            (score, chunk, matched)
            for score, chunk, matched in scored
            if score >= best * floor and matched >= MIN_MATCHED_TERMS
        ]
        if not kept:
            return []

        return [
            {
                "id": chunk.id,
                "document": chunk.document,
                "title": chunk.title,
                "heading": chunk.heading,
                "excerpt": chunk.content,
                "score": round(score, 6),
                "matched_terms": matched,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
                "source_version": chunk.source_version,
            }
            for score, chunk, matched in kept[:top_k]
        ]


def build_knowledge_source(root: Path | str, *, source_version: str = "1") -> LocalToolSource:
    index = KnowledgeIndex(load_chunks(root, source_version=source_version))

    def search_knowledge_base(arguments: dict[str, Any]) -> dict[str, Any]:
        query = str(arguments.get("query", "")).strip()
        if not query:
            raise ToolArgumentError("query must be a non-empty string")
        raw_top_k = arguments.get("top_k", 3)
        try:
            top_k = int(raw_top_k)
        except (TypeError, ValueError) as exc:
            raise ToolArgumentError("top_k must be an integer") from exc
        top_k = max(1, min(top_k, 10))

        citations = index.search(query, top_k=top_k)
        return {
            "query": query,
            "citations": citations,
            # An explicit empty result is information. The UI and the guardrail
            # both need to distinguish "no evidence found" from "evidence found
            # but not shown", so say it rather than returning three weak hits.
            "found": bool(citations),
            "total_chunks": len(index.chunks),
        }

    return LocalToolSource(
        [
            LocalTool(
                name="search_knowledge_base",
                run=search_knowledge_base,
                description=(
                    "Search the versioned policy knowledge base. Returns chunks with "
                    "stable citation ids, exact excerpts and source line ranges."
                ),
                action_type="read",
                resource_type="knowledge",
                risk_level="low",
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "top_k": {"type": "integer", "default": 3},
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            )
        ],
        name="local:knowledge",
    )
