"""Lexical retrieval (BM25) over runbook sections, boosted by Wazuh/MITRE metadata.

No embeddings or external vector store are needed: the corpus is small and curated, the
index is built in memory at startup and the ranking is deterministic and explainable.
``Retriever`` is a protocol so a vector-based implementation can be plugged in later.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from typing import Protocol

from ..security.limits import estimate_tokens
from .runbooks import Runbook, RunbookSection

_STOPWORDS = {
    # en
    "the", "and", "for", "with", "from", "this", "that", "are", "was", "were", "been", "has", "have",
    "not", "but", "you", "your", "all", "any", "can", "into", "via", "per", "its", "use", "using",
    "on", "in", "of", "to", "a", "an", "is", "be", "by", "or", "as", "at", "it", "if",
    # es
    "el", "la", "los", "las", "un", "una", "unos", "unas", "de", "del", "al", "y", "o", "u", "en",
    "con", "por", "para", "que", "se", "su", "sus", "es", "son", "lo", "le", "les", "como", "mas",
    "sin", "sobre", "entre", "este", "esta", "estos", "estas", "ese", "esa", "si", "no", "ya",
    # placeholders inserted by the PII redactor
    "redacted", "ip", "internal", "external", "user", "email", "secret",
}  # fmt: skip
_PRIORITY_SECTIONS = ("triage", "triaje", "contencion", "containment", "respuesta", "response",
                      "erradicacion", "eradication", "escalado", "escalation")  # fmt: skip
_TECHNIQUE_RE = re.compile(r"\bt\d{4}(?:\.\d{3})?\b")
_PLACEHOLDER_RE = re.compile(r"\[[A-Z_]+_\d+\]|\[REDACTED_SECRET\]")

MIN_RELEVANCE = 2.0
# A section matching a single query term only counts when that term is curated runbook
# metadata (title, keywords, groups, tactics, MITRE): one incidental body word ("three",
# "low") is not evidence that an alert is about that runbook.
MIN_MATCHED_TERMS = 2
# Secondary runbooks are only included when reasonably close to the best match.
RELATIVE_RELEVANCE = 0.35


def _fold(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def is_response_section(title: str) -> bool:
    """True for sections that describe response steps (triage, containment, ...)."""
    folded = _fold(title)
    return any(p in folded for p in _PRIORITY_SECTIONS)


def tokenize(text: str) -> list[str]:
    folded = _fold(_PLACEHOLDER_RE.sub(" ", text))
    tokens = [t for t in re.findall(r"[a-z0-9]+", folded) if len(t) > 1 and t not in _STOPWORDS]
    return tokens + _TECHNIQUE_RE.findall(folded)


@dataclass(frozen=True)
class RetrievalQuery:
    text: str
    mitre_ids: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    rule_id: str | None = None


@dataclass(frozen=True)
class RetrievedChunk:
    runbook_id: str
    runbook_title: str
    mitre: tuple[str, ...]
    section: str
    text: str
    score: float


class Retriever(Protocol):
    def search(self, query: RetrievalQuery, *, top_k: int, max_tokens: int) -> list[RetrievedChunk]: ...

    @property
    def runbooks(self) -> dict[str, Runbook]: ...


class BM25RunbookRetriever:
    def __init__(self, runbooks: list[Runbook], *, k1: float = 1.4, b: float = 0.75) -> None:
        self._runbooks = {rb.id: rb for rb in runbooks}
        self._k1, self._b = k1, b
        self._docs: list[tuple[RunbookSection, Counter[str], int]] = []
        self._header_tokens: dict[str, frozenset[str]] = {}
        for rb in runbooks:
            header = " ".join([rb.meta.title, *rb.meta.keywords, *rb.meta.wazuh_groups, *rb.meta.tactics,
                               *rb.meta.mitre])  # fmt: skip
            self._header_tokens[rb.id] = frozenset(tokenize(header))
            for section in rb.sections:
                tokens = tokenize(f"{header} {section.title} {section.text}")
                self._docs.append((section, Counter(tokens), len(tokens)))
        self._avgdl = sum(n for *_, n in self._docs) / len(self._docs) if self._docs else 1.0
        df: Counter[str] = Counter()
        for _, tf, _ in self._docs:
            df.update(tf.keys())
        n_docs = len(self._docs)
        self._idf = {t: math.log(1 + (n_docs - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    @property
    def runbooks(self) -> dict[str, Runbook]:
        return self._runbooks

    def _bm25(self, query_tokens: list[str], tf: Counter[str], length: int) -> float:
        score = 0.0
        for token in set(query_tokens):
            freq = tf.get(token, 0)
            if not freq:
                continue
            norm = freq + self._k1 * (1 - self._b + self._b * length / self._avgdl)
            score += self._idf.get(token, 0.0) * freq * (self._k1 + 1) / norm
        return score

    def _metadata_boost(self, runbook: Runbook, query: RetrievalQuery) -> float:
        meta = runbook.meta
        boost = 0.0
        if query.rule_id and query.rule_id in meta.wazuh_rules:
            boost += 8.0
        mitre_boost = 0.0
        for technique in query.mitre_ids:
            if technique in meta.mitre:
                mitre_boost += 6.0
            elif technique.split(".")[0] in {m.split(".")[0] for m in meta.mitre}:
                mitre_boost += 4.0
        boost += min(mitre_boost, 10.0)
        groups = {g.lower() for g in query.groups} & {g.lower() for g in meta.wazuh_groups}
        boost += min(2.0 * len(groups), 6.0)
        return boost

    def rank(self, query: RetrievalQuery) -> list[tuple[Runbook, float, dict[str, float]]]:
        query_tokens = tokenize(query.text)
        query_terms = set(query_tokens)
        per_runbook: dict[str, dict[str, float]] = {}
        for section, tf, length in self._docs:
            matched = query_terms & tf.keys()
            weak = len(matched) < MIN_MATCHED_TERMS and not matched & self._header_tokens[section.runbook_id]
            score = 0.0 if weak else self._bm25(query_tokens, tf, length)
            per_runbook.setdefault(section.runbook_id, {})[section.title] = score
        ranked = []
        for runbook_id, section_scores in per_runbook.items():
            runbook = self._runbooks[runbook_id]
            score = self._metadata_boost(runbook, query) + max(section_scores.values(), default=0.0)
            ranked.append((runbook, score, section_scores))
        ranked.sort(key=lambda item: (-item[1], item[0].id))
        return ranked

    def search(self, query: RetrievalQuery, *, top_k: int, max_tokens: int) -> list[RetrievedChunk]:
        chunks: list[RetrievedChunk] = []
        used = 0
        ranked = self.rank(query)[:top_k]
        best = ranked[0][1] if ranked else 0.0
        for runbook, score, _ in ranked:
            if score < MIN_RELEVANCE or score < best * RELATIVE_RELEVANCE:
                break

            # Response sections (triage, containment, ...) first; then context sections.
            def priority(item: tuple[int, RunbookSection]) -> tuple[int, int]:
                return (0 if is_response_section(item[1].title) else 1, item[0])

            selected: list[tuple[int, RunbookSection]] = []
            for index, section in sorted(enumerate(runbook.sections), key=priority):
                cost = estimate_tokens(section.text) + 20
                if used + cost > max_tokens:
                    continue
                used += cost
                selected.append((index, section))
            # Present the selected sections in document order, as the runbook author wrote them.
            for _, section in sorted(selected, key=lambda item: item[0]):
                chunks.append(
                    RetrievedChunk(
                        runbook_id=runbook.id,
                        runbook_title=runbook.meta.title,
                        mitre=tuple(runbook.meta.mitre),
                        section=section.title,
                        text=section.text,
                        score=round(score, 3),
                    )
                )
        return chunks
