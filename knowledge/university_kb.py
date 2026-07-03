# knowledge/university_kb.py
# Knowledge base for university agents.
# Runs in memory by default. Optionally persists to PostgreSQL.
# Every fact has a source type: 'seed', 'scraped', or 'conversation'

from datetime import datetime
from typing import List, Dict, Optional


class KnowledgeEntry:
    def __init__(
        self,
        topic: str,
        content: str,
        source_type: str,
        source_url: Optional[str] = None,
        confidence: float = 1.0
    ):
        self.topic = topic
        self.content = content
        self.source_type = source_type
        self.source_url = source_url
        self.confidence = confidence
        self.learned_at = datetime.now()
        self.times_used = 0

    def __repr__(self):
        return f"[{self.source_type.upper()}] {self.topic}: {self.content[:80]}..."


class UniversityKnowledgeBase:
    """
    Persistent knowledge base for one university agent.
    Stores everything the agent knows — from website scraping,
    seed facts, and facts learned through conversations.

    Grows smarter with every interaction.
    Every question asked of the agent adds to this knowledge base.
    """

    def __init__(self, university_id: str):
        self.university_id = university_id
        self.entries: List[KnowledgeEntry] = []
        self.total_questions_answered = 0

    def store(
        self,
        topic: str,
        content: str,
        source_type: str,
        source_url: Optional[str] = None,
        confidence: float = 1.0
    ):
        """Add a new knowledge entry."""
        entry = KnowledgeEntry(
            topic=topic,
            content=content,
            source_type=source_type,
            source_url=source_url,
            confidence=confidence
        )
        self.entries.append(entry)

    def store_bulk(self, facts: List[Dict]):
        """Store multiple facts at once — used for seed facts and scraping."""
        for fact in facts:
            self.store(
                topic=fact.get("topic", ""),
                content=fact.get("content", ""),
                source_type=fact.get("source_type", "seed"),
                source_url=fact.get("source_url"),
                confidence=fact.get("confidence", 1.0)
            )

    def search(self, query: str, limit: int = 8) -> List[KnowledgeEntry]:
        """
        Simple keyword search across all knowledge entries.
        Returns most relevant entries sorted by confidence.
        Upgrade to vector search when the knowledge base gets large.
        """
        query_lower = query.lower()
        matches = []

        for entry in self.entries:
            score = 0
            if query_lower in entry.topic.lower():
                score += 2
            if query_lower in entry.content.lower():
                score += 1
            # Boost by confidence and usage
            score *= entry.confidence
            score += entry.times_used * 0.1

            if score > 0:
                matches.append((score, entry))

        matches.sort(key=lambda x: x[0], reverse=True)
        results = [entry for _, entry in matches[:limit]]

        # Track usage
        for entry in results:
            entry.times_used += 1

        return results

    def get_full_context(self, max_entries: int = 60) -> str:
        """
        Returns the full knowledge base as a formatted string
        for injection into the agent's system prompt.
        Prioritises high-confidence, frequently-used entries.
        """
        sorted_entries = sorted(
            self.entries,
            key=lambda e: (e.confidence * 2 + e.times_used * 0.5),
            reverse=True
        )[:max_entries]

        if not sorted_entries:
            return "Knowledge base is empty — agent is learning."

        lines = ["KNOWLEDGE BASE:"]
        for entry in sorted_entries:
            source_label = {
                "seed": "VERIFIED",
                "scraped": "FROM WEBSITE",
                "conversation": "LEARNED"
            }.get(entry.source_type, entry.source_type.upper())

            lines.append(f"[{source_label}] {entry.topic}: {entry.content}")

        lines.append(
            f"\n(Knowledge base contains {len(self.entries)} entries. "
            f"{self.total_questions_answered} questions answered so far.)"
        )
        return "\n".join(lines)

    def stats(self) -> Dict:
        source_counts = {}
        for entry in self.entries:
            source_counts[entry.source_type] = (
                source_counts.get(entry.source_type, 0) + 1
            )
        return {
            "total_entries": len(self.entries),
            "by_source": source_counts,
            "questions_answered": self.total_questions_answered
        }
