# knowledge/trust_layer.py
"""
Evidence-Aware Recommendation / Advisor Trust Layer.

Purpose:
- Check how reliable a recommendation/fact is.
- Detect high-risk university facts like deadlines, tuition, GRE, funding.
- Give Raider internal guidance.
- Keep Aria's final answer human, not robotic.
"""

from typing import Any, Dict, List


HIGH_RISK_FACT_KEYWORDS = [
    "deadline",
    "application deadline",
    "tuition",
    "fees",
    "cost",
    "gre",
    "gpa requirement",
    "minimum gpa",
    "toefl",
    "ielts",
    "acceptance rate",
    "admit rate",
    "salary",
    "placement rate",
    "funding",
    "assistantship",
    "scholarship",
    "application fee",
]


def _get(entry: Any, key: str, default=None):
    """
    Supports both:
    1. KnowledgeEntry object
    2. dict-based persistent memory entry
    """
    if isinstance(entry, dict):
        return entry.get(key, default)

    return getattr(entry, key, default)


def is_high_risk_question(question: str) -> bool:
    """
    High-risk questions are questions where guessing is dangerous.
    Example: deadlines, tuition, funding, GRE/GPA rules, acceptance rate.
    """
    q = question.lower()
    return any(keyword in q for keyword in HIGH_RISK_FACT_KEYWORDS)


def source_weight(source_type: str) -> float:
    """
    Assign reliability weight by source type.
    """
    source_type = (source_type or "").lower()

    if source_type == "scraped":
        return 1.0

    if source_type == "seed":
        return 0.85

    if source_type == "human":
        return 0.9

    if source_type == "conversation":
        return 0.55

    return 0.4


def calculate_confidence(entries: List[Any], question: str) -> Dict:
    """
    Calculates a simple confidence label using:
    - number of relevant entries
    - stored confidence
    - source type reliability
    - whether the question is high-risk
    """
    high_risk = is_high_risk_question(question)

    if not entries:
        return {
            "level": "Low",
            "score": 0.0,
            "needs_verification": True,
            "reason": "No directly relevant verified evidence was found."
        }

    weighted_scores = []

    for entry in entries:
        stored_confidence = float(_get(entry, "confidence", 0.5) or 0.5)
        source_type = _get(entry, "source_type", "unknown")
        weighted_scores.append(stored_confidence * source_weight(source_type))

    score = sum(weighted_scores) / len(weighted_scores)

    # For high-risk facts, be stricter.
    if high_risk:
        if score >= 0.9:
            return {
                "level": "High",
                "score": round(score, 2),
                "needs_verification": True,
                "reason": (
                    "The answer has strong support, but this is a changing university fact "
                    "and should still be verified on the official page."
                )
            }

        if score >= 0.65:
            return {
                "level": "Medium",
                "score": round(score, 2),
                "needs_verification": True,
                "reason": (
                    "Some relevant evidence exists, but this is a changing university fact "
                    "such as deadline, tuition, funding, GRE/GPA rule, or admission statistic."
                )
            }

        return {
            "level": "Low",
            "score": round(score, 2),
            "needs_verification": True,
            "reason": "Evidence is weak for a high-risk factual question."
        }

    # Normal non-high-risk questions.
    if score >= 0.85:
        return {
            "level": "High",
            "score": round(score, 2),
            "needs_verification": False,
            "reason": "The answer is supported by strong relevant knowledge entries."
        }

    if score >= 0.65:
        return {
            "level": "Medium",
            "score": round(score, 2),
            "needs_verification": False,
            "reason": "The answer has reasonable support, but should be phrased carefully."
        }

    return {
        "level": "Low",
        "score": round(score, 2),
        "needs_verification": True,
        "reason": "The available evidence is weak or mostly conversation-learned."
    }


def build_evidence_context(entries: List[Any]) -> str:
    """
    Converts entries into internal prompt context for Raider.
    This is not shown directly to the student.
    """
    if not entries:
        return "No directly relevant verified evidence was found in the knowledge base."

    lines = []

    for i, entry in enumerate(entries, start=1):
        topic = _get(entry, "topic", "Untitled")
        content = _get(entry, "content", "")
        source_type = _get(entry, "source_type", "unknown")
        source_url = _get(entry, "source_url", None)
        confidence = _get(entry, "confidence", 0.5)

        lines.append(
            f"EVIDENCE {i}\n"
            f"Topic: {topic}\n"
            f"Content: {content}\n"
            f"Source type: {source_type}\n"
            f"Source URL: {source_url or 'Not available'}\n"
            f"Stored confidence: {confidence}\n"
        )

    return "\n".join(lines)


def build_trust_summary(entries: List[Any], question: str) -> Dict:
    """
    Structured trust metadata.
    Use this in reports/debug logs, not raw in normal chat.
    """
    confidence = calculate_confidence(entries, question)

    sources = []
    for entry in entries:
        sources.append({
            "topic": _get(entry, "topic", "Untitled"),
            "source_type": _get(entry, "source_type", "unknown"),
            "source_url": _get(entry, "source_url", None),
            "confidence": _get(entry, "confidence", 0.5),
        })

    return {
        "confidence": confidence,
        "sources": sources,
        "high_risk_question": is_high_risk_question(question),
    }


def human_trust_instruction(trust_summary: Dict) -> str:
    """
    Converts trust metadata into natural style guidance.
    This prevents robotic output.
    """
    confidence = trust_summary.get("confidence", {})
    level = confidence.get("level", "Low")
    needs_verification = confidence.get("needs_verification", True)

    if level == "High" and not needs_verification:
        return (
            "You can sound reasonably confident, but not arrogant. "
            "Do not expose raw confidence scores or metadata."
        )

    if level == "High" and needs_verification:
        return (
            "You can say the evidence looks strong, but because this information can change, "
            "recommend verifying the latest official page before the student acts on it."
        )

    if level == "Medium":
        return (
            "Use careful human wording such as 'this looks likely', 'I would treat this as', "
            "'I am reasonably confident', or 'I would still verify this'. "
            "Do not expose raw confidence scores or metadata."
        )

    return (
        "Be cautious. Say the current knowledge base does not have enough verified information. "
        "Do not invent facts. Suggest checking the official university page."
    )