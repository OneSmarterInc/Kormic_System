# knowledge/scraper.py
# Scrapes university websites and extracts structured knowledge.
# Uses requests + BeautifulSoup for reliability without extra dependencies.
# Claude extracts the meaningful facts from raw HTML content.

import requests
from bs4 import BeautifulSoup
import anthropic
import json
import time
from typing import List, Dict
from rich.console import Console

console = Console()
client = anthropic.Anthropic()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


def fetch_page(url: str, timeout: int = 15) -> str:
    """Fetch a page and return clean text content."""
    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        # Remove navigation, scripts, styles, footers
        for tag in soup(["script", "style", "nav", "footer",
                          "header", "aside", "iframe"]):
            tag.decompose()

        # Get meaningful text
        text = soup.get_text(separator=" ", strip=True)

        # Clean up whitespace
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        clean_text = " ".join(lines)

        # Limit to 4000 chars for Claude context
        return clean_text[:4000]

    except Exception as e:
        console.print(f"[red]Failed to fetch {url}: {e}[/red]")
        return ""


def extract_facts_from_page(
    url: str,
    page_text: str,
    university_name: str
) -> List[Dict]:
    """
    Use Claude to extract structured facts from raw page content.
    Returns list of {topic, content} dicts.
    """
    if not page_text.strip():
        return []

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            messages=[{
                "role": "user",
                "content": f"""Extract key facts about {university_name}'s graduate CS program
from this webpage content. Return ONLY a JSON array of objects with
"topic" and "content" fields. No other text, no markdown, just the JSON array.

Focus on extracting:
- GPA requirements (minimum and typical admitted)
- GRE requirements (required or optional, typical scores)
- TOEFL/IELTS requirements
- Application deadlines (fall and spring)
- Tuition and fees
- Program duration
- Available funding (RA, TA, fellowships)
- Research areas and faculty
- Acceptance rates or class size
- Any unique program features or connections

If a fact is not clearly stated on this page, do not invent it.
Only extract what is explicitly present.

PAGE CONTENT:
{page_text}"""
            }]
        )

        raw = response.content[0].text.strip()

        # Clean any Markdown code fences
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        facts = json.loads(raw)
        return facts if isinstance(facts, list) else []

    except Exception as e:
        console.print(f"[yellow]Fact extraction failed for {url}: {e}[/yellow]")
        return []


def scrape_university(
    university_id: str,
    urls: List[str],
    university_name: str,
    kb
) -> int:
    """
    Scrapes all target URLs for a university and stores facts in its knowledge base.
    Returns total number of facts stored.
    """
    total_facts = 0

    for i, url in enumerate(urls):
        console.print(
            f"  [dim]Scraping ({i+1}/{len(urls)}): {url[:60]}...[/dim]"
        )

        page_text = fetch_page(url)
        if not page_text:
            continue

        facts = extract_facts_from_page(url, page_text, university_name)

        for fact in facts:
            if fact.get("topic") and fact.get("content"):
                kb.store(
                    topic=fact["topic"],
                    content=fact["content"],
                    source_type="scraped",
                    source_url=url,
                    confidence=0.9
                )
                total_facts += 1

        # Be respectful to university servers
        time.sleep(1.5)

    return total_facts
