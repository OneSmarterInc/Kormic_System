# agents/university_agent.py
# The university agent for the Korgut Commons.
# Each instance represents one university's graduate program.
# Scrapes its own website on startup. Learns from every conversation.

import json
# import anthropic
from personas.university_personas import UNIVERSITY_PERSONAS
from knowledge.university_kb import UniversityKnowledgeBase
from knowledge.scraper import scrape_university
from rich.console import Console
from kormic.runtime import runtime
from kormic.logger import kormic_logger
from kormic.models.verify import ProofToken
from kormic.pedigree.builder import append_history_event
from agents.openrouter_client import call_openrouter

console = Console()
# client = anthropic.Anthropic()


class UniversityAgent:
    """
    A university agent in the Korgut Commons.

    On creation it:
    1. Loads its persona and constitution
    2. Seeds its knowledge base with verified facts
    3. Optionally scrapes its website for additional knowledge

    On each question it:
    1. Searches its knowledge base for relevant context
    2. Builds a system prompt combining constitution + knowledge
    3. Answers through Claude
    4. Stores the learned answer back in the knowledge base
    """

    def __init__(self, university_id: str, auto_scrape: bool = True):
        if university_id not in UNIVERSITY_PERSONAS:
            raise ValueError(f"Unknown university: {university_id}")

        self.university_id = university_id
        self.persona = UNIVERSITY_PERSONAS[university_id]
        self.kb = UniversityKnowledgeBase(university_id)

        # KORMIC INTEGRATION: Agent Registration (Birth)
        kormic_logger.info("SPAWN", f"TEMP_{university_id}", "Spawning University Agent")
        
        self.agent_code = runtime.agent_manager.register_new_agent(
            agent_type="UNI",
            entity_ref=university_id.replace("_", ""),
            instance_num="0001",
            real_world_id=self.persona["name"],
            guardrails={"can_access_kb": True, "can_scrape": auto_scrape}
        )
        
        kormic_logger.info("REGISTRATION", self.agent_code, f"Identity {self.agent_code} assigned.")
        kormic_logger.info("BIRTH", self.agent_code, "Sealed Birth Record signed and hashed.")

        # Load seed facts — verified information built into the persona
        seed_facts = self.persona.get("key_facts_seed", [])
        for fact in seed_facts:
            self.kb.store(
                topic=fact["topic"],
                content=fact["content"],
                source_type="seed",
                confidence=1.0
            )

        console.print(
            f"\n[bold blue]{self.persona['agent_name']}[/bold blue] "
            f"({self.persona['name']}) is initialising..."
        )
        console.print(
            f"  Loaded {len(seed_facts)} seed facts into knowledge base."
        )

        # Scrape the university website
        if auto_scrape:
            urls = self.persona.get("scrape_urls", [])
            if urls:
                console.print(
                    f"  Scraping {len(urls)} pages from "
                    f"{self.persona['name']} website..."
                )
                scraped_count = scrape_university(
                    university_id=university_id,
                    urls=urls,
                    university_name=self.persona["name"],
                    kb=self.kb
                )
                console.print(
                    f"  [green]Scraped {scraped_count} additional facts.[/green]"
                )
            else:
                console.print("  No scrape URLs configured.")

        stats = self.kb.stats()
        console.print(
            f"  [green]{self.persona['agent_name']} ready. "
            f"Knowledge base: {stats['total_entries']} entries.[/green]\n"
        )

    def _build_system_prompt(self) -> str:
        """Combines the agent's constitution with its current knowledge base."""
        knowledge_context = self.kb.get_full_context()
        return self.persona["constitution"] + "\n\n" + knowledge_context

    def answer(
        self,
        question: str,
        student_context: dict = None,
        token: ProofToken = None
    ) -> dict:
        """
        Answer a question from a student agent or directly.
        Every answer is stored back in the knowledge base.

        Args:
            question: The question being asked
            student_context: Optional student profile for personalised answers

        Returns:
            dict with university name, agent name, answer, and confidence
        """
        self.kb.total_questions_answered += 1

        # KORMIC INTEGRATION: Agent-to-Agent Verification
        if token:
            kormic_logger.info("VERIFY", self.agent_code, f"Verifying ProofToken from {token.agent_code} (FAST O(1) Check)")
            verification_result = runtime.verifier.verify_fast(token)
            
            if verification_result.status != "PASS":
                kormic_logger.warning("VERIFY", self.agent_code, f"Rejected {token.agent_code}: {verification_result.reason}")
                return {
                    "university": self.persona["name"],
                    "agent_name": self.persona["agent_name"],
                    "answer": f"ACCESS DENIED: Cryptographic verification failed for your agent. ({verification_result.reason})",
                    "kb_size": self.kb.stats()["total_entries"]
                }
            kormic_logger.info("VERIFY", self.agent_code, f"Verification PASS for {token.agent_code}")

        # Build context string if student profile provided
        student_ctx = ""
        if student_context:
            student_ctx = (
                f"\n\nSTUDENT CONTEXT (for personalising your answer):\n"
                f"Name: {student_context.get('name', 'the student')}\n"
                f"GPA: {student_context.get('gpa')} / "
                f"{student_context.get('gpa_scale', '4.0')}\n"
                f"From: {student_context.get('institution', 'unknown institution')}\n"
                f"Major: {student_context.get('major', 'unknown')}\n"
                f"GRE Quant: {student_context.get('gre_quant', 'not taken')}\n"
                f"Budget: USD {student_context.get('budget', 'unspecified')}/year"
            )

        # response = client.messages.create(
        #     model="claude-sonnet-4-6",
        #     max_tokens=1000,
        #     system=self._build_system_prompt(),
        #     messages=[{
        #         "role": "user",
        #         "content": question + student_ctx
        #     }]
        # )
        
        response = call_openrouter(
            system=self._build_system_prompt(),
            messages=[{"role": "user", "content": question + student_ctx}],
            max_tokens=1000
        )

        answer_text = response.content[0].text

        # Store what was learned from this interaction
        self.kb.store(
            topic=f"Q: {question[:120]}",
            content=answer_text[:500],
            source_type="conversation",
            confidence=0.8
        )
        
        # KORMIC INTEGRATION: Tamper-Evident History
        kormic_logger.info("INTERACT", self.agent_code, "Processed question, updating history.")
        pedigree_data = runtime.record_store.get(self.agent_code)
        if pedigree_data:
            from kormic.models.pedigree import Pedigree
            pedigree = Pedigree.from_dict(pedigree_data)
            updated_pedigree = append_history_event(pedigree, f"Answered query: {question[:50]}")
            runtime.record_store.put(self.agent_code, updated_pedigree.to_dict())
            kormic_logger.info("HISTORY", self.agent_code, f"History linked updated. New Head: {updated_pedigree.running_head[:10]}...")

        return {
            "university": self.persona["name"],
            "agent_name": self.persona["agent_name"],
            "answer": answer_text,
            "kb_size": self.kb.stats()["total_entries"]
        }

    def status(self) -> str:
        """Quick status summary for the Commons dashboard."""
        stats = self.kb.stats()
        return (
            f"{self.persona['agent_name']} | {self.persona['name']} | "
            f"{stats['total_entries']} facts | "
            f"{stats['questions_answered']} questions answered"
        )

    def assess_fit(self, student_package: dict) -> dict:
        """
        Assess a student's fit for this program based on their complete profile.
        Returns a structured JSON-like dict that can be stored in StudentProfile.
        """
        self.kb.total_questions_answered += 1

        prompt = f"""
You are {self.persona['agent_name']}, the {self.persona['name']} agent.

Assess this student's fit for your program honestly.

Return ONLY valid JSON. No markdown.

{{
  "match_tier": "strong|target|reach|unlikely",
  "match_score": 0,
  "fit_summary": "",
  "strengths_for_program": [],
  "gaps_for_program": [],
  "recommendation": "strong_apply|apply|consider|unlikely_but_try|do_not_apply",
  "realistic": true,
  "specific_advice": ""
}}

PROGRAM KNOWLEDGE BASE:
{self.kb.get_full_context()}

STUDENT PROFILE:
{json.dumps(student_package, indent=2)}
"""

        # response = client.messages.create(
        #     model="claude-sonnet-4-6",
        #     max_tokens=1000,
        #     system=self._build_system_prompt(),
        #     messages=[{"role": "user", "content": prompt}],
        # )
        
        response = call_openrouter(
            system=self._build_system_prompt(),
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000
        )

        raw = response.content[0].text.strip()

        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:-1])

        assessment = json.loads(raw.strip())
        assessment["university"] = self.persona["name"]
        assessment["agent"] = self.persona["agent_name"]

        self.kb.store(
            topic=f"Fit assessment for {student_package.get('name', 'student')}",
            content=assessment.get("fit_summary", ""),
            source_type="conversation",
            confidence=0.9,
        )

        return assessment

