# agents/student_agent.py
# Aria — The Student Advocate
# Integrated version:
# - Persistent student memory
# - Auto profile save
# - Conversation logging
# - Conversation summary
# - Admission probability estimate
# - University comparison
# - Export chat report
# - Response modes
# - GitHub Profile Intelligence
# - Raider trust-context support

from __future__ import annotations

from datetime import datetime
import json
import os
import re
from typing import Any, Dict, Optional

# import anthropic
from agents.openrouter_client import call_openrouter
from agents import commons
from personas.aria_constitution import build_aria_system_prompt
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from kormic.runtime import runtime
from kormic.logger import kormic_logger
from kormic.models.verify import ProofToken
from kormic.models.pedigree import Pedigree
from kormic.pedigree.builder import append_history_event

try:
    from profile_intelligence.profile_intelligence import ProfileIntelligenceService
except Exception:
    ProfileIntelligenceService = None


console = Console()
# client = anthropic.Anthropic()


class StudentAgent:
    """
    Aria — the student advocate in the Korgut Commons.

    Responsibilities:
    - Maintain chat history during the session.
    - Persist important student memory across sessions.
    - Save the student profile automatically.
    - Analyze public GitHub profiles when shared.
    - Query university agents through Commons when verified data is needed.
    - Export a clean student advising report.
    """

    PROFILE_DIR = "profiles"
    MEMORY_DIR = "memory"
    LOG_DIR = "logs"
    REPORT_DIR = "reports"

    VALID_RESPONSE_MODES = {"short", "detailed", "summary"}

    def __init__(self, student_profile: dict, profile=None):
        """Create Aria.

        Args:
            student_profile: Normal dict used by Aria's prompt.
            profile: Optional StudentProfile object that persists insights,
                university assessments, and summary to disk.
        """
        self.profile = profile

        if self.profile is not None and hasattr(self.profile, "data"):
            # Use the persistent StudentProfile data as the single source of truth.
            self.student_profile = self.profile.data or (student_profile or {})
        else:
            self.student_profile = student_profile or {}

        self.student_name = self.student_profile.get("name", "there")
        self.student_key = self._safe_name(self.student_name)

        self.conversation_history = []
        self.messages_exchanged = 0
        self.response_mode = self.student_profile.get("response_mode", "detailed")

        if self.response_mode not in self.VALID_RESPONSE_MODES:
            self.response_mode = "detailed"
            
        # KORMIC INTEGRATION: Agent Registration (Birth)
        kormic_logger.info("SPAWN", f"TEMP_{self.student_key}", "Spawning Student Agent")
        
        self.agent_code = runtime.agent_manager.register_new_agent(
            agent_type="STU",
            entity_ref=self.student_key,
            instance_num="0001",
            real_world_id=self.student_name,
            guardrails={"max_budget_limit": True, "allow_github_scrape": True}
        )
        
        kormic_logger.info("REGISTRATION", self.agent_code, f"Identity {self.agent_code} assigned.")
        kormic_logger.info("BIRTH", self.agent_code, "Sealed Birth Record signed and hashed.")

        self.memory_file = os.path.join(
            self.MEMORY_DIR,
            f"{self.student_key}_memory.json"
        )

        self.memory: Dict[str, Any] = {}
        self.load_memory()

        self.system_prompt = build_aria_system_prompt(self.student_profile)

        self.profile_intelligence = (
            ProfileIntelligenceService()
            if ProfileIntelligenceService is not None
            else None
        )

        self.save_student_profile()

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def _safe_name(self, value: str) -> str:
        value = str(value or "student").strip().lower()
        value = re.sub(r"[^a-z0-9]+", "_", value)
        return value.strip("_") or "student"

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        try:
            if value in [None, ""]:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            if value in [None, ""]:
                return default
            return int(float(value))
        except (TypeError, ValueError):
            return default

    def _ensure_dirs(self):
        for folder in [
            self.PROFILE_DIR,
            self.MEMORY_DIR,
            self.LOG_DIR,
            self.REPORT_DIR,
        ]:
            os.makedirs(folder, exist_ok=True)

    # ------------------------------------------------------------------
    # Student profile persistence
    # ------------------------------------------------------------------
    def save_student_profile(self) -> str:
        self._ensure_dirs()

        filename = os.path.join(
            self.PROFILE_DIR,
            f"{self.student_key}_profile.json"
        )

        self.student_profile["response_mode"] = self.response_mode

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.student_profile, f, indent=4, ensure_ascii=False)

        return filename

    # ------------------------------------------------------------------
    # Persistent memory
    # ------------------------------------------------------------------
    def load_memory(self):
        self._ensure_dirs()

        default_memory = {
            "student": self.student_name,
            "important_points": [],
            "universities_discussed": [],
            "github_profiles_analyzed": [],
            "last_updated": None,
        }

        if not os.path.exists(self.memory_file):
            self.memory = default_memory
            self.save_memory()
            return

        try:
            with open(self.memory_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)

            self.memory = {**default_memory, **loaded}
            self.memory.setdefault("important_points", [])
            self.memory.setdefault("universities_discussed", [])
            self.memory.setdefault("github_profiles_analyzed", [])
            self.memory.setdefault("last_updated", None)

        except Exception as exc:
            console.print(
                f"[yellow]Could not load memory file. Starting fresh: {exc}[/yellow]"
            )
            self.memory = default_memory
            self.save_memory()

    def save_memory(self):
        self._ensure_dirs()
        self.memory["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(self.memory_file, "w", encoding="utf-8") as f:
            json.dump(self.memory, f, indent=4, ensure_ascii=False)

    def update_memory(self, user_message: str, aria_response: str):
        text = user_message.lower()

        important_keywords = [
            "gpa", "budget", "cmu", "mit", "wright state", "funding",
            "sop", "gre", "toefl", "ielts", "research", "work experience",
            "github", "linkedin", "ai", "ml", "data science", "cybersecurity",
            "software engineering", "deadline", "scholarship"
        ]

        if any(keyword in text for keyword in important_keywords):
            point = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "user": user_message,
                "aria": aria_response[:500],
            }

            self.memory["important_points"].append(point)
            self.memory["important_points"] = self.memory["important_points"][-50:]

        university_aliases = {
            "cmu": "CMU",
            "carnegie mellon": "CMU",
            "mit": "MIT",
            "wright state": "Wright State",
            "msu": "Michigan State",
            "michigan state": "Michigan State",
            "uw": "University of Washington",
            "university of washington": "University of Washington",
            "rutgers": "Rutgers",
            "sdsu": "San Diego State",
        }

        for alias, canonical_name in university_aliases.items():
            if alias in text and canonical_name not in self.memory["universities_discussed"]:
                self.memory["universities_discussed"].append(canonical_name)

        self.save_memory()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    def log_conversation(self, user_message: str, aria_response: str):
        self._ensure_dirs()

        log_path = os.path.join(self.LOG_DIR, "aria_conversation_log.txt")

        with open(log_path, "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Student: {self.student_name}\n")
            f.write(f"User: {user_message}\n\n")
            f.write(f"Aria: {aria_response}\n")

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------
    def _memory_context(self) -> str:
        recent_points = self.memory.get("important_points", [])[-5:]
        universities = self.memory.get("universities_discussed", [])
        github_info = self.student_profile.get("github_profile_intelligence")

        lines = ["\n\nPERSISTENT STUDENT MEMORY:"]

        if universities:
            lines.append("Universities discussed: " + ", ".join(universities))

        if recent_points:
            lines.append("Recent important points:")
            for point in recent_points:
                lines.append(f"- Student said: {point.get('user')}")
        else:
            lines.append("No important memory points stored yet.")

        if github_info:
            lines.append("\nGitHub Profile Intelligence:")
            lines.append(
                f"- Primary direction: {github_info.get('primary_direction', 'Unknown')}"
            )
            lines.append(
                f"- Summary: {github_info.get('human_summary', 'Not available')}"
            )

        return "\n".join(lines)

    def _response_mode_instruction(self) -> str:
        if self.response_mode == "short":
            return """

RESPONSE STYLE FOR THIS TURN:
Give a very short answer.
Maximum 1-2 sentences.
Answer directly without long explanations.
"""

        if self.response_mode == "summary":
            return """

RESPONSE STYLE FOR THIS TURN:
Give a normal explanation.

At the end add:

Summary:
• Point 1
• Point 2
• Point 3
"""

        return """

RESPONSE STYLE FOR THIS TURN:
Give a helpful detailed response with reasoning, but avoid unnecessary over-explaining.
Use short paragraphs.
"""

    def _runtime_system_prompt(self) -> str:
        return (
            self.system_prompt
            + self._memory_context()
            + self._response_mode_instruction()
        )

    def _saved_assessment_response(self, user_message: str) -> Optional[str]:
        """Answer simple questions from stored fit assessments without another LLM call."""
        lower_msg = user_message.lower()
        assessments = self.student_profile.get("assessments", {}) or {}
        wright = assessments.get("wright_state_cs")

        if not wright:
            return None

        if "match score" in lower_msg:
            return f"Your Wright State match score is {wright.get('match_score', 'not available')}."

        if "match tier" in lower_msg:
            return f"Your Wright State match tier is {wright.get('match_tier', 'not available')}."

        if "what does wright state think" in lower_msg or "wright state fit" in lower_msg:
            return wright.get("fit_summary", "No Wright State assessment is available yet.")

        return None

    # ------------------------------------------------------------------
    # Commands / utility outputs
    # ------------------------------------------------------------------
    def conversation_summary(self) -> str:
        universities = ", ".join(
            self.memory.get("universities_discussed", [])
        ) or "None yet"

        github_info = self.student_profile.get("github_profile_intelligence", {})
        github_direction = github_info.get("primary_direction", "Not analyzed yet")

        return f"""
### Conversation Summary

**Student:** {self.student_name}

**GPA:** {self.student_profile.get("gpa", "Not provided")}

**GRE Quant:** {self.student_profile.get("gre_quant", "Not provided")}

**TOEFL:** {self.student_profile.get("toefl", "Not provided")}

**Budget:** ${self.student_profile.get("budget", "Not provided")}

**Universities Discussed:** {universities}

**GitHub Direction:** {github_direction}

**Messages Exchanged:** {self.messages_exchanged}
"""

    def admission_probability(self) -> str:
        gpa = self._safe_float(self.student_profile.get("gpa"), 0.0)
        gre = self._safe_int(self.student_profile.get("gre_quant"), 0)
        budget = self._safe_int(self.student_profile.get("budget"), 0)

        if gpa >= 3.7 and gre >= 167:
            cmu = "Reach"
        elif gpa >= 3.3 and gre >= 160:
            cmu = "High Reach"
        else:
            cmu = "Very High Reach"

        if gpa >= 3.2 and gre >= 158:
            wright = "Realistic"
        elif gpa >= 3.0:
            wright = "Moderate"
        else:
            wright = "Reach"

        if gpa >= 3.35 and gre >= 160:
            msu = "Moderate"
        else:
            msu = "Reach"

        if gpa >= 3.7 and gre >= 165:
            uw = "Reach"
        else:
            uw = "High Reach"

        cmu_note = (
            "Cost is a major issue for CMU based on the current budget."
            if budget and budget < 40000
            else "Budget should still be reviewed carefully for CMU."
        )

        github_info = self.student_profile.get("github_profile_intelligence", {})
        github_note = ""
        if github_info:
            github_note = (
                f"\n**Profile signal:** GitHub analysis currently points toward "
                f"**{github_info.get('primary_direction', 'Unknown')}**, which should be used "
                f"to choose better-fit tracks and electives."
            )

        return f"""
### Admission Fit Estimate

| University | Fit / Chance Category |
|---|---|
| CMU | {cmu} |
| Wright State | {wright} |
| Michigan State | {msu} |
| University of Washington | {uw} |

**Note:** {cmu_note}
{github_note}

This is a rough advising estimate, not an official admission prediction. Exact admission chances require verified historical admission data and current program-specific criteria.
"""

    def university_comparison(self) -> str:
        github_info = self.student_profile.get("github_profile_intelligence", {})
        github_direction = github_info.get("primary_direction")

        github_row = ""
        if github_direction:
            github_row = (
                f"| Student GitHub Fit | Depends on faculty/lab match | "
                f"Good if applied {github_direction} work connects to AFRL/research areas |\n"
            )

        return f"""
### CMU vs Wright State

| Factor | CMU | Wright State |
|---|---|---|
| Prestige / Ranking | Very high | Moderate |
| Cost | Very expensive | More affordable |
| Admission Difficulty | Very hard | More realistic |
| Funding | Competitive and limited for many MS students | Assistantships may be possible but must be verified |
| Best For | Top-tier research/prestige seekers | Value, applied research, AFRL connection |
{github_row}

**Simple advice:** CMU is stronger in prestige, but Wright State may fit better if budget, realistic admission chances, and applied research access matter more.
"""

    def export_report(self) -> str:
        self._ensure_dirs()

        filename = os.path.join(
            self.REPORT_DIR,
            f"{self.student_key}_chat_report.txt"
        )

        with open(filename, "w", encoding="utf-8") as f:
            f.write("KORGUT ARIA CHAT REPORT\n")
            f.write("=" * 60 + "\n")
            f.write(f"Student: {self.student_name}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("STUDENT PROFILE\n")
            f.write("-" * 60 + "\n")
            f.write(json.dumps(self.student_profile, indent=4, ensure_ascii=False))

            f.write("\n\nPERSISTENT MEMORY\n")
            f.write("-" * 60 + "\n")
            f.write(json.dumps(self.memory, indent=4, ensure_ascii=False))

            f.write("\n\nCONVERSATION SUMMARY\n")
            f.write("-" * 60 + "\n")
            f.write(self.conversation_summary())

            f.write("\n\nADMISSION FIT ESTIMATE\n")
            f.write("-" * 60 + "\n")
            f.write(self.admission_probability())

            f.write("\n\nUNIVERSITY COMPARISON\n")
            f.write("-" * 60 + "\n")
            f.write(self.university_comparison())

            f.write("\n\nCONVERSATION HISTORY\n")
            f.write("-" * 60 + "\n")

            for msg in self.conversation_history:
                f.write(f"\n{msg['role'].upper()}:\n{msg['content']}\n")

        return f"Report exported successfully: {filename}"

    def generate_student_report(self) -> str:
        return self.export_report()

    # ------------------------------------------------------------------
    # GitHub Profile Intelligence
    # ------------------------------------------------------------------
    def _extract_github_input(self, message: str) -> Optional[str]:
        message = message.strip()

        github_url_pattern = (
            r"(?:https?://)?(?:www\.)?github\.com/"
            r"([A-Za-z0-9-]{1,39})(?:[/?#\s]|$)"
        )
        url_match = re.search(github_url_pattern, message, re.IGNORECASE)

        if url_match:
            username = url_match.group(1)
            return f"https://github.com/{username}"

        if "github" not in message.lower():
            return None

        username_patterns = [
            r"github\s*(?:id|username|profile)?\s*(?:is|:|-)?\s*([A-Za-z0-9-]{1,39})",
            r"my\s+github\s*(?:id|username|profile)?\s*(?:is|:|-)?\s*([A-Za-z0-9-]{1,39})",
        ]

        invalid_words = {
            "is", "id", "username", "profile", "link", "url",
            "account", "github", "my", "this", "here"
        }

        for pattern in username_patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                username = match.group(1).strip().strip("/")

                if username.lower() not in invalid_words:
                    return username

        return None

    def _handle_github_profile_analysis(self, user_message: str) -> Optional[str]:
        github_input = self._extract_github_input(user_message)

        if not github_input:
            return None

        if self.profile_intelligence is None:
            return (
                "I can analyze GitHub profiles, but the profile_intelligence module is not available "
                "in this environment yet. Please confirm the profile_intelligence folder exists and "
                "contains github_analyzer.py, course_mapper.py, and profile_intelligence.py."
            )

        try:
            analysis = self.profile_intelligence.analyze_github(
                github_input,
                student_name=self.student_name
            )

            course_recommendation = analysis.get("course_recommendation", {})
            github_analysis = analysis.get("github_analysis", {})

            self.student_profile["github_profile"] = github_input
            self.student_profile["github_profile_intelligence"] = {
                "generated_at": analysis.get("generated_at"),
                "human_summary": analysis.get("human_summary"),
                "primary_direction": course_recommendation.get("primary_direction"),
                "recommendations": course_recommendation.get("recommendations", []),
            }

            if github_input not in self.memory["github_profiles_analyzed"]:
                self.memory["github_profiles_analyzed"].append(github_input)

            self.save_student_profile()
            self.save_memory()

            top_languages = github_analysis.get("top_languages", [])[:5]
            top_keywords = github_analysis.get("top_keywords", [])[:15]
            inferred_interests = (
                github_analysis
                .get("inferred_interests", {})
                .get("ranked_interests", [])[:5]
            )

            github_prompt = f"""
You are Aria.

The student shared a GitHub profile. The system analyzed the student's public GitHub work.

STUDENT NAME:
{self.student_name}

GITHUB INPUT:
{github_input}

GITHUB HUMAN SUMMARY:
{analysis.get("human_summary")}

TOP VISIBLE LANGUAGES:
{top_languages}

TOP TECHNICAL KEYWORDS:
{top_keywords}

INFERRED INTEREST AREAS:
{inferred_interests}

COURSE RECOMMENDATION:
Primary direction: {course_recommendation.get("primary_direction")}

Recommended course areas:
{course_recommendation.get("recommendations")}

Now respond to the student naturally.

Important rules:
- Sound like a real graduate admissions advisor, not a bot.
- Do not show raw scores unless the student asks for detailed analysis.
- Explain what their GitHub suggests about their interests and work style.
- Recommend suitable course tracks based on the GitHub evidence.
- Mention that GitHub only shows public work, so private projects, internships, resume, and academic work may change the recommendation.
- Avoid saying the student "must" choose a course. Use advisor-style language like "I would consider", "this points toward", or "your profile seems aligned with".
- Keep the answer warm, honest, and practical.
"""

            # response = client.messages.create(
            #     model="claude-sonnet-4-6",
            #     max_tokens=1000,
            #     system=self._runtime_system_prompt(),
            #     messages=[{
            #         "role": "user",
            #         "content": github_prompt
            #     }]
            # )
            
            response = call_openrouter(
                system=self._runtime_system_prompt(),
                messages=[{"role": "user", "content": github_prompt}],
                max_tokens=1000
            )

            return response.content[0].text

        except Exception as exc:
            console.print(f"[yellow]GitHub analysis failed: {exc}[/yellow]")

            return (
                "I tried checking that GitHub profile, but I couldn’t analyze it properly. "
                "Please make sure the GitHub username or link is correct, public, and reachable. "
                "If most of your work is in private repositories, you can also paste a short summary "
                "of your projects and I’ll still help you choose the right course direction."
            )

    # ------------------------------------------------------------------
    # University agent enrichment
    # ------------------------------------------------------------------
    def _contains_university_query(self, message: str) -> bool:
        triggers = [
            "let me check with",
            "let me ask the",
            "checking with",
            "i'll check",
            "i will check",
            "consulting the",
            "wright state agent",
            "university agent",
            "commons agent"
        ]
        return any(trigger in message.lower() for trigger in triggers)

    def _enrich_with_university_knowledge(
        self,
        aria_response: str,
        user_message: str
    ) -> str:
        if "wright state" not in user_message.lower() and "wright state" not in aria_response.lower():
            return aria_response

        # KORMIC INTEGRATION: Agent-to-Agent Verification
        # Generating a ProofToken to pass to the university agent
        kormic_logger.info("COMMUNICATE", self.agent_code, "Generating ProofToken to send to University Agent.")
        pedigree_data = runtime.record_store.get(self.agent_code)
        pedigree = Pedigree.from_dict(pedigree_data)
        
        token = ProofToken(
            agent_code=self.agent_code,
            birth_record=pedigree.birth_record.to_dict(),
            authority_reference="KormicRoot",
            current_head=pedigree.running_head,
            history_length=len(pedigree.history),
            freshness_timestamp=pedigree.history[-1].timestamp if pedigree.history else pedigree.birth_record.created_at
        )

        result = commons.query(
            "wright_state_cs",
            user_message,
            self.student_profile,
            token=token
        )

        if not result:
            return aria_response

        trust = result.get("trust", {})
        confidence = trust.get("confidence", {})
        confidence_level = confidence.get("level", "Unknown")
        needs_verification = confidence.get("needs_verification", True)
        confidence_reason = confidence.get("reason", "")

        enrichment_prompt = f"""You are Aria. You just got this answer
from the Wright State (Raider) agent in the Korgut Commons.

RAIDER'S ANSWER:
{result['answer']}

TRUST CONTEXT FOR YOU ONLY:
Confidence level: {confidence_level}
Needs verification: {needs_verification}
Reason: {confidence_reason}

Your previous response to the student was:
{aria_response}

Now give your FINAL response that incorporates Raider's information.

Important style rules:
- Keep your warm, honest Aria voice.
- Be natural. Do not sound like a database.
- Do not expose raw labels like confidence_score, source_type, source_url, or internal metadata.
- If confidence is high, you may sound reasonably confident.
- If confidence is medium, use careful wording like "this looks like", "I would treat this as", or "I am reasonably confident".
- If confidence is low, clearly say you do not have enough verified information.
- If verification is needed, say it naturally, like: "I’d still verify the latest official page before you submit."
- Tell the student you checked with the Wright State agent only if it feels natural."""

        # enriched = client.messages.create(
        #     model="claude-sonnet-4-6",
        #     max_tokens=1000,
        #     system=self._runtime_system_prompt(),
        #     messages=[{
        #         "role": "user",
        #         "content": enrichment_prompt
        #     }]
        # )
        
        enriched = call_openrouter(
            system=self._runtime_system_prompt(),
            messages=[{"role": "user", "content": enrichment_prompt}],
            max_tokens=1000
        )

        return enriched.content[0].text

    # ------------------------------------------------------------------
    # Main chat function
    # ------------------------------------------------------------------
    def _finalize_response(self, user_message: str, aria_response: str) -> str:
        # KORMIC INTEGRATION: The Watchdog (Behavioral Monitoring)
        # We intercept the LLM output and grade it. (Mocking metrics for demo)
        metrics = {
            "accuracy": 0.9 if "sorry" not in aria_response.lower() else 0.4,
            "overconfidence": 0.1,
            "guardrail_hit_rate": 0.05,
            "latency_drift": 1.0
        }
        
        behavior_report = runtime.behavior_monitor.evaluate(self.agent_code, metrics)
        
        if behavior_report.status == "HALT":
            kormic_logger.error("MONITOR", self.agent_code, f"Agent HALTED due to behavior: {behavior_report.reason}")
            aria_response = "[SYSTEM HALT] This agent has been isolated due to behavioral degradation."
        elif behavior_report.status == "FLAG":
            kormic_logger.warning("MONITOR", self.agent_code, f"Agent FLAGGED: {behavior_report.reason}")
        else:
            kormic_logger.info("MONITOR", self.agent_code, "Behavior OK.")
            
        self.conversation_history.append({
            "role": "assistant",
            "content": aria_response
        })

        self.log_conversation(user_message, aria_response)
        self.update_memory(user_message, aria_response)
        self.save_student_profile()

        if self.profile is not None and hasattr(self.profile, "data"):
            self.profile.data.update(self.student_profile)
            if hasattr(self.profile, "add_conversation_insight"):
                self.profile.add_conversation_insight(user_message)
            else:
                self.profile.save()

        # KORMIC INTEGRATION: Tamper-Evident Chain (History)
        kormic_logger.info("INTERACT", self.agent_code, "Updating tamper-evident history chain.")
        pedigree_data = runtime.record_store.get(self.agent_code)
        if pedigree_data:
            pedigree = Pedigree.from_dict(pedigree_data)
            updated_pedigree = append_history_event(pedigree, f"Chat Interaction: {user_message[:30]}")
            runtime.record_store.put(self.agent_code, updated_pedigree.to_dict())
            kormic_logger.info("HISTORY", self.agent_code, f"Chain updated. New Head: {updated_pedigree.running_head[:10]}...")

        return aria_response

    def chat(self, user_message: str) -> str:
        self.messages_exchanged += 1

        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        lower_msg = user_message.lower()

        saved_assessment = self._saved_assessment_response(user_message)
        if saved_assessment:
            return self._finalize_response(user_message, saved_assessment)

        if "probability" in lower_msg or "chance" in lower_msg:
            return self._finalize_response(
                user_message,
                self.admission_probability()
            )

        if "compare" in lower_msg or "cmu vs wright" in lower_msg:
            return self._finalize_response(
                user_message,
                self.university_comparison()
            )

        github_response = self._handle_github_profile_analysis(user_message)
        if github_response:
            return self._finalize_response(user_message, github_response)

        # response = client.messages.create(
        #     model="claude-sonnet-4-6",
        #     max_tokens=1000,
        #     system=self._runtime_system_prompt(),
        #     messages=self.conversation_history
        # )
        
        response = call_openrouter(
            system=self._runtime_system_prompt(),
            messages=self.conversation_history,
            max_tokens=1000
        )

        aria_response = response.content[0].text

        if self._contains_university_query(aria_response):
            aria_response = self._enrich_with_university_knowledge(
                aria_response,
                user_message
            )

        return self._finalize_response(user_message, aria_response)

    # ------------------------------------------------------------------
    # Terminal loop
    # ------------------------------------------------------------------
    def run_interactive(self):
        console.print(Panel(
            f"[bold]Aria[/bold] is ready.\n"
            f"Advising: [cyan]{self.student_name}[/cyan]\n"
            f"University agents available in the Korgut Commons:\n"
            f"  • Raider (Wright State University CS)\n\n"
            f"[dim]Commands:\n"
            f"  • quit / exit / bye - exit and auto-export report\n"
            f"  • status - see Commons status\n"
            f"  • history - show message count\n"
            f"  • summary - show conversation summary\n"
            f"  • export - export full chat report\n"
            f"  • mode short - short answers\n"
            f"  • mode detailed - detailed answers\n"
            f"  • mode summary - summary-style answers[/dim]",
            title="[bold blue]Korgut Commons[/bold blue]",
            border_style="blue"
        ))

        console.print(
            f"[yellow]Current Response Mode:[/yellow] {self.response_mode}"
        )

        while True:
            try:
                user_input = input(f"\n[{self.student_name}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Session ended.[/dim]")
                break

            if not user_input:
                continue

            command = user_input.lower()

            if command in ["quit", "exit", "bye"]:
                export_message = self.export_report()
                console.print(f"\n[green]{export_message}[/green]")
                console.print(
                    "\n[bold blue]Aria:[/bold blue] Good luck with your "
                    "applications. I'll be here when you need me.\n"
                )
                break

            if command == "status":
                console.print(commons.status())
                continue

            if command == "history":
                console.print(
                    f"\n[dim]{self.messages_exchanged} messages exchanged.[/dim]\n"
                )
                continue

            if command == "summary":
                console.print(Markdown(self.conversation_summary()))
                continue

            if command == "export":
                console.print(f"[green]{self.export_report()}[/green]")
                continue

            if command == "mode short":
                self.response_mode = "short"
                self.save_student_profile()
                console.print("[green]Response mode set to SHORT[/green]")
                continue

            if command == "mode detailed":
                self.response_mode = "detailed"
                self.save_student_profile()
                console.print("[green]Response mode set to DETAILED[/green]")
                continue

            if command == "mode summary":
                self.response_mode = "summary"
                self.save_student_profile()
                console.print("[green]Response mode set to SUMMARY[/green]")
                continue

            response = self.chat(user_input)

            console.print("\n[bold green]Aria:[/bold green]")
            console.print(Markdown(response))
