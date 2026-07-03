# agents/student_agent.py
# Aria — The Student Advocate
# She lives in the Korgut Commons and has access to all university agents.
# She remembers every conversation with a student.
# She never gives up on finding a path.

import re
from typing import Optional

import anthropic
from personas.aria_constitution import build_aria_system_prompt
from agents import commons
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from profile_intelligence.profile_intelligence import ProfileIntelligenceService

console = Console()
client = anthropic.Anthropic()


class StudentAgent:
    """
    Aria — the student advocate in the Korgut Commons.

    She maintains full conversation history so she remembers
    everything the student has told her. She can query university
    agents directly when she needs verified information.

    She can also analyze a student's public GitHub profile to infer
    interests, technical strengths, and suitable course tracks.

    She has a personality. She is not a chatbot.
    """

    def __init__(self, student_profile: dict):
        self.student_profile = student_profile
        self.student_name = student_profile.get("name", "there")
        self.conversation_history = []
        self.system_prompt = build_aria_system_prompt(student_profile)
        self.messages_exchanged = 0

        # Profile Intelligence service for GitHub analysis
        self.profile_intelligence = ProfileIntelligenceService()

    def _contains_university_query(self, message: str) -> bool:
        """
        Detect if Aria's response indicates she wants to query
        a university agent in the Commons.
        """
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
        return any(t in message.lower() for t in triggers)

    def _extract_github_input(self, message: str) -> Optional[str]:
        """
        Detect GitHub profile URL or username from a student's message.

        Supports:
        - My GitHub is https://github.com/username
        - github.com/username
        - My github id is username
        - GitHub: username
        """
        message = message.strip()

        # Case 1: full GitHub profile URL
        github_url_pattern = (
            r"(?:https?://)?(?:www\.)?github\.com/"
            r"([A-Za-z0-9-]{1,39})(?:[/?#\s]|$)"
        )
        url_match = re.search(github_url_pattern, message, re.IGNORECASE)

        if url_match:
            username = url_match.group(1)
            return f"https://github.com/{username}"

        # Case 2: sentence contains GitHub and then username
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
        """
        If the student shared a GitHub profile, analyze it and let Aria
        explain course-fit recommendations naturally.

        Returns:
            Aria response string if GitHub was detected.
            None if no GitHub input was detected.
        """
        github_input = self._extract_github_input(user_message)

        if not github_input:
            return None

        try:
            analysis = self.profile_intelligence.analyze_github(
                github_input,
                student_name=self.student_name
            )

            # Save useful intelligence into current student profile memory
            self.student_profile["github_profile"] = github_input
            self.student_profile["github_profile_intelligence"] = {
                "generated_at": analysis.get("generated_at"),
                "human_summary": analysis.get("human_summary"),
                "primary_direction": analysis
                .get("course_recommendation", {})
                .get("primary_direction"),
                "recommendations": analysis
                .get("course_recommendation", {})
                .get("recommendations", []),
            }

            github_analysis = analysis.get("github_analysis", {})
            course_recommendation = analysis.get("course_recommendation", {})

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

            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1000,
                system=self.system_prompt,
                messages=[{
                    "role": "user",
                    "content": github_prompt
                }]
            )

            return response.content[0].text

        except Exception as e:
            console.print(f"[yellow]GitHub analysis failed: {e}[/yellow]")

            return (
                "I tried checking that GitHub profile, but I couldn’t analyze it properly. "
                "Please make sure the GitHub username or link is correct, public, and reachable. "
                "If most of your work is in private repositories, you can also paste a short summary "
                "of your projects and I’ll still help you choose the right course direction."
            )

    def _enrich_with_university_knowledge(
        self,
        aria_response: str,
        user_message: str
    ) -> str:
        """
        If Aria indicated she's checking with a university agent,
        actually do that and enrich her response with verified data.
        """
        # For this experiment, check Wright State specifically
        if "wright state" in user_message.lower() or \
           "wright state" in aria_response.lower():
            result = commons.query(
                "wright_state_cs",
                user_message,
                self.student_profile
            )

            if result:
                # Let Aria incorporate the university agent's answer
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

                enriched = client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=1000,
                    system=self.system_prompt,
                    messages=[{
                        "role": "user",
                        "content": enrichment_prompt
                    }]
                )

                return enriched.content[0].text

        return aria_response

    def chat(self, user_message: str) -> str:
        """
        Send a message to Aria and get her response.
        She maintains full conversation history.
        She queries university agents when needed.
        She analyzes GitHub profiles when the student shares one.
        """
        self.messages_exchanged += 1

        # Add user message to conversation history
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        # First: check whether the student shared a GitHub profile
        github_response = self._handle_github_profile_analysis(user_message)

        if github_response:
            self.conversation_history.append({
                "role": "assistant",
                "content": github_response
            })

            return github_response

        # Normal Aria response
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            system=self.system_prompt,
            messages=self.conversation_history
        )

        aria_response = response.content[0].text

        # If Aria indicated she's checking with a university agent, do it
        if self._contains_university_query(aria_response):
            aria_response = self._enrich_with_university_knowledge(
                aria_response,
                user_message
            )

        # Add Aria's response to history
        self.conversation_history.append({
            "role": "assistant",
            "content": aria_response
        })

        return aria_response

    def run_interactive(self):
        """
        Run an interactive conversation in the terminal.
        Type 'quit', 'exit', or 'bye' to end.
        Type 'status' to see the Commons status.
        Type 'history' to see conversation summary.
        """
        console.print(Panel(
            f"[bold]Aria[/bold] is ready.\n"
            f"Advising: [cyan]{self.student_name}[/cyan]\n"
            f"University agents available in the Korgut Commons:\n"
            f"  • Raider (Wright State University CS)\n\n"
            f"[dim]Commands: 'quit' to exit, 'status' to see Commons status[/dim]",
            title="[bold blue]Korgut Commons[/bold blue]",
            border_style="blue"
        ))

        while True:
            try:
                user_input = input(
                    f"\n[{self.student_name}]: "
                ).strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Session ended.[/dim]")
                break

            if not user_input:
                continue

            if user_input.lower() in ["quit", "exit", "bye"]:
                console.print(
                    "\n[bold blue]Aria:[/bold blue] Good luck with your "
                    "applications. I'll be here when you need me.\n"
                )
                break

            if user_input.lower() == "status":
                console.print(commons.status())
                continue

            if user_input.lower() == "history":
                console.print(
                    f"\n[dim]{self.messages_exchanged} messages exchanged "
                    f"in this session.[/dim]\n"
                )
                continue

            # Get Aria's response
            response = self.chat(user_input)

            console.print(
                f"\n[bold green]Aria:[/bold green]"
            )
            console.print(Markdown(response))