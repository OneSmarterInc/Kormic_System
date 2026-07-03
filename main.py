#!/usr/bin/env python3
"""
main.py — Korgut Commons Entry Point

Integrated local version:
- Default Priya profile
- Optional resume parser: --resume resumes/my_resume.pdf
- Optional GitHub skills assessment: --github github_username_or_url
- Persistent StudentProfile storage
- Wright State fit assessment storage
- Aria + Raider interactive mode

Usage:
    python main.py
    python main.py --no-scrape
    python main.py --raider-only
    python main.py --resume resumes/my_resume.pdf --no-scrape
    python main.py --github https://github.com/someusername --no-scrape
    python main.py --resume resumes/my_resume.pdf --github someusername --no-scrape
"""

from __future__ import annotations

import argparse
import copy
import os
import sys
from typing import Any, Dict

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from student_profile.student_profile import StudentProfile

load_dotenv()
console = Console()


PRIYA = {
    "name": "Priya",
    "gpa": 3.3,
    "gpa_scale": "4.0",
    "institution": "PES University, Bangalore",
    "major": "Computer Science",
    "graduation_year": 2024,
    "gre_quant": 162,
    "gre_verbal": 148,
    "toefl": 105,
    "disciplines": ["Computer Science", "Data Science"],
    "budget": 35000,
    "work_months": 0,
    "research": (
        "One project on NLP sentiment analysis using BERT, "
        "submitted to a workshop but not accepted. "
        "Strong Python skills, some experience with PyTorch."
    ),
    "notes": (
        "Parents strongly prefer CMU or a top-10 program. "
        "Priya is quietly open to other options but hasn't told her parents. "
        "Budget is a real constraint — family cannot afford more than USD 35,000/year total."
    ),
}


def print_banner(student_name: str = "Student", github_enabled: bool = False, resume_enabled: bool = False):
    input_sources = []
    if resume_enabled:
        input_sources.append("Resume")
    if github_enabled:
        input_sources.append("GitHub")
    source_line = ""
    if input_sources:
        source_line = "\n[bold]Input sources:[/bold] " + ", ".join(input_sources)

    console.print(Panel(
        "[bold white]KORGUT COMMONS[/bold white]\n"
        "[dim]Where agents live, learn, and advocate for students.[/dim]\n\n"
        "[bold]Active agents this session:[/bold]\n"
        f"  [bold blue]Aria[/bold blue] — Student Advocate (advising {student_name})\n"
        "  [bold cyan]Raider[/bold cyan] — Wright State University CS\n"
        "  [bold magenta]Student Profile[/bold magenta] — Persistent profile + fit storage"
        + ("\n  [bold purple]GitHub Skills Agent[/bold purple] — Demonstrated skills assessment" if github_enabled else "")
        + source_line,
        border_style="blue",
        padding=(1, 4),
    ))


def load_student_profile_from_resume(resume_path: str) -> Dict[str, Any]:
    from agents.resume_parser import ResumeParserAgent

    if not os.path.exists(resume_path):
        console.print(f"[bold red]Resume not found:[/bold red] {resume_path}")
        sys.exit(1)

    parser = ResumeParserAgent()
    profile = parser.parse(resume_path)
    parser.print_summary(profile)

    if not profile.get("name"):
        profile["name"] = "Student"

    return profile


def attach_github_assessment(student_profile: Dict[str, Any], github_input: str) -> Dict[str, Any]:
    """Run GitHubSkillsAgent if available and merge result into student_profile."""
    try:
        from agents.github_agent import GitHubSkillsAgent
    except Exception as exc:
        console.print(
            "[yellow]GitHubSkillsAgent is not available yet. "
            "Skipping GitHub assessment. Add agents/github_agent.py first.[/yellow]"
        )
        console.print(f"[dim]Import detail: {exc}[/dim]")
        return student_profile

    console.print(f"[yellow]Analysing GitHub profile:[/yellow] {github_input}")

    github_agent = GitHubSkillsAgent()
    github_assessment = github_agent.analyse(github_input)
    github_agent.print_summary(github_assessment)

    if "error" in github_assessment:
        console.print(
            "[yellow]GitHub assessment was not added to the student profile because analysis failed.[/yellow]"
        )
        return student_profile

    student_profile["github_assessment"] = github_assessment

    skills = list(student_profile.get("skills", []) or [])
    for item in github_assessment.get("languages", []) or []:
        if isinstance(item, dict) and item.get("name") and item["name"] not in skills:
            skills.append(item["name"])
        elif isinstance(item, str) and item not in skills:
            skills.append(item)
    for tool in github_assessment.get("frameworks_and_tools", []) or []:
        if tool not in skills:
            skills.append(tool)
    student_profile["skills"] = skills[:30]

    existing_notes = student_profile.get("notes", "") or ""
    student_profile["notes"] = (
        existing_notes
        + "\nGitHub assessment: "
        + str(github_assessment.get("admissions_summary", ""))
        + " Aria note: "
        + str(github_assessment.get("aria_notes", ""))
    ).strip()

    return student_profile


def main():
    parser = argparse.ArgumentParser(description="Korgut Commons")
    parser.add_argument("--no-scrape", action="store_true", help="Skip website scraping")
    parser.add_argument("--raider-only", action="store_true", help="Test Wright State agent directly")
    parser.add_argument(
        "--resume",
        type=str,
        help="Path to resume PDF/DOCX. Example: resumes/my_resume.pdf",
    )
    parser.add_argument(
        "--github",
        type=str,
        help="GitHub profile URL or username to analyse before Aria starts",
    )
    args = parser.parse_args()

    if not os.getenv("ANTHROPIC_API_KEY"):
        console.print(
            "[bold red]Error:[/bold red] ANTHROPIC_API_KEY not found.\n"
            "Copy .env.template to .env and add your key."
        )
        sys.exit(1)

    student_data = copy.deepcopy(PRIYA)

    if args.resume:
        student_data = load_student_profile_from_resume(args.resume)

    if args.github:
        student_data = attach_github_assessment(student_data, args.github)

    profile = StudentProfile(student_data)
    profile.generate_summary()
    profile.save()

    print_banner(
        student_name=profile.data.get("name", "Student"),
        github_enabled=bool(args.github),
        resume_enabled=bool(args.resume),
    )

    console.print("\n[bold green]Student Profile Loaded[/bold green]")
    profile.print_status()

    from agents.university_agent import UniversityAgent
    from agents.student_agent import StudentAgent
    from agents import commons

    auto_scrape = not args.no_scrape
    raider = UniversityAgent(
        university_id="wright_state_cs",
        auto_scrape=auto_scrape,
    )

    commons.register("wright_state_cs", raider)
    console.print(commons.status())

    # Generate and store Wright State fit assessment.
    try:
        assessment = raider.assess_fit(profile.data)
        profile.add_assessment("wright_state_cs", assessment)
        profile.generate_summary()
        console.print("\n[green]Fit Assessment Generated and saved in StudentProfile.[/green]")
    except Exception as exc:
        console.print("\n[yellow]Fit assessment could not be generated. Continuing session.[/yellow]")
        console.print(f"[dim]{exc}[/dim]")

    if args.raider_only:
        console.print(
            "[bold cyan]Raider direct mode.[/bold cyan] "
            "Ask Wright State anything. Type 'quit' to exit.\n"
        )
        while True:
            try:
                question = input("Your question: ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if question.lower() in ["quit", "exit"]:
                break
            if not question:
                continue

            result = raider.answer(question, profile.data)
            console.print(f"\n[bold cyan]Raider:[/bold cyan] {result['answer']}\n")
        return

    aria = StudentAgent(
        student_profile=profile.data,
        profile=profile,
    )
    aria.run_interactive()


if __name__ == "__main__":
    main()
