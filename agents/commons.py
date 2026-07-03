# agents/commons.py
# The Korgut Commons — where agents live and communicate.
# This is the registry and communication layer for all agents.
# Every agent registers here. Communication flows through here.

# import anthropic
from typing import Optional, List, Dict
from rich.console import Console
from kormic.models.verify import ProofToken
from kormic.runtime import runtime
from kormic.logger import kormic_logger
from agents.openrouter_client import call_openrouter

console = Console()
# client = anthropic.Anthropic()

# The Commons registry — all active agents register here
_university_agents: Dict = {}


def register(university_id: str, agent):
    """Register a university agent in the Commons."""
    _university_agents[university_id] = agent
    console.print(
        f"[dim]Commons: {agent.persona['agent_name']} registered.[/dim]"
    )


def query(
    university_id: str,
    question: str,
    student_context: dict = None,
    token: ProofToken = None
) -> Optional[Dict]:
    """
    Query a specific university agent.
    Called by Aria when she needs verified information about a program.
    """
    agent = _university_agents.get(university_id)
    if not agent:
        return None
    
    if token:
        kormic_logger.info("COMMUNICATE", token.agent_code, f"Sending query to {university_id}")
        
    return agent.answer(question, student_context, token)


def query_all(
    question: str,
    student_context: dict = None,
    token: ProofToken = None
) -> List[Dict]:
    """
    Broadcast a question to all registered university agents.
    Useful for cross-program comparisons.
    """
    responses = []
    for uid, agent in _university_agents.items():
        try:
            if token:
                kormic_logger.info("COMMUNICATE", token.agent_code, f"Broadcasting to {uid}")
            response = agent.answer(question, student_context, token)
            responses.append(response)
        except Exception as e:
            console.print(f"[yellow]Query failed for {uid}: {e}[/yellow]")
    return responses


def synthesise(
    original_question: str,
    responses: List[Dict],
    student_profile: dict
) -> str:
    """
    When Aria receives answers from multiple university agents,
    she synthesises them into a single coherent response for the student.
    This is the cross-agent intelligence layer.
    """
    if not responses:
        return "I wasn't able to get answers from the university agents on that one."

    compiled = "\n\n".join([
        f"{r['agent_name']} ({r['university']}) says:\n{r['answer']}"
        for r in responses
    ])

    synthesis_prompt = f"""You are Aria. Multiple university agents in the
Korgut Commons have answered a question. Synthesise their responses into a
single clear, personalised answer for {student_profile.get('name', 'the student')}.

Be specific. Cite university names where relevant. If the agents gave
different answers, note the differences clearly. Keep your answer
conversational and direct.

ORIGINAL QUESTION: {original_question}

UNIVERSITY AGENT RESPONSES:
{compiled}"""

    # response = client.messages.create(
    #     model="claude-sonnet-4-6",
    #     max_tokens=1000,
    #     messages=[{"role": "user", "content": synthesis_prompt}]
    # )
    
    response = call_openrouter(
        messages=[{"role": "user", "content": synthesis_prompt}],
        max_tokens=1000
    )

    return response.content[0].text


def status() -> str:
    """Show the current state of the Korgut Commons."""
    if not _university_agents:
        return "The Korgut Commons is empty — no agents registered yet."

    lines = [
        f"\n{'='*60}",
        "  THE KORGUT COMMONS",
        f"  {len(_university_agents)} university agent(s) active",
        f"{'='*60}",
    ]
    for agent in _university_agents.values():
        lines.append(f"  {agent.status()}")
    lines.append(f"{'='*60}\n")
    return "\n".join(lines)
