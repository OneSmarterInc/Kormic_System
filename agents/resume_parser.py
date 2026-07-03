# agents/resume_parser.py
# The Resume Parser Agent for the Korgut Commons.
# Reads a student resume (PDF or DOCX) and extracts
# a structured profile for Aria to work with.

# import anthropic
import json
import base64
from pathlib import Path
from rich.console import Console
from agents.openrouter_client import call_openrouter

console = Console()
# client = anthropic.Anthropic()

EXTRACTION_PROMPT = """
You are a resume parser for Korgut, a graduate admissions platform.
Extract structured information from this student resume.

Return ONLY a valid JSON object with these exact fields.
No markdown, no explanation, just the JSON.

Required fields (use null if not found, never invent data):
{
  "name": string or null,
  "email": string or null,
  "undergraduate_institution": string or null,
  "undergraduate_major": string or null,
  "graduation_year": integer or null,
  "gpa": float or null,
  "gpa_scale": "4.0" or "10.0" or "percentage" or null,
  "gre_quant": integer or null,
  "gre_verbal": integer or null,
  "toefl": integer or null,
  "ielts": float or null,
  "work_experience_months": integer,
  "work_experience_summary": string or null,
  "research_experience": string or null,
  "publications_count": integer,
  "technical_skills": [list of strings],
  "projects": [
    {"title": string, "description": string, "technologies": [strings]}
  ],
  "inferred_disciplines": [list of strings],
  "gaps": [list of fields that are missing but important],
  "confidence_notes": string
}

Rules:
- Never invent data. If a field is not clearly present, use null.
- For work_experience_months: calculate from dates. Use 0 if no experience.
- For inferred_disciplines: suggest 2-3 graduate disciplines based on
  the student's major, skills, and projects.
- For gaps: always include 'budget' and 'target_disciplines'.
- For confidence_notes: one sentence about anything ambiguous or notable.
"""


def read_pdf(file_path: str) -> dict:
    with open(file_path, 'rb') as f:
        data = base64.standard_b64encode(f.read()).decode('utf-8')
    return {
        'type': 'document',
        'source': {
            'type': 'base64',
            'media_type': 'application/pdf',
            'data': data
        }
    }


def read_docx(file_path: str) -> str:
    from docx import Document
    doc = Document(file_path)
    return '\n'.join([p.text for p in doc.paragraphs if p.text.strip()])


class ResumeParserAgent:
    def parse(self, file_path: str) -> dict:
        path = Path(file_path)
        suffix = path.suffix.lower()
        console.print(f'[dim]Parsing: {path.name}[/dim]')

        if suffix == '.pdf':
            return self._parse_pdf(file_path)
        elif suffix in ['.docx', '.doc']:
            return self._parse_docx(file_path)
        else:
            raise ValueError(f'Unsupported format: {suffix}')

    def _parse_pdf(self, file_path: str) -> dict:
        doc_content = read_pdf(file_path)
        # response = client.messages.create(
        #     model='claude-sonnet-4-6',
        #     max_tokens=1000,
        #     messages=[{
        #         'role': 'user',
        #         'content': [doc_content, {'type': 'text', 'text': EXTRACTION_PROMPT}]
        #     }]
        # )
        
        response = call_openrouter(
            messages=[{'role': 'user', 'content': [doc_content, {'type': 'text', 'text': EXTRACTION_PROMPT}]}],
            max_tokens=1000
        )
        return self._process(response.content[0].text)

    def _parse_docx(self, file_path: str) -> dict:
        text = read_docx(file_path)
        # response = client.messages.create(
        #     model='claude-sonnet-4-6',
        #     max_tokens=1000,
        #     messages=[{'role': 'user', 'content': f'RESUME:\n{text}\n\n{EXTRACTION_PROMPT}'}]
        # )
        
        response = call_openrouter(
            messages=[{'role': 'user', 'content': f'RESUME:\n{text}\n\n{EXTRACTION_PROMPT}'}],
            max_tokens=1000
        )
        return self._process(response.content[0].text)

    def _process(self, raw: str) -> dict:
        clean = raw.strip()
        if clean.startswith('```'):
            clean = '\n'.join(clean.split('\n')[1:-1])
        extracted = json.loads(clean.strip())
        return self._map(extracted)

    def _map(self, e: dict) -> dict:
        gaps = e.get('gaps', [])
        notes = f"Profile from resume. "
        if e.get('confidence_notes'):
            notes += e['confidence_notes'] + " "
        if gaps:
            notes += f"Aria to collect: {', '.join(gaps)}."

        return {
            'name': e.get('name', 'Student'),
            'email': e.get('email'),
            'institution': e.get('undergraduate_institution'),
            'major': e.get('undergraduate_major'),
            'graduation_year': e.get('graduation_year'),
            'gpa': e.get('gpa'),
            'gpa_scale': e.get('gpa_scale', '4.0'),
            'gre_quant': e.get('gre_quant'),
            'gre_verbal': e.get('gre_verbal'),
            'toefl': e.get('toefl'),
            'work_months': e.get('work_experience_months', 0),
            'research': e.get('research_experience', 'None stated'),
            'disciplines': e.get('inferred_disciplines', []),
            'skills': e.get('technical_skills', []),
            'projects': e.get('projects', []),
            'budget': None,
            'notes': notes,
            'source': 'resume',
            'verified': False,
            'gaps': gaps
        }

    def print_summary(self, profile: dict):
        console.print('\n[bold green]Resume parsed.[/bold green]')
        for label, key in [
            ('Name', 'name'), ('Institution', 'institution'),
            ('Major', 'major'), ('GPA', 'gpa'),
            ('Work exp', 'work_months'), ('Skills', 'skills')
        ]:
            val = profile.get(key)
            if isinstance(val, list):
                val = ', '.join(str(v) for v in val[:5])
            console.print(f'  {label}: {val}')
        gaps = profile.get('gaps', [])
        if gaps:
            console.print(f'  [yellow]Gaps: {", ".join(gaps)}[/yellow]')
        console.print()
