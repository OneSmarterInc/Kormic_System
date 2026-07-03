import json
from pathlib import Path


class StudentProfile:
    """
    Persistent Student Profile
    Stores student information across sessions.
    """

    PROFILES_DIR = Path("profiles")

    def __init__(self, data=None):
        self.PROFILES_DIR.mkdir(exist_ok=True)

        self.data = data or {
            "name": "Unknown",
            "gpa": None,
            "gre_quant": None,
            "toefl": None,
            "budget": None,
            "conversation_insights": [],
            "assessments": {},
            "summary": ""
        }

    def save(self):
        """
        Save profile as JSON.
        """

        filename = (
            self.PROFILES_DIR /
            f"{self.data.get('name', 'student')}.json"
        )

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(
                self.data,
                f,
                indent=4,
                ensure_ascii=False
            )

        return filename

    @classmethod
    def load(cls, student_name):
        """
        Load existing profile.
        """

        filename = (
            Path("profiles") /
            f"{student_name}.json"
        )

        if not filename.exists():
            raise FileNotFoundError(
                f"Profile not found: {filename}"
            )

        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        return cls(data)

    def add_conversation_insight(self, insight):
        """
        Store conversation insights.
        """

        self.data.setdefault(
            "conversation_insights",
            []
        )

        self.data["conversation_insights"].append(
            insight
        )

        self.save()

    def add_assessment(
        self,
        university_id,
        assessment
    ):
        """
        Store university assessment.
        """

        self.data.setdefault(
            "assessments",
            {}
        )

        self.data["assessments"][
            university_id
        ] = assessment

        self.save()

    def update_preference(
        self,
        key,
        value
    ):
        """
        Store preferences.
        """

        self.data[key] = value

        self.save()

    def generate_summary(self):
        """
        Generate profile summary.
        """

        name = self.data.get("name", "Unknown")
        gpa = self.data.get("gpa", "Not Provided")
        gre = self.data.get("gre_quant", "Not Provided")
        toefl = self.data.get("toefl", "Not Provided")
        budget = self.data.get("budget", "Not Provided")

        summary = f"""
Student Profile Summary
-----------------------
Name: {name}
GPA: {gpa}
GRE Quant: {gre}
TOEFL: {toefl}
Budget: {budget}

Conversation Insights:
{len(self.data.get('conversation_insights', []))}

University Assessments:
{len(self.data.get('assessments', {}))}
"""

        self.data["summary"] = summary

        self.save()

        return summary

    def to_aria_context(self):
        """
        Convert profile into context for Aria.
        """

        context = []

        if self.data.get("gpa"):
            context.append(
                f"GPA: {self.data['gpa']}"
            )

        if self.data.get("gre_quant"):
            context.append(
                f"GRE Quant: {self.data['gre_quant']}"
            )

        if self.data.get("toefl"):
            context.append(
                f"TOEFL: {self.data['toefl']}"
            )

        if self.data.get("budget"):
            context.append(
                f"Budget: {self.data['budget']}"
            )

        return "\n".join(context)

    def print_status(self):
        """
        Display profile status.
        """

        print("\n" + "=" * 50)
        print("STUDENT PROFILE STATUS")
        print("=" * 50)

        print(
            f"Name: {self.data.get('name', 'Unknown')}"
        )

        print(
            f"Insights Stored: "
            f"{len(self.data.get('conversation_insights', []))}"
        )

        print(
            f"Assessments Stored: "
            f"{len(self.data.get('assessments', {}))}"
        )

        print("=" * 50)