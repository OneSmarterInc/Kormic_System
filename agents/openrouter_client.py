import os
import requests
from typing import List, Dict, Any

class MockContentBlock:
    def __init__(self, text: str):
        self.text = text

class MockResponse:
    def __init__(self, text: str):
        self.content = [MockContentBlock(text)]

def call_openrouter(system: str = "", messages: List[Dict[str, Any]] = None, max_tokens: int = 1000) -> MockResponse:
    """
    Temporary replacement for Anthropic client.messages.create.
    Uses OpenRouter API and mimics Anthropic's response object.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return MockResponse("ERROR: OPENROUTER_API_KEY not found in environment. Please add it to your .env file.")
        
    formatted_messages = []
    if system:
        system += "\n\nCRITICAL INSTRUCTION: DO NOT output any internal reasoning, planning, or word counts. Output ONLY the final response exactly as it should be presented to the user."
        formatted_messages.append({"role": "system", "content": system})
    if messages:
        # Convert any nested dictionaries in content (Anthropic style) to strings for standard OpenAI format.
        # But wait, Anthropic uses [{'type': 'text', 'text': '...'}].
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                # Flatten anthropic-style blocks to a single string (simple fallback for basic text)
                flat_content = ""
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        flat_content += block.get("text", "")
                    elif isinstance(block, str):
                        flat_content += block
                formatted_messages.append({"role": msg["role"], "content": flat_content})
            else:
                formatted_messages.append({"role": msg["role"], "content": str(content)})
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "http://localhost",
        "X-Title": "Kormic Pedigree System"
    }
    
    payload = {
        # Using a reliable model on OpenRouter, claude-3-haiku or gemini-flash is good for testing.
        # But we'll use openrouter/auto or google/gemini-pro if not specified.
        "model": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free", 
        "messages": formatted_messages,
        "max_tokens": max_tokens
    }
    
    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload)
        response.raise_for_status()
        text = response.json()["choices"][0]["message"]["content"]
        return MockResponse(text)
    except Exception as e:
        return MockResponse(f"OpenRouter Error: {str(e)}\nResponse: {getattr(response, 'text', '') if 'response' in locals() else 'None'}")
