import os
import requests
import json
from dotenv import load_dotenv

# Load API key from environment
load_dotenv()
API_KEY = os.getenv("OPENROUTER_API_KEY")

if not API_KEY:
    raise ValueError("Missing OPENROUTER_API_KEY. Please set it in your .env file or environment.")

url = "https://openrouter.ai/api/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
    # Optional headers for leaderboards
    "HTTP-Referer": "http://localhost", 
    "X-Title": "Reasoning Test Script"
}

def print_separator(title):
    print(f"\n{'='*20} {title} {'='*20}")

# --- 1. First API Call ---
print_separator("REQUEST 1: Initial Question")
payload = {
    "model": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "messages": [
        {
            "role": "user",
            "content": "How many r's are in the word 'strawberry'?"
        }
    ],
    "reasoning": {"enabled": True}
}

response = requests.post(url, headers=headers, data=json.dumps(payload))
response.raise_for_status()
data = response.json()

# Extract the first message
assistant_message = data['choices'][0]['message']
content = assistant_message.get('content')
reasoning_details = assistant_message.get('reasoning_details')

# Print Reasoning Details
print("\n REASONING PROCESS (Step-by-Step):")
if reasoning_details:
    for detail in reasoning_details:
        # Reasoning details often come as a list of blocks with 'content'
        if isinstance(detail, dict) and 'content' in detail:
            print(detail['content'])
        else:
            print(detail)
else:
    print("No reasoning details returned.")

# Print Final Answer
print("\n FINAL ANSWER:")
print(content)
