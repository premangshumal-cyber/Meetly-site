import os
from google import genai

client = genai.Client(api_key=os.environ["AQ.Ab8RN6KR_G_BOOSmNPZGCPXpgDVnZiK0qJeXAY3nsTS1BleQ0w"])

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Explain this repository."
)

print(response.text)
