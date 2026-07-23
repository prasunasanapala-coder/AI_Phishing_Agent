import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

models = [
    "gemini-flash-latest"]

for model in models:
    print(f"\nTesting {model}")

    try:
        response = client.models.generate_content(
            model=model,
            contents="Reply with SUCCESS only."
        )

        print("✅ SUCCESS")
        print(response.text)

    except Exception as e:
        print("❌ FAILED")
        print(e)