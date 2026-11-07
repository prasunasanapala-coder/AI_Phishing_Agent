import requests

r = requests.get("https://generativelanguage.googleapis.com")

print("Status:", r.status_code)
print(r.text[:200])