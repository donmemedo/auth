import requests

from src.config import settings

payload = {"client_id": settings.token_client_id, "client_secret": settings.token_client_secret,
           "audience": settings.auth0_audience, "grant_type": "client_credentials"}
headers = {'content-type': "application/json"}
response = requests.post(url=f"https://{settings.auth0_domain}/oauth/token", json=payload, headers=headers)
print(response.json()['access_token'])
