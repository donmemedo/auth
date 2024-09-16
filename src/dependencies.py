from src.authorization_header_elements import get_bearer_token
from fastapi import Depends
from src.json_web_token import JsonWebToken


def validate_token(token: str = Depends(get_bearer_token)):
    return JsonWebToken(token).validate()
