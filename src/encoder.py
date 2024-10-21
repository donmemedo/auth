import datetime
from datetime import timezone

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.config import settings

payload = {

    "exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=1)

}

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


def private_key_with_pass(private_key_pass, private):
    encrypted_pem_private_key = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
    )
    return encrypted_pem_private_key


def encoder(msg, private, password=None):
    if password:
        private = serialization.load_pem_private_key(
            private, password=password, backend=default_backend()
        )
    encoded = jwt.encode(msg, private, algorithm="RS256", headers={"kid": "230498151c214b788dd97f22b85410a5"})
    return encoded


def decoder(token, public=None):
    if not public:
        public=public_key
    try:
        repo = jwt.decode(token, public, issuer=settings.issuer, audience=settings.audience, algorithms=["RS256"],
                      options={"require": ["exp", "nbf","iss","aud","iat", "sub","scope","permissions","gty"]})
        return repo
    except jwt.exceptions.ExpiredSignatureError:
        return False
    except jwt.exceptions.InvalidAudienceError:
        return False
    except jwt.exceptions.InvalidIssuerError:
        return False
    except jwt.exceptions.InvalidIssuedAtError:
        return False
    except jwt.exceptions.MissingRequiredClaimError as e:
        return e



password = b"your-password"
message = {
    "iss": settings.issuer,
    "sub": "RquTDGxqtYFlyBVSbl1JsXG95bmb5CVa@clients",
    "aud": settings.audience,
    "iat": datetime.datetime.now(tz=timezone.utc),
    "exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=100),
    "nbf": datetime.datetime.now(tz=timezone.utc) - datetime.timedelta(seconds=1),
    "scope": "admin:read",
    "gty": "client-credentials",
    "azp": "RquTDGxqtYFlyBVSbl1JsXG95bmb5CVa",
    "permissions": [
        "admin:read"
    ]
}

bb = encoder(message, private_key)
print(bb)
print("without password \n")
print(decoder(bb, public_key))

pem = private_key_with_pass(password, private_key)
cc = encoder(message, pem, password=password)
print(cc)
print("with password \n")
print(decoder(cc, public_key))
print(public_key)