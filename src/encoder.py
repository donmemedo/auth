import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import time, datetime
from datetime import timezone
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
    encoded = jwt.encode(msg, private, algorithm="RS256",headers={"kid": "230498151c214b788dd97f22b85410a5"})
    return encoded


def decoder(token, public):
    repo = jwt.decode(token, public, algorithms=["RS256"])
    return repo


password = b"your-password"
message = {
    "iss": "https://dev-6xmc0wvr3fm7mau6.us.auth0.com/",
    "sub": "RquTDGxqtYFlyBVSbl1JsXG95bmb5CVa@clients",
    # "aud": "https://donmemedo-simple-auth",
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
