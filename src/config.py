# from pydantic import field_validator
from pydantic.v1 import validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    auth0_audience: str = ""
    auth0_domain: str= ""
    client_origin_url: str= ""
    auth0_client_id: str= ""
    auth0_client_secret: str= ""
    app_secret_key: str= ""
    token_client_id: str= ""
    token_client_secret: str= ""
    issuer: str= ""
    audience: str= "aa"
    port: int= 80
    reload: bool= True

    @classmethod
    # @validator("client_origin_url", "auth0_audience", "auth0_domain")
    @validator("client_origin_url", "auth0_audience", "auth0_domain","auth0_client_id","auth0_client_secret","app_secret_key")
    # @field_validator("client_origin_url", "auth0_audience", "auth0_domain")
    def check_not_empty(cls, v):
        assert v != "", f"{v} is not defined"
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
