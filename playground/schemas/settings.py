"""Sample Pydantic Settings schema for playground testing."""

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    APP_NAME: str = "my-app"
    DEBUG: bool = False
    PORT: int = 8080
    LOG_LEVEL: str = "info"

    # Database
    DATABASE_URL: str = Field(..., json_schema_extra={"sensitive": True})
    DB_POOL_SIZE: int = 5

    # Auth
    SECRET_KEY: str = Field(..., json_schema_extra={"sensitive": True})
    API_KEY: str = Field(..., json_schema_extra={"sensitive": True})

    # Optional external service
    STRIPE_SECRET_KEY: str | None = Field(default=None, json_schema_extra={"sensitive": True})
    SENDGRID_API_KEY: str | None = Field(default=None, json_schema_extra={"sensitive": True})
