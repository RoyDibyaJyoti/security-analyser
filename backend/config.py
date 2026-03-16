"""
Configuration management for Security Analyzer
Python 3.9 + Pydantic v2 Compatible Version
"""
from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from functools import lru_cache
from typing import Optional, List
import os

class Settings(BaseSettings):
    # ==================== Application ====================
    APP_NAME: str = "Security Analyzer Pro"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"

    # ==================== Server ====================
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "8000"))

    # ==================== Security ====================
    MAX_URL_LENGTH: int = 2048
    MAX_EMAIL_SIZE: int = 10 * 1024 * 1024  # 10MB
    REQUEST_TIMEOUT: int = 15
    SCAN_TIMEOUT: int = 60

    # OWASP Scanner Safety
    ALLOWED_DOMAINS: List[str] = os.getenv("ALLOWED_DOMAINS", "").split(",") if os.getenv("ALLOWED_DOMAINS") else []
    BLOCK_INTERNAL_IPS: bool = True
    USER_AGENT: str = "SecurityAnalyzer/1.0 (Educational; +https://yourdomain.com)"

    # ==================== Phishing Detection ====================
    PHISHING_THRESHOLD: float = 0.7
    ENABLE_ML_MODEL: bool = True
    ENABLE_LLM_ANALYSIS: bool = True  # New Flag
    LLM_MODEL: str = os.getenv("LLM_MODEL", "llama3.2")

    # ==================== External APIs ====================
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    URLSCAN_API_KEY: Optional[str] = os.getenv("URLSCAN_API_KEY")

    # ==================== Logging ====================
    LOG_LEVEL: str = "INFO"

    # ==================== Pydantic v2 Configuration ====================
    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()