from backend.config import settings
from backend.models import RiskLevel
from backend.llm_analyzer import LLMPhishingAnalyzer
from backend.phishing_detector import PhishingDetector


def test_llm_analyzer_uses_configured_model(monkeypatch):
	analyzer = LLMPhishingAnalyzer()
	calls = {}

	class DummyOllama:
		@staticmethod
		def chat(model, messages, options):
			calls["model"] = model
			return {
				"message": {
					"content": '{"is_phishing": true, "confidence": 0.9, "reasoning": "spoofing", "risk_factors": ["spoofed domain"]}'
				}
			}

	monkeypatch.setattr("backend.llm_analyzer.ollama", DummyOllama)
	monkeypatch.setattr(settings, "ENABLE_LLM_ANALYSIS", True)
	monkeypatch.setattr(settings, "LLM_MODEL", "llama3.2")

	result = analyzer.analyze("verify your account", "https://example.com")

	assert result["available"] is True
	assert result["is_phishing"] is True
	assert calls["model"] == "llama3.2"


def test_phishing_detector_marks_phishing_from_llm(monkeypatch):
	detector = PhishingDetector()

	monkeypatch.setattr(settings, "ENABLE_ML_MODEL", False)
	monkeypatch.setattr(settings, "ENABLE_LLM_ANALYSIS", True)
	monkeypatch.setattr(settings, "PHISHING_THRESHOLD", 0.7)

	def fake_llm_analyze(content, url):
		return {
			"available": True,
			"is_phishing": True,
			"confidence": 0.88,
			"reasoning": "Asks for immediate credential verification.",
			"risk_factors": ["urgency", "credential harvesting"]
		}

	monkeypatch.setattr("backend.phishing_detector.llm_analyzer.analyze", fake_llm_analyze)

	response = detector.analyze(
		email_content="URGENT: verify now to avoid account suspension",
		url="http://login-update.example.top"
	)

	assert response.is_phishing is True
	assert response.risk_score >= 0.7
	assert response.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
	assert any(ind.name == "LLM Contextual Analysis" for ind in response.indicators)


def test_phishing_detector_flags_suspicious_tld_with_path(monkeypatch):
	detector = PhishingDetector()

	monkeypatch.setattr(settings, "ENABLE_ML_MODEL", False)
	monkeypatch.setattr(settings, "ENABLE_LLM_ANALYSIS", False)
	monkeypatch.setattr(settings, "PHISHING_THRESHOLD", 0.7)

	response = detector.analyze(url="https://secure-login.top/reset")

	assert response.risk_score >= 0.7
	assert response.is_phishing is True
	assert any(ind.name == "Suspicious TLD" for ind in response.indicators)


def test_phishing_detector_flags_typosquatting_domains(monkeypatch):
	detector = PhishingDetector()

	monkeypatch.setattr(settings, "ENABLE_ML_MODEL", False)
	monkeypatch.setattr(settings, "ENABLE_LLM_ANALYSIS", False)
	monkeypatch.setattr(settings, "PHISHING_THRESHOLD", 0.7)

	response_one = detector.analyze(url="https://y0utube.com")
	response_two = detector.analyze(url="https://amaz0n.com")

	assert response_one.is_phishing is True
	assert response_two.is_phishing is True
	assert response_one.risk_score >= 0.8
	assert response_two.risk_score >= 0.8
	assert any(ind.name == "Possible Typosquatting Domain" for ind in response_one.indicators)
	assert any(ind.name == "Possible Typosquatting Domain" for ind in response_two.indicators)


def test_phishing_detector_flags_hyphenated_brand_impersonation(monkeypatch):
	detector = PhishingDetector()

	monkeypatch.setattr(settings, "ENABLE_ML_MODEL", False)
	monkeypatch.setattr(settings, "ENABLE_LLM_ANALYSIS", False)
	monkeypatch.setattr(settings, "PHISHING_THRESHOLD", 0.7)

	response = detector.analyze(url="https://amaz0n-security.xyz")

	assert response.is_phishing is True
	assert response.risk_score >= 0.8
	assert any(ind.name == "Possible Typosquatting Domain" for ind in response.indicators)
