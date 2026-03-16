"""
Main Phishing Detector Logic combining Heuristics, ML, and LLM
"""
from typing import Optional, Dict, List, Any
from datetime import datetime
import re
from urllib.parse import urlparse
from backend.config import settings
from backend.models import PhishingAnalysisResponse, RiskLevel, Indicator
from backend.ml_model import ml_model
from backend.llm_analyzer import llm_analyzer

class PhishingDetector:
    _DIGIT_SUBSTITUTIONS = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    })

    _TARGET_BRANDS = {
        "youtube", "amazon", "google", "microsoft", "paypal", "apple", "netflix", "facebook", "instagram"
    }

    _SUSPICIOUS_DOMAIN_TERMS = {
        "security", "secure", "verify", "account", "login", "signin", "auth", "support", "update", "billing"
    }

    def _extract_domain_label(self, hostname: str) -> str:
        parts = (hostname or "").split(".")
        if len(parts) >= 2:
            return parts[-2]
        return parts[0] if parts else ""

    def _detect_typosquatting(self, hostname: str) -> Optional[str]:
        label = self._extract_domain_label((hostname or "").lower())
        if not label:
            return None

        normalized = label.translate(self._DIGIT_SUBSTITUTIONS)
        has_digit = any(ch.isdigit() for ch in label)
        label_tokens = [token for token in re.split(r"[-_]", label) if token]
        normalized_tokens = [token.translate(self._DIGIT_SUBSTITUTIONS) for token in label_tokens]

        if has_digit and normalized in self._TARGET_BRANDS and label != normalized:
            return normalized

        for raw_token, normalized_token in zip(label_tokens, normalized_tokens):
            if normalized_token in self._TARGET_BRANDS and raw_token != normalized_token:
                return normalized_token

        for brand in self._TARGET_BRANDS:
            looks_like_brand_compound = (
                normalized.startswith(f"{brand}-")
                or normalized.endswith(f"-{brand}")
                or f"-{brand}-" in normalized
            )
            includes_suspicious_term = any(term in normalized for term in self._SUSPICIOUS_DOMAIN_TERMS)

            if looks_like_brand_compound and (has_digit or includes_suspicious_term):
                return brand

        return None

    def analyze(self, email_content: Optional[str] = None, url: Optional[str] = None, 
                headers: Optional[Dict] = None, from_address: Optional[str] = None) -> PhishingAnalysisResponse:
        
        indicators: List[Indicator] = []
        risk_score = 0.0
        llm_reasoning = ""
        is_phishing = False
        confidence = 0.0
        suspicious_tld_detected = False
        credential_path_detected = False

        # 1. Heuristic Checks (URL & Content)
        combined_text = (email_content or "") + (url or "")
        
        if url:
            parsed_url = urlparse(url)
            hostname = (parsed_url.hostname or "").lower()
            path_and_query = f"{parsed_url.path or ''} {parsed_url.query or ''}".lower()

            if parsed_url.scheme == "http":
                indicators.append(Indicator(name="Insecure Protocol", description="URL uses HTTP instead of HTTPS", severity=RiskLevel.MEDIUM, evidence=url))
                risk_score += 0.2
            
            suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".work"]
            if hostname and any(hostname.endswith(tld) for tld in suspicious_tlds):
                suspicious_tld_detected = True
                indicators.append(Indicator(name="Suspicious TLD", description="Domain uses a high-risk Top Level Domain", severity=RiskLevel.HIGH, evidence=url))
                risk_score += 0.3

            if "xn--" in hostname:
                indicators.append(Indicator(
                    name="Potential Homograph Domain",
                    description="Domain contains punycode and may impersonate a trusted brand",
                    severity=RiskLevel.HIGH,
                    evidence=hostname,
                ))
                risk_score += 0.25

            # Phishing URLs often pack suspicious login/reset terms into path and query.
            suspicious_terms = [
                "verify", "login", "signin", "account", "update", "suspended", "reset", "password", "token"
            ]
            if any(term in path_and_query for term in suspicious_terms):
                credential_path_detected = True
                indicators.append(Indicator(
                    name="Credential-Themed URL Path",
                    description="URL path/query contains common phishing credential-harvesting terms",
                    severity=RiskLevel.MEDIUM,
                    evidence=(parsed_url.path or parsed_url.query or url)[:200],
                ))
                risk_score += 0.15

            if "@" in url:
                indicators.append(Indicator(
                    name="Obfuscated Destination",
                    description="URL contains '@' which can hide the true destination",
                    severity=RiskLevel.HIGH,
                    evidence=url,
                ))
                risk_score += 0.2

            if hostname.count("-") >= 3:
                indicators.append(Indicator(
                    name="Hyphenated Hostname Pattern",
                    description="Hostname has many hyphens, a common phishing domain pattern",
                    severity=RiskLevel.MEDIUM,
                    evidence=hostname,
                ))
                risk_score += 0.1

            impersonated_brand = self._detect_typosquatting(hostname)
            if impersonated_brand:
                indicators.append(Indicator(
                    name="Possible Typosquatting Domain",
                    description="Domain appears to impersonate a high-value brand using lookalike characters",
                    severity=RiskLevel.CRITICAL,
                    evidence=f"{hostname} resembles {impersonated_brand}",
                ))
                is_phishing = True
                confidence = max(confidence, 0.8)
                risk_score = max(risk_score, 0.8)

            # Explicitly mark common phishing URL combinations as phishing.
            if suspicious_tld_detected and credential_path_detected:
                is_phishing = True
                risk_score = max(risk_score, 0.75)
                confidence = max(confidence, 0.75)

        if email_content:
            urgent_words = ["urgent", "immediate", "verify now", "account suspended", "click here"]
            if any(word in email_content.lower() for word in urgent_words):
                indicators.append(Indicator(name="Urgency Language", description="Content contains urgent call-to-action phrases", severity=RiskLevel.MEDIUM, evidence="Found urgency keywords"))
                risk_score += 0.2

        # 2. ML Model Analysis
        if settings.ENABLE_ML_MODEL and email_content:
            try:
                ml_result = ml_model.predict(email_content)
                if ml_result["is_phishing"]:
                    is_phishing = True
                    risk_score = max(risk_score, ml_result["phishing_probability"])
                    confidence = max(confidence, ml_result["confidence"])
                    indicators.append(Indicator(
                        name="ML Classifier", 
                        description=f"Naive Bayes model detected phishing with {ml_result['confidence']:.2f} confidence", 
                        severity=RiskLevel.HIGH if ml_result["phishing_probability"] > 0.8 else RiskLevel.MEDIUM,
                        evidence=f"Probability: {ml_result['phishing_probability']}"
                    ))
            except Exception as e:
                print(f"ML Error: {e}")

        # 3. LLM Analysis (The Upgrade)
        if settings.ENABLE_LLM_ANALYSIS:
            try:
                llm_result = llm_analyzer.analyze(combined_text, url)
                if llm_result.get("available"):
                    llm_reasoning = llm_result.get("reasoning", "")
                    if llm_result.get("is_phishing"):
                        is_phishing = True
                        # LLM overrides score if confident
                        risk_score = max(risk_score, llm_result.get("confidence", 0.5))
                        confidence = max(confidence, llm_result.get("confidence", 0.5))
                        
                        indicators.append(Indicator(
                            name="LLM Contextual Analysis",
                            description=llm_reasoning,
                            severity=RiskLevel.CRITICAL if llm_result.get("confidence", 0) > 0.8 else RiskLevel.HIGH,
                            evidence=", ".join(llm_result.get("risk_factors", []))
                        ))
            except Exception as e:
                print(f"LLM Error: {e}")

        # Normalize Score
        risk_score = min(1.0, risk_score)
        
        # Determine Final Status
        if risk_score >= settings.PHISHING_THRESHOLD:
            is_phishing = True
        
        # Map Score to Risk Level
        if risk_score >= 0.8:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 0.5:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.2:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        recommendations = []
        if is_phishing:
            recommendations.append("Do not click any links or download attachments.")
            recommendations.append("Report this email to your security team immediately.")
            recommendations.append("Verify the sender's address via a separate channel.")
        else:
            recommendations.append("Standard caution advised. Verify unexpected requests.")

        return PhishingAnalysisResponse(
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            is_phishing=is_phishing,
            indicators=indicators,
            analysis_timestamp=datetime.utcnow(),
            recommendations=recommendations,
            confidence=round(confidence, 2),
            llm_reasoning=llm_reasoning if llm_reasoning else None
        )

detector = PhishingDetector()