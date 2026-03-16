"""
LLM-based phishing analysis using Ollama (Llama 3.2)
"""
import json
import re
from typing import Optional, Dict
from backend.config import settings

try:
    import ollama
except ImportError:
    ollama = None

class LLMPhishingAnalyzer:
    """Use Llama 3.2 via Ollama for contextual phishing analysis"""

    def analyze(self, content: str, url: Optional[str] = None) -> Dict:
        """Analyze content using LLM"""
        if not settings.ENABLE_LLM_ANALYSIS:
            return {"available": False}

        if ollama is None:
            return {
                "available": False,
                "error": "ollama package is not installed"
            }
        
        prompt = self._build_prompt(content, url)
        
        try:
            response = ollama.chat(
                model=settings.LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1, "num_predict": 300}
            )
            
            raw_content = response["message"]["content"]
            result = self._parse_llm_response(raw_content)
            return {"available": True, **result}
            
        except Exception as e:
            print(f"⚠️ LLM analysis failed: {e}")
            return {"available": False, "error": str(e)}

    def _build_prompt(self, content: str, url: Optional[str]) -> str:
        """Build structured prompt for phishing analysis"""
        url_context = f"\nURL to evaluate: {url}" if url else ""
        
        # Truncate content if too long to avoid context limits
        safe_content = content[:2500] if content else ""

        return f"""You are a cybersecurity expert analyzing potential phishing attempts.
Analyze this content for phishing indicators:
CONTENT:
{safe_content}
{url_context}

Respond in VALID JSON format ONLY (no markdown code blocks):
{{
    "is_phishing": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation of why",
    "risk_factors": ["factor1", "factor2"]
}}
Be conservative: only flag as phishing if strong evidence exists."""

    def _parse_llm_response(self, response: str) -> Dict:
        """Parse LLM JSON response robustly"""
        # Remove markdown code blocks if present (e.g., ```json ... ```)
        clean_response = re.sub(r'```json\s*', '', response)
        clean_response = re.sub(r'```\s*', '', clean_response)
        
        # Extract JSON object
        json_match = re.search(r'\{[\s\S]*\}', clean_response)
        
        if json_match:
            try:
                data = json.loads(json_match.group())
                # Ensure types are correct
                return {
                    "is_phishing": bool(data.get("is_phishing", False)),
                    "confidence": float(data.get("confidence", 0.5)),
                    "reasoning": str(data.get("reasoning", "No reasoning provided")),
                    "risk_factors": data.get("risk_factors", [])
                }
            except json.JSONDecodeError:
                pass
        
        # Fallback heuristic if JSON parsing fails
        is_phish = "phishing" in response.lower() or "suspicious" in response.lower()
        return {
            "is_phishing": is_phish,
            "confidence": 0.6 if is_phish else 0.3,
            "reasoning": "LLM response parsing failed, used keyword heuristic.",
            "risk_factors": ["parsing_error"]
        }

llm_analyzer = LLMPhishingAnalyzer()