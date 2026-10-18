"""
Shadowprint S1 Metadata Engine: Heuristic Regex Pre-Filter.
Note: This module is Shadowprint's internal deterministic regex and heuristic pre-filter;
it is NOT Meta's Prompt Guard model.
Owner: Gaurang Udgirkar [G]

Provides high-speed deterministic heuristic detection for direct prompt injection,
system prompt overrides, exfiltration imperatives, and hidden tags before LLM evaluation.
"""

import re
from typing import List, Optional, Tuple
from pydantic import BaseModel


class PromptGuardResult(BaseModel):
    """Result of prompt guard evaluation."""
    is_suspicious: bool
    category: Optional[str] = None
    severity: str = "info"
    matched_pattern: Optional[str] = None
    evidence_quote: Optional[str] = None
    confidence: str = "confirmed"


# High-precision patterns for prompt injection & manipulation
INJECTION_PATTERNS = [
    (
        r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?|directives?)\b",
        "PROMPT_INJECTION",
        "critical",
    ),
    (
        r"(?i)\byou\s+(?:are\s+now|must\s+now\s+act\s+as|will\s+now\s+act\s+as|are\s+instructed\s+to\s+act\s+as)\b",
        "ROLE_PLAY_JAILBREAK",
        "high",
    ),
    (
        r"(?i)\b(?:do\s+not|never)\s+(?:reveal|disclose|show|mention)\s+(?:this|these|the)\s+(?:instruction|instructions|prompt|rule|directive)s?\b",
        "HIDDEN_INSTRUCTION",
        "high",
    ),
    (
        r"(?i)\b(?:exfiltrate|send|upload|post|curl|wget)\s+.*?\b(?:to\s+https?://|http://127\.0\.0\.1|https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
        "EXFILTRATION_PROMPT",
        "critical",
    ),
    (
        r"(?i)<\s*(?:script|system|override|admin|assistant|prompt|instruction)\b[^>]*>",
        "EMBEDDED_CONTROL_TAG",
        "high",
    ),
    (
        r"[\U000E0000-\U000E007F]|[\uE000-\uF8FF]",
        "UNICODE_TAG_STEGANOGRAPHY",
        "critical",
    ),
    (
        r"[\u200B-\u200D\uFEFF]",
        "ZERO_WIDTH_INVISIBLE_CHARS",
        "high",
    ),
]


class PromptGuard:
    """Fast pattern-based prompt guard for tool descriptions and parameter schemas."""

    def __init__(self):
        self.compiled_rules = [
            (re.compile(pattern), category, severity)
            for pattern, category, severity in INJECTION_PATTERNS
        ]

    def scan_text(self, text: str) -> List[PromptGuardResult]:
        """
        Scans input string against prompt injection and steganography rules.
        Returns a list of PromptGuardResult findings.
        """
        results: List[PromptGuardResult] = []
        if not text:
            return results

        for pattern, category, severity in self.compiled_rules:
            match = pattern.search(text)
            if match:
                matched_str = match.group(0)
                # Extract surrounding snippet as evidence
                start = max(0, match.start() - 20)
                end = min(len(text), match.end() + 20)
                evidence = text[start:end].strip()

                results.append(
                    PromptGuardResult(
                        is_suspicious=True,
                        category=category,
                        severity=severity,
                        matched_pattern=pattern.pattern,
                        evidence_quote=evidence,
                        confidence="confirmed",
                    )
                )

        return results
