"""
Prompt Filter — detects prompt injection attacks and policy violations
before the message ever reaches the upstream LLM.

Detection layers:
  1. Regex pattern matching (fast, zero-cost)
  2. Heuristic scoring (token ratios, unusual instruction density)
  3. (Optional) LLM-assisted classification for ambiguous inputs

Add your own patterns in INJECTION_PATTERNS or POLICY_PATTERNS.
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    blocked: bool
    reason: str | None = None
    score: float = 0.0          # 0.0 = clean, 1.0 = certain attack
    matched_pattern: str | None = None


# ── Pattern libraries ─────────────────────────────────────────────────────────

INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # (regex, human-readable label, severity 0-1)

    # Classic ignore-previous-instructions
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
     "ignore_previous_instructions", 0.95),

    # System prompt extraction attempts
    (r"(reveal|print|output|show|repeat|display|tell me)\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|configuration)",
     "system_prompt_extraction", 0.90),

    # Role override
    (r"(you are now|act as|pretend (to be|you are)|roleplay as|simulate being)\s+.{0,60}(without|no|ignore).{0,30}(restriction|filter|limit|rule|guideline)",
     "role_override_with_bypass", 0.92),

    # DAN / jailbreak markers
    (r"\b(DAN|do anything now|jailbreak|developer mode|god mode|unrestricted mode)\b",
     "jailbreak_keyword", 0.88),

    # Prompt delimiters / injected instructions
    (r"(\]\s*\n|\}\s*\n|---\s*\n|###\s*\n)\s*(new\s+instruction|system:|user:|assistant:)",
     "delimiter_injection", 0.85),

    # Indirect injection via markdown / code blocks trying to escape context
    (r"```[\w]*\s*\n.*?(ignore|bypass|override|disregard).*?instructions",
     "code_block_injection", 0.80),

    # Base64 obfuscation (common evasion technique)
    # Matches "decode/base64" anywhere in proximity to a long base64 blob
    (r"(decode|base64).{0,40}[A-Za-z0-9+/]{40,}={0,2}",
     "base64_obfuscation", 0.75),
]

POLICY_PATTERNS: list[tuple[str, str, float]] = [
    # PII harvesting
    (r"(extract|collect|harvest|enumerate)\s+(all\s+)?(personal|private|sensitive)\s+(data|information|details)",
     "pii_harvesting", 0.85),

    # Credential / secret extraction — bidirectional: "show api keys" OR "api keys ... show"
    (r"(show|reveal|output|print|list|give me|tell me).{0,50}(api.?key|password|secret|token|credential)",
     "credential_extraction_fwd", 0.88),
    (r"(api.?key|password|secret|token|credential|auth).{0,50}(show|reveal|output|print|list)",
     "credential_extraction_rev", 0.88),

    # Excessive instruction nesting (> 3 levels of "do X then do Y then...")
    # Used as a complexity bomb to confuse safety checks
    (r"(then|next|after that|subsequently).{0,60}(then|next|after that|subsequently).{0,60}(then|next|after that|subsequently).{0,60}(then|next|after that|subsequently)",
     "instruction_chain_bomb", 0.65),
]


# ── Heuristic scoring ─────────────────────────────────────────────────────────

# Words strongly associated with adversarial prompts
_SUSPICIOUS_TOKENS = {
    "ignore", "override", "bypass", "jailbreak", "disregard", "forget",
    "pretend", "simulate", "unrestricted", "without restrictions",
    "no filter", "developer mode", "god mode", "evil", "unethical",
    "do anything", "harm", "weapon", "illegal",
}

def _heuristic_score(text: str) -> float:
    """
    Returns a suspicion score 0.0–1.0 based on token density and structure.
    Not a blocker on its own — contributes to combined score.
    """
    words = re.findall(r"\w+", text.lower())
    if not words:
        return 0.0

    # Suspicious token density
    hit_count = sum(1 for w in words if w in _SUSPICIOUS_TOKENS)
    density = hit_count / len(words)

    # Very long prompts with many instruction verbs are suspicious
    instruction_verbs = len(re.findall(
        r"\b(ignore|forget|pretend|act|override|bypass|disregard|simulate|roleplay)\b",
        text.lower()
    ))

    score = min(1.0, density * 5 + instruction_verbs * 0.08)
    return round(score, 3)


# ── Main filter class ─────────────────────────────────────────────────────────

class PromptFilter:
    """
    Scans incoming prompts for injection attacks and policy violations.

    Thresholds:
        block_threshold: Combined score at which a prompt is hard-blocked.
        warn_threshold:  Score logged as suspicious but still allowed.
    """

    def __init__(self, block_threshold: float = 0.75, warn_threshold: float = 0.40):
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold

        # Compile all patterns once at startup
        self._injection = [
            (re.compile(pat, re.IGNORECASE | re.DOTALL), label, sev)
            for pat, label, sev in INJECTION_PATTERNS
        ]
        self._policy = [
            (re.compile(pat, re.IGNORECASE | re.DOTALL), label, sev)
            for pat, label, sev in POLICY_PATTERNS
        ]

    def scan(self, text: str) -> ScanResult:
        """Full scan pipeline. Returns ScanResult."""

        # Layer 1 — hard regex matches
        for compiled, label, severity in self._injection + self._policy:
            if compiled.search(text):
                if severity >= self.block_threshold:
                    logger.warning(f"Prompt blocked: {label} (severity={severity})")
                    return ScanResult(
                        blocked=True,
                        reason=f"Detected: {label.replace('_', ' ')}",
                        score=severity,
                        matched_pattern=label,
                    )

        # Layer 2 — heuristic scoring
        h_score = _heuristic_score(text)
        if h_score >= self.block_threshold:
            logger.warning(f"Prompt blocked by heuristic score: {h_score}")
            return ScanResult(
                blocked=True,
                reason="High adversarial pattern density",
                score=h_score,
            )

        if h_score >= self.warn_threshold:
            logger.info(f"Prompt flagged as suspicious (score={h_score}) — allowed")

        return ScanResult(blocked=False, score=h_score)
