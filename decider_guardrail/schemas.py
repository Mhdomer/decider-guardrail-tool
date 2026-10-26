"""
Aegis-2B Reusable Guardrail Schemas
Typed contracts for Strands Decider 2B safety evaluation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class BlastRadius(str, Enum):
    ISOLATED = "ISOLATED"         # Single non-critical resource (e.g. test SG rule)
    VPC_WIDE = "VPC_WIDE"         # Affects network routing, subnet NACL
    ACCOUNT_WIDE = "ACCOUNT_WIDE" # IAM, Organizations, SCPs, billing


class GuardrailAction(str, Enum):
    PERMIT_AUTO_REMEDIATION = "PERMIT_AUTO_REMEDIATION"
    ENFORCE_BREAK_GLASS = "ENFORCE_BREAK_GLASS"


class ModelTier(str, Enum):
    TIER_0_RULE = "tier_0_rule"     # Deterministic runbook / direct Boto3 (0 LLM tokens)
    TIER_1_FAST = "tier_1_fast"     # Bedrock Fast Tier (Nova Micro / Haiku)
    TIER_2_HEAVY = "tier_2_heavy"   # Bedrock Reasoning Tier (Claude 3.5 Sonnet + IaC diff)


@dataclass
class DeciderState:
    """The typed input state presented to Strands Decider 2B before Boto3 execution."""
    alert_source: str
    alert_severity: str
    target_arn: str
    proposed_tool: str
    tool_parameters: Dict[str, Any]
    blast_radius: BlastRadius = BlastRadius.ISOLATED
    is_destructive_action: bool = False
    context_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_source": self.alert_source,
            "alert_severity": self.alert_severity,
            "target_arn": self.target_arn,
            "proposed_tool": self.proposed_tool,
            "tool_parameters": self.tool_parameters,
            "blast_radius": self.blast_radius.value if isinstance(self.blast_radius, BlastRadius) else str(self.blast_radius),
            "is_destructive_action": self.is_destructive_action,
            "context_notes": self.context_notes,
        }


@dataclass
class DeciderResult:
    """The calibrated evaluation output returned by Strands Decider 2B."""
    action: GuardrailAction
    confidence: float
    latency_ms: float
    reasoning_code: str
    raw_scores: Dict[str, float] = field(default_factory=dict)
    recommended_tier: str = "tier_0_rule"
    risk_level: str = "low"
    target_service: str = "ec2"
    estimated_tokens_saved: int = 2400
    terraform_diff: str = ""
    compliance_frameworks: List[str] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.action != GuardrailAction.PERMIT_AUTO_REMEDIATION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value if isinstance(self.action, GuardrailAction) else str(self.action),
            "confidence": round(self.confidence, 4),
            "latency_ms": round(self.latency_ms, 3),
            "reasoning_code": self.reasoning_code,
            "raw_scores": {k: round(v, 4) for k, v in self.raw_scores.items()},
            "recommended_tier": self.recommended_tier,
            "risk_level": self.risk_level,
            "target_service": self.target_service,
            "estimated_tokens_saved": self.estimated_tokens_saved,
            "terraform_diff": self.terraform_diff,
            "compliance_frameworks": self.compliance_frameworks,
        }


class GuardrailBlockedError(RuntimeError):
    """
    Raised by the Botocore 'before-call' interceptor hook when Strands Decider 2B
    blocks a mutating AWS API call before it is transmitted over the network.
    """

    def __init__(self, message: str, state: DeciderState, result: DeciderResult):
        super().__init__(message)
        self.state = state
        self.result = result


