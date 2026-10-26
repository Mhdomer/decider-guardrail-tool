"""
Aegis-2B - DeciderGuardrailTool
Plug-and-play agent tool definition for Amazon Bedrock and Strands Agents SDK.
Enables autonomous cloud operations agents to verify safety and blast radius
prior to executing mutating Boto3 infrastructure calls.
"""

from typing import Any, Dict, Optional
from decider_guardrail.schemas import (
    BlastRadius,
    DeciderResult,
    DeciderState,
    GuardrailAction,
)
from decider_guardrail.guardrail import DeciderCloudGuardrail


class DeciderGuardrailTool:
    """
    A fast, calibrated safety gate tool for autonomous cloud agents.
    
    Evaluates proposed AWS operations locally in under 1ms, returning
    whether an action is safe for autonomous remediation (PERMIT),
    must be halted for human MFA authorization (ENFORCE_BREAK_GLASS),
    or contains malicious prompt injections (QUARANTINE).
    """

    name: str = "decider_cloud_guardrail"
    description: str = (
        "Evaluates proposed AWS Boto3 actions against cloud safety policies, "
        "blast radius thresholds, and prompt injection signatures. Use this tool "
        "to verify any infrastructure mutation before executing it against live AWS APIs."
    )

    def __init__(self, risk_threshold: float = 0.85, simulate_local_latency: bool = False):
        self.guardrail = DeciderCloudGuardrail(
            risk_threshold=risk_threshold,
            simulate_local_latency=simulate_local_latency,
        )

    def __call__(
        self,
        proposed_tool: str,
        target_arn: str,
        tool_parameters: Optional[Dict[str, Any]] = None,
        alert_source: str = "aws.securityhub",
        alert_severity: str = "HIGH",
        blast_radius: str = "ISOLATED",
        is_destructive_action: bool = False,
        context_notes: str = "",
    ) -> Dict[str, Any]:
        """
        Executes the safety evaluation tool.
        
        Args:
            proposed_tool: The Boto3 API operation to verify (e.g. 'delete_security_group')
            target_arn: The AWS resource ARN targeted by the operation
            tool_parameters: Dictionary of parameters passed to the AWS call
            alert_source: Origin of the security alert (e.g. 'aws.guardduty')
            alert_severity: Severity label (LOW, MEDIUM, HIGH, CRITICAL)
            blast_radius: Scope of impact (ISOLATED, VPC_WIDE, ACCOUNT_WIDE)
            is_destructive_action: True if action deletes or revokes active infrastructure
            context_notes: Alert description or title to scan for prompt injections
            
        Returns:
            Dictionary containing the safety verdict, confidence, latency, and reasoning.
        """
        try:
            radius = BlastRadius(blast_radius.lower())
        except ValueError:
            radius = BlastRadius.ISOLATED

        state = DeciderState(
            alert_source=alert_source,
            alert_severity=alert_severity,
            target_arn=target_arn,
            proposed_tool=proposed_tool,
            tool_parameters=tool_parameters or {},
            blast_radius=radius,
            is_destructive_action=is_destructive_action,
            context_notes=context_notes,
        )

        result: DeciderResult = self.guardrail.evaluate(state)

        return {
            "verdict": result.action.value,
            "permitted": result.action == GuardrailAction.PERMIT_AUTO_REMEDIATION,
            "confidence": round(result.confidence, 4),
            "latency_ms": round(result.latency_ms, 3),
            "recommended_tier": str(result.recommended_tier),
            "reasoning_code": result.reasoning_code,
            "risk_scores": {k: round(v, 4) for k, v in result.raw_scores.items()},
            "requires_mfa": result.action != GuardrailAction.PERMIT_AUTO_REMEDIATION,
            "terraform_patch_available": bool(result.terraform_diff),
        }
