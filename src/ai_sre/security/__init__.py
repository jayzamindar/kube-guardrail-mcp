"""Security package for AI-SRE capability gates and cryptographic execution barriers."""

from ai_sre.security.approval_gate import ApprovalGate, ApprovalGateError

__all__ = ["ApprovalGate", "ApprovalGateError"]
