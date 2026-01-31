"""Tinman OpenClaw Eval - Security evaluation harness for OpenClaw agents."""

__version__ = "0.1.0"

from .harness import EvalHarness, EvalResult
from .attacks.base import Attack, AttackCategory, ExpectedBehavior, Severity, AttackResult
from .synthetic_gateway import SyntheticGateway, GatewayConfig
from .report import ReportGenerator

__all__ = [
    "EvalHarness",
    "EvalResult",
    "AttackResult",
    "Attack",
    "AttackCategory",
    "ExpectedBehavior",
    "Severity",
    "SyntheticGateway",
    "GatewayConfig",
    "ReportGenerator",
]
