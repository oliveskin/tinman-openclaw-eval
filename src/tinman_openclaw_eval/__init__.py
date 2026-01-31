"""Tinman OpenClaw Eval - Security evaluation harness for OpenClaw agents."""

__version__ = "0.1.1"

from .harness import EvalHarness, EvalResult
from .attacks.base import Attack, AttackCategory, ExpectedBehavior, Severity, AttackResult
from .synthetic_gateway import SyntheticGateway, GatewayConfig
from .report import ReportGenerator
from .tinman_integration import TinmanAnalyzer, TinmanAnalysis, check_tinman_available

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
    "TinmanAnalyzer",
    "TinmanAnalysis",
    "check_tinman_available",
]
