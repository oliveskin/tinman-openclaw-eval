"""Tinman OpenClaw Eval - Security evaluation harness for OpenClaw agents."""

__version__ = "0.1.2"

from .harness import EvalHarness, EvalResult
from .attacks.base import Attack, AttackCategory, ExpectedBehavior, Severity, AttackResult
from .synthetic_gateway import SyntheticGateway, GatewayConfig
from .report import ReportGenerator
from .tinman_integration import TinmanAnalyzer, TinmanAnalysis, check_tinman_available

# Gateway adapter for real-time monitoring
try:
    from .adapters.openclaw import OpenClawAdapter

    ADAPTER_AVAILABLE = True
except ImportError:
    OpenClawAdapter = None  # type: ignore
    ADAPTER_AVAILABLE = False

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
    # Gateway adapter
    "OpenClawAdapter",
    "ADAPTER_AVAILABLE",
]
