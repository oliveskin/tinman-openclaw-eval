"""Attack modules for OpenClaw security evaluation."""

from .base import Attack, AttackCategory, ExpectedBehavior, AttackPayload, Severity, AttackResult
from .prompt_injection import PromptInjectionAttacks
from .tool_exfil import ToolExfilAttacks
from .context_bleed import ContextBleedAttacks
from .privilege_escalation import PrivilegeEscalationAttacks
from .supply_chain import SupplyChainAttacks
from .financial import FinancialAttacks
from .unauthorized_action import UnauthorizedActionAttacks
from .mcp_attacks import MCPAttacks
from .indirect_injection import IndirectInjectionAttacks

__all__ = [
    "Attack",
    "AttackCategory",
    "ExpectedBehavior",
    "AttackPayload",
    "Severity",
    "AttackResult",
    # Attack classes
    "PromptInjectionAttacks",
    "ToolExfilAttacks",
    "ContextBleedAttacks",
    "PrivilegeEscalationAttacks",
    "SupplyChainAttacks",
    "FinancialAttacks",
    "UnauthorizedActionAttacks",
    "MCPAttacks",
    "IndirectInjectionAttacks",
]
