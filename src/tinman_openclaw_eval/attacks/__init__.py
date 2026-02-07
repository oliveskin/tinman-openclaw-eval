"""Attack modules for OpenClaw security evaluation."""

from .base import Attack, AttackCategory, AttackPayload, AttackResult, ExpectedBehavior, Severity
from .context_bleed import ContextBleedAttacks
from .evasion_bypass import EvasionBypassAttack
from .financial import FinancialAttacks
from .indirect_injection import IndirectInjectionAttacks
from .mcp_attacks import MCPAttacks
from .memory_poisoning import MemoryPoisoningAttack
from .platform_specific import PlatformSpecificAttack
from .privilege_escalation import PrivilegeEscalationAttacks
from .prompt_injection import PromptInjectionAttacks
from .supply_chain import SupplyChainAttacks
from .tool_exfil import ToolExfilAttacks
from .unauthorized_action import UnauthorizedActionAttacks

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
    "EvasionBypassAttack",
    "MemoryPoisoningAttack",
    "PlatformSpecificAttack",
]
