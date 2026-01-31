"""Gateway adapters for tinman-openclaw-eval.

Adapters convert platform-specific events to Tinman's canonical format.
"""

from .openclaw import OpenClawAdapter

__all__ = ["OpenClawAdapter"]
