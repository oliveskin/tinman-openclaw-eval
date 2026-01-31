"""Evaluation harness for running attack suites."""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .attacks import (
    Attack,
    AttackPayload,
    AttackResult,
    AttackCategory,
    Severity,
    PromptInjectionAttacks,
    ToolExfilAttacks,
    ContextBleedAttacks,
    PrivilegeEscalationAttacks,
    SupplyChainAttacks,
)
from .synthetic_gateway import SyntheticGateway, GatewayConfig


@dataclass
class EvalResult:
    """Result of a full evaluation run."""

    run_id: str
    started_at: datetime
    completed_at: datetime | None = None
    total_attacks: int = 0
    passed: int = 0
    failed: int = 0
    vulnerabilities: int = 0
    errors: int = 0
    results: list[AttackResult] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def pass_rate(self) -> float:
        """Calculate pass rate."""
        if self.total_attacks == 0:
            return 0.0
        return self.passed / self.total_attacks

    @property
    def vulnerability_rate(self) -> float:
        """Calculate vulnerability rate."""
        if self.total_attacks == 0:
            return 0.0
        return self.vulnerabilities / self.total_attacks

    def summary(self) -> dict[str, Any]:
        """Get summary statistics."""
        by_category: dict[str, dict[str, int]] = {}
        by_severity: dict[str, dict[str, int]] = {}

        for result in self.results:
            # By category
            cat = result.category.value
            if cat not in by_category:
                by_category[cat] = {"total": 0, "passed": 0, "failed": 0, "vulnerabilities": 0}
            by_category[cat]["total"] += 1
            if result.passed:
                by_category[cat]["passed"] += 1
            else:
                by_category[cat]["failed"] += 1
            if result.is_vulnerability:
                by_category[cat]["vulnerabilities"] += 1

            # By severity
            sev = result.severity.value
            if sev not in by_severity:
                by_severity[sev] = {"total": 0, "passed": 0, "failed": 0, "vulnerabilities": 0}
            by_severity[sev]["total"] += 1
            if result.passed:
                by_severity[sev]["passed"] += 1
            else:
                by_severity[sev]["failed"] += 1
            if result.is_vulnerability:
                by_severity[sev]["vulnerabilities"] += 1

        return {
            "run_id": self.run_id,
            "duration_seconds": (self.completed_at - self.started_at).total_seconds() if self.completed_at else None,
            "total_attacks": self.total_attacks,
            "passed": self.passed,
            "failed": self.failed,
            "vulnerabilities": self.vulnerabilities,
            "errors": self.errors,
            "pass_rate": f"{self.pass_rate:.1%}",
            "vulnerability_rate": f"{self.vulnerability_rate:.1%}",
            "by_category": by_category,
            "by_severity": by_severity,
        }

    def to_json(self) -> str:
        """Serialize to JSON."""
        return json.dumps({
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "summary": self.summary(),
            "results": [
                {
                    "attack_id": r.attack_id,
                    "attack_name": r.attack_name,
                    "category": r.category.value,
                    "severity": r.severity.value,
                    "expected": r.expected.value,
                    "actual": r.actual.value,
                    "passed": r.passed,
                    "is_vulnerability": r.is_vulnerability,
                    "latency_ms": r.latency_ms,
                    "error": r.error,
                }
                for r in self.results
            ],
            "config": self.config,
        }, indent=2)


class EvalHarness:
    """
    Security evaluation harness for OpenClaw agents.

    Runs attack payloads against a Gateway (synthetic or real)
    and collects results for analysis.
    """

    def __init__(
        self,
        gateway: SyntheticGateway | None = None,
        gateway_config: GatewayConfig | None = None,
    ):
        self.gateway = gateway or SyntheticGateway(gateway_config)
        self.attack_modules: list[Attack] = [
            PromptInjectionAttacks(),
            ToolExfilAttacks(),
            ContextBleedAttacks(),
            PrivilegeEscalationAttacks(),
            SupplyChainAttacks(),
        ]

    def get_all_payloads(self) -> list[AttackPayload]:
        """Get all attack payloads from all modules."""
        payloads = []
        for module in self.attack_modules:
            payloads.extend(module.payloads)
        return payloads

    def get_payloads_by_category(
        self,
        category: AttackCategory | str,
    ) -> list[AttackPayload]:
        """Get payloads filtered by category."""
        if isinstance(category, str):
            category = AttackCategory(category)

        payloads = []
        for module in self.attack_modules:
            if module.category == category:
                payloads.extend(module.payloads)
        return payloads

    def get_payloads_by_severity(
        self,
        min_severity: Severity | str,
    ) -> list[AttackPayload]:
        """Get payloads at or above a severity level."""
        if isinstance(min_severity, str):
            min_severity = Severity(min_severity)

        severity_order = [Severity.S0, Severity.S1, Severity.S2, Severity.S3, Severity.S4]
        min_index = severity_order.index(min_severity)

        payloads = []
        for module in self.attack_modules:
            for payload in module.payloads:
                if severity_order.index(payload.severity) >= min_index:
                    payloads.append(payload)
        return payloads

    async def run(
        self,
        payloads: list[AttackPayload] | None = None,
        categories: list[AttackCategory | str] | None = None,
        min_severity: Severity | str | None = None,
        max_concurrent: int = 5,
        progress_callback: Any = None,
    ) -> EvalResult:
        """
        Run evaluation with selected payloads.

        Args:
            payloads: Specific payloads to run (overrides other filters)
            categories: Filter by categories
            min_severity: Minimum severity to include
            max_concurrent: Max concurrent attack executions
            progress_callback: Called with (completed, total) after each attack

        Returns:
            EvalResult with all attack results
        """
        import uuid

        # Determine payloads to run
        if payloads is None:
            payloads = self.get_all_payloads()

            # Apply category filter
            if categories:
                cat_set = {
                    AttackCategory(c) if isinstance(c, str) else c
                    for c in categories
                }
                payloads = [p for p in payloads if p.category in cat_set]

            # Apply severity filter
            if min_severity:
                if isinstance(min_severity, str):
                    min_severity = Severity(min_severity)
                severity_order = [Severity.S0, Severity.S1, Severity.S2, Severity.S3, Severity.S4]
                min_index = severity_order.index(min_severity)
                payloads = [
                    p for p in payloads
                    if severity_order.index(p.severity) >= min_index
                ]

        # Create result container
        result = EvalResult(
            run_id=str(uuid.uuid4()),
            started_at=datetime.now(timezone.utc),
            total_attacks=len(payloads),
            config={
                "gateway_mode": self.gateway.config.mode.value,
                "sandbox_enabled": self.gateway.config.sandbox_enabled,
                "pairing_enabled": self.gateway.config.pairing_enabled,
            },
        )

        # Create session for the run
        session_id = self.gateway.create_session()

        # Run attacks with concurrency limit
        semaphore = asyncio.Semaphore(max_concurrent)
        completed = 0

        async def run_attack(payload: AttackPayload) -> AttackResult:
            nonlocal completed
            async with semaphore:
                # Find the attack module for this payload
                for module in self.attack_modules:
                    if module.category == payload.category:
                        attack_result = await module.execute(
                            payload, self.gateway, session_id
                        )
                        break
                else:
                    # Fallback - shouldn't happen
                    attack_result = AttackResult(
                        attack_id=payload.id,
                        attack_name=payload.name,
                        category=payload.category,
                        severity=payload.severity,
                        expected=payload.expected_behavior,
                        actual=payload.expected_behavior,
                        passed=True,
                        error="No attack module found",
                    )

                completed += 1
                if progress_callback:
                    progress_callback(completed, len(payloads))

                return attack_result

        # Execute all attacks
        attack_results = await asyncio.gather(
            *[run_attack(p) for p in payloads],
            return_exceptions=True,
        )

        # Process results
        for ar in attack_results:
            if isinstance(ar, Exception):
                result.errors += 1
            elif isinstance(ar, AttackResult):
                result.results.append(ar)
                if ar.passed:
                    result.passed += 1
                else:
                    result.failed += 1
                if ar.is_vulnerability:
                    result.vulnerabilities += 1
                if ar.error:
                    result.errors += 1

        result.completed_at = datetime.now(timezone.utc)
        return result

    async def run_single(
        self,
        attack_id: str,
        session_id: str | None = None,
    ) -> AttackResult:
        """Run a single attack by ID."""
        # Find the payload
        payload = None
        module = None
        for m in self.attack_modules:
            payload = m.get_payload_by_id(attack_id)
            if payload:
                module = m
                break

        if not payload or not module:
            raise ValueError(f"Attack not found: {attack_id}")

        # Create or use session
        if session_id is None:
            session_id = self.gateway.create_session()

        return await module.execute(payload, self.gateway, session_id)

    def assert_baseline(
        self,
        result: EvalResult,
        baseline_path: Path | str,
    ) -> tuple[bool, list[str]]:
        """
        Assert results match a baseline.

        Returns (passed, list of differences).
        """
        baseline_path = Path(baseline_path)
        if not baseline_path.exists():
            return False, [f"Baseline file not found: {baseline_path}"]

        with open(baseline_path) as f:
            baseline = json.load(f)

        differences = []

        # Check each attack result against baseline
        baseline_results = {r["attack_id"]: r for r in baseline.get("results", [])}

        for ar in result.results:
            if ar.attack_id not in baseline_results:
                differences.append(f"New attack not in baseline: {ar.attack_id}")
                continue

            expected = baseline_results[ar.attack_id]
            if ar.passed != expected.get("passed"):
                differences.append(
                    f"{ar.attack_id}: expected passed={expected.get('passed')}, "
                    f"got passed={ar.passed}"
                )

        # Check for missing attacks
        result_ids = {r.attack_id for r in result.results}
        for attack_id in baseline_results:
            if attack_id not in result_ids:
                differences.append(f"Attack in baseline but not in results: {attack_id}")

        return len(differences) == 0, differences

    def save_baseline(
        self,
        result: EvalResult,
        output_path: Path | str,
    ) -> None:
        """Save current results as a baseline."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result.to_json())
