"""Evaluation harness for running attack suites."""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .attacks import (
    Attack,
    AttackCategory,
    AttackPayload,
    AttackResult,
    ContextBleedAttacks,
    EvasionBypassAttack,
    ExpectedBehavior,
    FinancialAttacks,
    IndirectInjectionAttacks,
    MCPAttacks,
    MemoryPoisoningAttack,
    PlatformSpecificAttack,
    PrivilegeEscalationAttacks,
    PromptInjectionAttacks,
    Severity,
    SupplyChainAttacks,
    ToolExfilAttacks,
    UnauthorizedActionAttacks,
)
from .synthetic_gateway import GatewayConfig, SyntheticGateway
from .tinman_integration import TinmanAnalyzer, check_tinman_available


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
    traces: list[Any] = field(default_factory=list)  # Tinman Trace objects
    tinman_enabled: bool = False

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
            "duration_seconds": (self.completed_at - self.started_at).total_seconds()
            if self.completed_at
            else None,
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
        return json.dumps(
            {
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
            },
            indent=2,
        )


class EvalHarness:
    """
    Security evaluation harness for OpenClaw agents.

    Runs attack payloads against a Gateway (synthetic or real)
    and collects results for analysis. Uses AgentTinman's FailureClassifier
    for advanced analysis when available.
    """

    def __init__(
        self,
        gateway: SyntheticGateway | None = None,
        gateway_config: GatewayConfig | None = None,
        use_tinman: bool = True,
    ):
        self.gateway = gateway or SyntheticGateway(gateway_config)
        self.attack_modules: list[Attack] = [
            PromptInjectionAttacks(),
            ToolExfilAttacks(),
            ContextBleedAttacks(),
            PrivilegeEscalationAttacks(),
            SupplyChainAttacks(),
            FinancialAttacks(),
            UnauthorizedActionAttacks(),
            MCPAttacks(),
            IndirectInjectionAttacks(),
            EvasionBypassAttack(),
            MemoryPoisoningAttack(),
            PlatformSpecificAttack(),
        ]
        self._module_by_attack_id = self._build_payload_index(self.attack_modules)
        # Initialize Tinman analyzer if requested and available
        self.tinman_analyzer = TinmanAnalyzer() if use_tinman else None
        self.tinman_enabled = use_tinman and check_tinman_available()

    @staticmethod
    def _build_payload_index(modules: list[Attack]) -> dict[str, Attack]:
        """Build a stable index from attack ID to attack module."""
        payload_index: dict[str, Attack] = {}
        for module in modules:
            for payload in module.payloads:
                if payload.id in payload_index:
                    raise ValueError(f"Duplicate attack ID found: {payload.id}")
                payload_index[payload.id] = module
        return payload_index

    def _create_session_for_payload(self, payload: AttackPayload) -> str:
        """Create a session that matches payload targeting semantics."""
        channel_type = (
            payload.target if payload.target in {"dm_channel", "group_channel"} else "dm_channel"
        )
        elevated = payload.target == "elevated_session"
        return self.gateway.create_session(channel_type=channel_type, elevated=elevated)

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
        category = AttackCategory.parse(category)

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
                cat_set = {AttackCategory.parse(c) for c in categories}
                payloads = [p for p in payloads if p.category in cat_set]

            # Apply severity filter
            if min_severity:
                if isinstance(min_severity, str):
                    min_severity = Severity(min_severity)
                severity_order = [Severity.S0, Severity.S1, Severity.S2, Severity.S3, Severity.S4]
                min_index = severity_order.index(min_severity)
                payloads = [p for p in payloads if severity_order.index(p.severity) >= min_index]

        # Create result container
        result = EvalResult(
            run_id=str(uuid.uuid4()),
            started_at=datetime.now(timezone.utc),
            total_attacks=len(payloads),
            config={
                "gateway_mode": self.gateway.config.mode.value,
                "sandbox_enabled": self.gateway.config.sandbox_enabled,
                "pairing_enabled": self.gateway.config.pairing_enabled,
                "tinman_enabled": self.tinman_enabled,
            },
            tinman_enabled=self.tinman_enabled,
        )

        # Run attacks with concurrency limit
        semaphore = asyncio.Semaphore(max_concurrent)
        completed = 0

        async def run_attack(payload: AttackPayload) -> AttackResult:
            nonlocal completed
            async with semaphore:
                module = self._module_by_attack_id.get(payload.id)
                if module is None:
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
                else:
                    session_id = self._create_session_for_payload(payload)
                    attack_result = await module.execute(payload, self.gateway, session_id)

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
                # Run Tinman analysis if enabled
                if self.tinman_enabled and self.tinman_analyzer:
                    tinman_analysis = self.tinman_analyzer.analyze_response(
                        attack_payload=ar.details.get("payload", ""),
                        response_content=ar.response,
                        response_metadata=ar.details,
                        attack_category=ar.category.value,
                    )
                    # Enrich result with Tinman analysis
                    ar.details["tinman_analysis"] = {
                        "primary_class": tinman_analysis.primary_class,
                        "secondary_class": tinman_analysis.secondary_class,
                        "confidence": tinman_analysis.confidence,
                        "severity": tinman_analysis.severity,
                        "reasoning": tinman_analysis.reasoning,
                        "indicators": tinman_analysis.indicators,
                    }
                    # Override vulnerability detection with Tinman's analysis
                    if tinman_analysis.is_failure and not ar.is_vulnerability:
                        ar.details["tinman_detected_failure"] = True
                        ar.actual = ExpectedBehavior.ATTACK_SUCCEEDED
                        ar.passed = ar.expected == ar.actual

                    # Generate Tinman trace
                    trace = self.tinman_analyzer.convert_to_trace(
                        attack_id=ar.attack_id,
                        attack_payload=ar.details.get("payload", ""),
                        response_content=ar.response,
                        response_metadata=ar.details,
                        latency_ms=ar.latency_ms,
                    )
                    result.traces.append(trace)

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
        module = self._module_by_attack_id.get(attack_id)
        if module:
            payload = module.get_payload_by_id(attack_id)

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
