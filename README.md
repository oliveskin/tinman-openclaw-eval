# Tinman OpenClaw Eval

Security evaluation harness for OpenClaw agents. Powered by [Tinman](https://github.com/oliveskin/Agent-Tinman).

## Features

- **280+ attack probes** (currently 288) across 12 categories
- **Synthetic Gateway** for isolated testing
- **CI integration** via SARIF, JUnit, and JSON outputs
- **Baseline assertions** for regression testing
- **Real-time monitoring** via Gateway WebSocket

## Attack Categories

Run `tinman-eval list-attacks` to see exact counts by category.

| Category | Description |
|----------|-------------|
| **Prompt Injection** | Jailbreaks, instruction override, prompt leaking |
| **Tool Exfiltration** | Sensitive file/secret exfiltration attempts |
| **Context Bleed** | Cross-session leaks, conversation history extraction |
| **Privilege Escalation** | Sandbox escape, elevation bypass attempts |
| **Supply Chain** | Malicious skills, dependency and update attacks |
| **Financial Transaction** | Wallet/seed phrase theft, transaction/approval attempts |
| **Unauthorized Action** | Actions without consent/confirmation |
| **MCP Attacks** | MCP tool abuse, server injection, cross-tool exfil |
| **Indirect Injection** | Injection via documents, URLs, issues, logs, metadata |
| **Evasion Bypass** | Unicode/encoding bypass, obfuscation, injection variants |
| **Memory Poisoning** | Persistent instruction poisoning, fabricated history |
| **Platform Specific** | OS and cloud-specific payloads (Windows/macOS/Linux/metadata) |

## Installation

```bash
pip install tinman-openclaw-eval
```

Or from source:

```bash
git clone https://github.com/oliveskin/tinman-openclaw-eval
cd tinman-openclaw-eval
pip install -e ".[dev]"
```

## Quick Start

```bash
# Run all attacks (mock gateway)
tinman-eval run

# Run specific category
tinman-eval run -c prompt_injection
tinman-eval run -c financial
tinman-eval run -c evasion_bypass

# Run only high severity (S3+)
tinman-eval run -s S3

# Save report
tinman-eval run -o report.md

# List all attacks
tinman-eval list-attacks

# Run single attack
tinman-eval run-single PI-001 -v
```

Category aliases are supported (e.g. `financial`, `mcp_attacks`, `supplychain`, `platform`).

## CI Integration

### GitHub Actions

```yaml
name: Security Eval
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install tinman-openclaw-eval

      - name: Run security evaluation
        run: |
          tinman-eval run \
            --output security-report.json \
            --format json

      - name: Assert baseline
        run: |
          tinman-eval assert-cmd \
            security-report.json \
            --baseline expected/baseline.json

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-report.sarif
        if: always()

      - name: Generate SARIF (always)
        run: |
          tinman-eval run \
            --output security-report.sarif \
            --format sarif
        if: always()
```

### Generate Baseline

```bash
# Create initial baseline
tinman-eval baseline --output expected/baseline.json

# Update after intentional changes
tinman-eval run -f json -o new-results.json
# Review and approve
mv new-results.json expected/baseline.json
```

## Output Formats

| Format | Use Case |
|--------|----------|
| `markdown` | Human-readable reports |
| `json` | Programmatic analysis |
| `sarif` | GitHub Code Scanning |
| `junit` | CI test results |

## Custom Attacks

Add a new attack module under `src/tinman_openclaw_eval/attacks/`:

```python
from tinman_openclaw_eval.attacks.base import Attack, AttackCategory, AttackPayload, ExpectedBehavior, Severity


class MyAttacks(Attack):
    category = AttackCategory.PROMPT_INJECTION
    name = "My Attacks"

    def _load_payloads(self) -> None:
        self.payloads.append(
            AttackPayload(
                id="MY-001",
                name="My probe",
                category=self.category,
                severity=Severity.S2,
                payload="...",
                target="dm_channel",
                expected_behavior=ExpectedBehavior.REJECTED_BY_SOUL,
            )
        )
```

Then export it from `src/tinman_openclaw_eval/attacks/__init__.py` and register it in
`src/tinman_openclaw_eval/harness.py`.

## Programmatic Usage

```python
import asyncio
from tinman_openclaw_eval import EvalHarness, AttackCategory

async def main():
    harness = EvalHarness()

    # Run all attacks
    result = await harness.run()

    # Check for vulnerabilities
    print(f"Vulnerabilities: {result.vulnerabilities}")

    # Run specific categories
    result = await harness.run(categories=[
        AttackCategory.PROMPT_INJECTION,
        AttackCategory.FINANCIAL_TRANSACTION,
        AttackCategory.EVASION_BYPASS,
    ])

    # Run high severity only
    result = await harness.run(min_severity="S3")

asyncio.run(main())
```

## Testing Against Real Gateway

```bash
# Connect to local OpenClaw Gateway
tinman-eval run --no-mock --gateway-url ws://127.0.0.1:18789

# With custom config
tinman-eval run --no-mock --gateway-url ws://192.168.1.100:18789
```

## Attack Probe IDs

| Prefix | Category |
|--------|----------|
| `PI-*` | Prompt Injection |
| `TE-*` | Tool Exfiltration |
| `CB-*` | Context Bleed |
| `PE-*` | Privilege Escalation |
| `SC-*` | Supply Chain |
| `FT-*` | Financial Transaction |
| `UA-*` | Unauthorized Action |
| `MCP-*` | MCP Attacks |
| `II-*` | Indirect Injection |
| `EB-*` | Evasion Bypass |
| `MP-*` | Memory Poisoning |
| `PS-*` | Platform Specific |

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **S4** | Critical | Immediate fix required |
| **S3** | High | Fix before deploy |
| **S2** | Medium | Review recommended |
| **S1** | Low | Monitor |
| **S0** | Info | Observation only |

## Integration with OpenClaw Skill

For continuous monitoring in OpenClaw, use the [Tinman Skill](https://github.com/oliveskin/openclaw-skill-tinman):

```bash
# In OpenClaw
/tinman sweep                    # Run security sweep
/tinman sweep --category financial
/tinman watch                    # Real-time monitoring
```

## Links

- [Tinman](https://github.com/oliveskin/Agent-Tinman) - AI Failure Mode Research
- [Tinman Skill](https://github.com/oliveskin/openclaw-skill-tinman) - OpenClaw Integration
- [OpenClaw](https://github.com/openclaw/openclaw) - Personal AI Assistant

## License

Apache-2.0
